// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core.h"
#include <KLocalizedString>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QLockFile>
#include <QRegularExpression>
#include <QSettings>
#include <QSslCertificate>
#include <QTemporaryDir>
#include <unistd.h>

namespace SparkyCA
{
QStringList browserDatabases(const QString &home)
{
    QStringList databases;
    for (const QString browser : {".mozilla/firefox", ".waterfox"}) {
        const QString directory = QDir(home).filePath(browser);
        QSettings profiles(directory + "/profiles.ini", QSettings::IniFormat);
        for (const auto &group : profiles.childGroups()) {
            if (!group.startsWith("Profile")) continue;
            profiles.beginGroup(group);
            const QString path = profiles.value("Path").toString();
            const QString profile = profiles.value("IsRelative", 1).toInt() ? QDir(directory).filePath(path) : path;
            if (!path.isEmpty() && QFileInfo::exists(profile + "/cert9.db")) databases.append(QDir::cleanPath(profile));
            profiles.endGroup();
        }
    }
    const QString legacy = QDir(home).filePath(".pki/nssdb");
    databases.append(QDir::cleanPath(QFileInfo::exists(legacy) ? legacy : QDir(home).filePath(".local/share/pki/nssdb")));
    databases.removeDuplicates();
    return databases;
}
Store::Store(QString systemDirectory, QString systemBundle, QString nssDatabase)
    : m_system(std::move(systemDirectory)), m_bundle(std::move(systemBundle)), m_nss(std::move(nssDatabase))
{
    if (m_system.isEmpty() == m_nss.isEmpty()) fail(i18n("Choose exactly one store."));
}
static void safePath(const QString &path)
{
    QString current = QFileInfo(path).absoluteFilePath();
    while (current != "/") {
        if (QFileInfo(current).isSymLink()) fail(i18n("Refusing a symbolic link in store path: %1", current));
        current = QFileInfo(current).absolutePath();
    }
}
static QJsonObject manifest(const QString &path)
{
    if (!QFileInfo::exists(path)) return {{"groups", QJsonArray()}, {"owned", QJsonArray()}};
    QJsonParseError error;
    const auto json = QJsonDocument::fromJson(readFile(path), &error);
    if (error.error != QJsonParseError::NoError || !json.isObject()) fail(i18n("Invalid store ownership manifest."));
    return json.object();
}
void Store::rebuild()
{
    if (m_bundle == "/etc/ssl/certs/ca-certificates.crt") {
        run("/usr/sbin/update-ca-certificates", {});
    } else {
        const QString output = QFileInfo(m_bundle).absolutePath();
        QTemporaryDir configuration(QFileInfo(m_system).absolutePath() + "/updater-XXXXXX");
        if (!configuration.isValid()) fail(i18n("Cannot create updater configuration."));
        QDir().mkpath(output);
        QDir().mkpath(configuration.path() + "/empty");
        writeFile(configuration.path() + "/ca.conf", {});
        run("/usr/sbin/update-ca-certificates", {"--fresh", "--localcertsdir", m_system, "--certsdir", configuration.path() + "/empty",
            "--etccertsdir", output, "--certbundle", QFileInfo(m_bundle).fileName(), "--certsconf", configuration.path() + "/ca.conf", "--hooksdir", configuration.path() + "/empty"});
        if (QDir(m_system).entryList({"*.crt"}, QDir::Files).isEmpty()) writeFile(m_bundle, {});
    }
}
void Store::install(const Catalogue &catalogue, const QString &group, bool allowE521)
{
    if (!catalogue.groups().contains(group)) fail(i18n("Unknown certificate group: %1", group));
    const QString directory = m_nss.isEmpty() ? m_system : m_nss;
    if (m_nss.isEmpty() && m_bundle == "/etc/ssl/certs/ca-certificates.crt" && geteuid() != 0) fail(i18n("System changes require root. Run sparky-ca through sudo or pkexec."));
    safePath(directory);
    if (!QDir().mkpath(directory)) fail(i18n("Cannot create store directory."));
    QLockFile lock(directory + "/.sparky-ca.lock");
    if (!lock.tryLock(0)) fail(i18n("Certificate store is busy."));
    const QString statePath = directory + "/.sparky-ca.json";
    safePath(statePath);
    auto state = manifest(statePath);
    auto groups = state.value("groups").toArray();
    if (!groups.contains(group)) groups.append(group);
    QJsonArray owned = state.value("owned").toArray();
    QList<Entry> chosen;
    for (const auto &entry : catalogue.entries()) {
        if (!entry.groups.contains(group) || catalogue.state(entry.certificate) != "valid") continue;
        if (catalogue.requiresE521(entry.certificate) && !allowE521) continue;
        catalogue.verify(entry.certificate, true);
        chosen.append(entry);
    }
    if (chosen.isEmpty()) fail(i18n("This group has no installable certificates."));
    if (!m_nss.isEmpty() && !QFileInfo::exists(directory + "/cert9.db")) run("certutil", {"-N", "-d", "sql:" + directory, "--empty-password"});
    for (const auto &entry : chosen) {
        const QString id = entry.certificate.fingerprint();
        if (owned.contains(id)) continue;
        const QString filename = directory + "/sparky-ca-" + id + ".crt";
        safePath(filename);
        if (m_nss.isEmpty()) {
            if (QFileInfo::exists(filename)) fail(i18n("Unowned certificate filename already exists."));
            writeFile(filename, entry.certificate.pem());
        } else {
            const QByteArray listing = run("certutil", {"-L", "-d", "sql:" + directory});
            if (listing.contains(("sparky-ca-" + id).toUtf8())) fail(i18n("Unowned NSS nickname already exists."));
            QTemporaryDir temp;
            writeFile(temp.path() + "/cert.crt", entry.certificate.pem());
            run("certutil", {"-A", "-d", "sql:" + directory, "-n", "sparky-ca-" + id, "-t", entry.certificate.root() ? "C,," : ",,", "-i", temp.path() + "/cert.crt"});
        }
        owned.append(id);
        state.insert("owned", owned);
        writeFile(statePath, QJsonDocument(state).toJson());
    }
    if (m_nss.isEmpty()) rebuild();
    state.insert("groups", groups);
    writeFile(statePath, QJsonDocument(state).toJson());
}
void Store::remove(const Catalogue &catalogue, const QString &group)
{
    const QString directory = m_nss.isEmpty() ? m_system : m_nss;
    if (m_nss.isEmpty() && m_bundle == "/etc/ssl/certs/ca-certificates.crt" && geteuid() != 0) fail(i18n("System changes require root. Run sparky-ca through sudo or pkexec."));
    if (!QFileInfo::exists(directory)) return;
    safePath(directory);
    QLockFile lock(directory + "/.sparky-ca.lock");
    if (!lock.tryLock(0)) fail(i18n("Certificate store is busy."));
    const QString statePath = directory + "/.sparky-ca.json";
    safePath(statePath);
    auto state = manifest(statePath);
    QJsonArray groups;
    for (const auto &item : state.value("groups").toArray()) if (group != "all" && item.toString() != group) groups.append(item);
    QSet<QString> retained;
    for (const auto &entry : catalogue.entries()) {
        for (const auto &selected : groups) if (entry.groups.contains(selected.toString())) retained.insert(entry.certificate.fingerprint());
    }
    QJsonArray owned;
    for (const auto &item : state.value("owned").toArray()) {
        const QString id = item.toString();
        if (!QRegularExpression("^[0-9a-f]{64}$").match(id).hasMatch()) fail(i18n("Invalid owned certificate fingerprint."));
        if (retained.contains(id)) { owned.append(id); continue; }
        if (m_nss.isEmpty()) {
            const QString filename = directory + "/sparky-ca-" + id + ".crt";
            safePath(filename);
            if (QFileInfo::exists(filename) && Certificate(readFile(filename)).fingerprint() != id) fail(i18n("Owned certificate bytes have changed."));
            if (QFileInfo::exists(filename) && !QFile::remove(filename)) fail(i18n("Cannot remove certificate."));
        } else {
            run("certutil", {"-D", "-d", "sql:" + directory, "-n", "sparky-ca-" + id});
        }
    }
    if (m_nss.isEmpty()) rebuild();
    state.insert("groups", groups);
    state.insert("owned", owned);
    writeFile(statePath, QJsonDocument(state).toJson());
}
QJsonArray Store::list(const Catalogue &catalogue) const
{
    QJsonArray result;
    if (m_nss.isEmpty()) {
        if (!QFileInfo::exists(m_bundle)) return result;
        for (const auto &ssl : QSslCertificate::fromData(readFile(m_bundle))) {
            const Certificate cert(ssl.toPem());
            auto item = describe(cert, cert.subject(), catalogue.state(cert));
            item.insert("note", catalogue.verificationNote(cert));
            result.append(item);
        }
    } else if (QFileInfo::exists(m_nss + "/cert9.db")) {
        const QString listing = QString::fromUtf8(run("certutil", {"-L", "-d", "sql:" + m_nss}));
        const QRegularExpression pattern("^(.+?)\\s+([A-Za-z,]+)\\s*$");
        for (const auto &line : listing.split('\n')) {
            const auto match = pattern.match(line);
            if (!match.hasMatch() || !match.captured(2).contains(',')) continue;
            const QString nickname = match.captured(1).trimmed();
            const Certificate cert(run("certutil", {"-L", "-a", "-d", "sql:" + m_nss, "-n", nickname}));
            auto description = describe(cert, nickname, catalogue.state(cert));
            description.insert("trust", match.captured(2));
            description.insert("note", catalogue.verificationNote(cert));
            result.append(description);
        }
    }
    return result;
}
}
