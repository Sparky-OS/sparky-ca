// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core.h"
#include <KLocalizedString>
#include <QDir>
#include <QJsonDocument>
#include <QLockFile>
#include <sys/stat.h>
#include <unistd.h>

namespace SparkyCA
{
static bool trustedDirectory(const QString &path)
{
    struct stat info{};
    return stat(QFile::encodeName(path).constData(), &info) == 0 && S_ISDIR(info.st_mode) && (info.st_uid == 0 || info.st_uid == geteuid()) && !(info.st_mode & 0022);
}
bool trustedStateFile(const QString &path)
{
    try {
        validateStorePath(path);
    } catch (const std::exception &) {
        return false;
    }
    struct stat info{};
    if (stat(QFile::encodeName(path).constData(), &info) != 0 || !S_ISREG(info.st_mode)) return false;
    return (info.st_uid == 0 || info.st_uid == geteuid()) && !(info.st_mode & 0022) && trustedDirectory(QFileInfo(path).absolutePath());
}
static QJsonObject readState(const QString &path)
{
    if (!trustedStateFile(path)) return {};
    return QJsonDocument::fromJson(readFile(path)).object();
}
static QSet<QString> fingerprints(const Catalogue &catalogue)
{
    QSet<QString> result;
    for (const auto &entry : catalogue.entries()) result.insert(entry.certificate.fingerprint());
    return result;
}
// The refreshed copy replaces the packaged one only when it still holds everything the package ships.
static bool cacheSupersedes(const QString &data, const QString &stateDirectory, Catalogue &packaged, Catalogue &candidate)
{
    const QString cached = stateDirectory + "/catalogue.json";
    if (stateDirectory.isEmpty() || !trustedStateFile(cached)) return false;
    try {
        candidate.load(readFile(cached));
    } catch (const std::exception &) {
        return false;
    }
    Q_UNUSED(data)
    return fingerprints(candidate).contains(fingerprints(packaged));
}
Catalogue loadCatalogue(const QString &data, const QString &stateDirectory, const QString &catalogueFile)
{
    Catalogue catalogue(data + "/pins.json", data + "/roots");
    if (!catalogueFile.isEmpty()) {
        catalogue.load(readFile(catalogueFile));
        return catalogue;
    }
    catalogue.load(readFile(data + "/catalogue.json"));
    Catalogue candidate(data + "/pins.json", data + "/roots");
    if (cacheSupersedes(data, stateDirectory, catalogue, candidate)) catalogue = candidate;
    const auto revocation = readState(stateDirectory + "/revocation.json");
    if (!revocation.isEmpty()) catalogue.applyRevocation(revocation);
    return catalogue;
}
QString catalogueSource(const QString &data, const QString &stateDirectory)
{
    Catalogue packaged(data + "/pins.json", data + "/roots"), candidate(data + "/pins.json", data + "/roots");
    packaged.load(readFile(data + "/catalogue.json"));
    return cacheSupersedes(data, stateDirectory, packaged, candidate) ? QStringLiteral("refreshed") : QStringLiteral("package");
}
QString automationFlag(const QString &configDirectory)
{
    return configDirectory + "/auto-update.disabled";
}
bool automationEnabled(const QString &configDirectory)
{
    return !QFileInfo::exists(automationFlag(configDirectory));
}
void setAutomationEnabled(const QString &configDirectory, bool enabled)
{
    const QString flag = automationFlag(configDirectory);
    if (enabled) {
        if (QFileInfo::exists(flag) && !QFile::remove(flag)) fail(i18n("Cannot turn automatic updates on."));
        return;
    }
    if (!QDir().mkpath(configDirectory)) fail(i18n("Cannot create the configuration folder."));
    writeFile(flag, i18n("Automatic certificate updates are turned off. Remove this file or run: sparky-ca auto enable\n").toUtf8());
}
QString automationStatusPath(const AutomationOptions &options)
{
    return options.scope == "system" ? options.stateDirectory + "/status.json" : options.home + "/.local/state/sparky-ca/status.json";
}
static void publish(const QString &path, const QByteArray &bytes)
{
    const QString directory = QFileInfo(path).absolutePath();
    if (!QDir().mkpath(directory)) fail(i18n("Cannot create the state folder."));
    QFile::setPermissions(directory, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner | QFile::ReadGroup | QFile::ExeGroup | QFile::ReadOther | QFile::ExeOther);
    writeFile(path, bytes);
    QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner | QFile::ReadGroup | QFile::ReadOther);
}
static QString names(const QJsonArray &records)
{
    QStringList list;
    for (const auto &record : records) list.append(record.toObject().value("name").toString());
    return list.join(", ");
}
QString journalLines(const QJsonObject &report)
{
    QStringList lines;
    const auto catalogue = report.value("catalogue").toObject();
    if (!report.value("error").toString().isEmpty()) lines << "3 " + i18n("Automatic update failed: %1", report.value("error").toString());
    if (catalogue.value("refreshed").toBool())
        lines << "6 " + (catalogue.value("changed").toBool() ? i18n("The certificate catalogue was refreshed and changed.") : i18n("The certificate catalogue was refreshed; nothing changed."));
    if (!catalogue.value("error").toString().isEmpty()) lines << "4 " + i18n("The catalogue could not be refreshed: %1", catalogue.value("error").toString());
    const auto revocation = report.value("revocation").toObject();
    if (revocation.contains("checked")) {
        lines << "6 " + i18n("Revocation: %1 certificates checked, %2 revoked, %3 without an answer.", revocation.value("good").toInt() + revocation.value("revoked").toArray().size(),
                          revocation.value("revoked").toArray().size(), revocation.value("unknown").toInt());
    }
    for (const auto &item : report.value("stores").toArray()) {
        const auto store = item.toObject();
        const QString label = store.value("store").toString();
        if (!store.value("added").toArray().isEmpty()) lines << "5 " + i18n("%1: added %2", label, names(store.value("added").toArray()));
        for (const auto &removed : store.value("removed").toArray())
            lines << "5 " + i18n("%1: removed %2 (%3)", label, removed.toObject().value("name").toString(), removed.toObject().value("reason").toString());
        if (store.value("needsChoice").toInt() > 0) lines << "5 " + i18np("%2: one new E-521 certificate needs your choice and was not installed.", "%2: %1 new E-521 certificates need your choice and were not installed.", store.value("needsChoice").toInt(), label);
        for (const auto &error : store.value("errors").toArray()) lines << "4 " + i18n("%1: %2", label, error.toString());
    }
    for (const auto &deferred : report.value("deferred").toArray()) lines << "6 " + deferred.toString();
    for (const auto &notice : report.value("notices").toArray()) lines << "4 " + notice.toString();
    if (lines.isEmpty()) lines << "6 " + i18n("Nothing to do.");
    return lines.join('\n');
}
QJsonObject runAutomation(const AutomationOptions &options)
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QJsonObject report{{"schema", 1}, {"scope", options.scope}, {"time", now.toString(Qt::ISODate)}, {"runId", QString::number(now.toMSecsSinceEpoch())}};
    const QString statusPath = automationStatusPath(options);
    const QJsonObject previousStatus = readState(statusPath);
    QJsonArray notices, stores, deferred;
    try {
        if (!QDir().mkpath(QFileInfo(statusPath).absolutePath())) fail(i18n("Cannot create the state folder."));
        QLockFile lock(QFileInfo(statusPath).absolutePath() + "/.sparky-ca-auto.lock");
        lock.setStaleLockTime(30 * 60 * 1000);
        if (!lock.tryLock(0)) fail(i18n("Another automatic update is running."));
        Catalogue catalogue = loadCatalogue(options.data, options.stateDirectory);
        QJsonObject catalogueReport{{"source", catalogueSource(options.data, options.stateDirectory)}, {"refreshed", false}, {"changed", false}, {"error", QString()}};
        QString lastRefresh = previousStatus.value("lastRefresh").toString();
        QJsonObject revocationReport;
        if (options.network && options.scope == "system") {
            try {
                Catalogue updated = catalogue;
                updated.ingest(download(options.bundleUrl, options.transport), download(options.hashUrl, options.transport, 4096));
                catalogueReport.insert("refreshed", true);
                lastRefresh = now.toString(Qt::ISODate);
                if (updated.json() != catalogue.json()) {
                    publish(options.stateDirectory + "/catalogue.json", updated.json());
                    catalogueReport.insert("changed", true);
                    catalogue = updated;
                }
            } catch (const std::exception &error) {
                catalogueReport.insert("error", QString::fromUtf8(error.what()));
            }
            const QJsonObject revocation = checkRevocation(catalogue, options.transport, readState(options.stateDirectory + "/revocation.json"), true);
            publish(options.stateDirectory + "/revocation.json", QJsonDocument(revocation).toJson());
            catalogue.applyRevocation(revocation);
            QJsonArray revoked;
            int good = 0, unknown = 0;
            const auto records = revocation.value("certificates").toObject();
            for (const auto &id : records.keys()) {
                const QString status = records.value(id).toObject().value("status").toString();
                good += status == "good";
                unknown += status == "unknown";
                if (status != "revoked") continue;
                for (const auto &entry : catalogue.entries()) if (entry.certificate.fingerprint() == id) revoked.append(QJsonObject{{"name", entry.name}, {"sha256", id}});
            }
            revocationReport = {{"checked", revocation.value("checked")}, {"good", good}, {"unknown", unknown}, {"revoked", revoked}, {"errors", revocation.value("errors")}};
        }
        report.insert("catalogue", catalogueReport);
        if (!revocationReport.isEmpty()) report.insert("revocation", revocationReport);
        if (!catalogueReport.value("error").toString().isEmpty()) {
            const QDateTime last = QDateTime::fromString(lastRefresh, Qt::ISODate);
            if (last.isValid() && last.daysTo(now) > 7) notices.append(i18n("The catalogue has not been refreshed for %1 days.", last.daysTo(now)));
            else if (!last.isValid()) notices.append(i18n("The catalogue has never been refreshed from the Internet on this machine."));
        }
        // An E-521 certificate waiting for the user's choice is reported once, not on every run.
        const auto reported = [&](QJsonObject record) {
            QSet<QString> before;
            for (const auto &item : previousStatus.value("stores").toArray()) {
                const auto old = item.toObject();
                if (old.value("store") != record.value("store")) continue;
                for (const auto &id : old.value("pendingChoice").toArray()) before.insert(id.toString());
            }
            int fresh = 0;
            for (const auto &id : record.value("pendingChoice").toArray()) fresh += !before.contains(id.toString());
            record.insert("needsChoice", fresh);
            return record;
        };
        if (options.scope == "system") {
            Store store(options.systemDirectory, options.systemBundle, {});
            stores.append(reported(store.refresh(catalogue)));
        } else {
            for (const auto &database : options.nssDatabases) {
                Store store({}, {}, database);
                if (store.selectedGroups().isEmpty()) continue;
                if (QFileInfo(database + "/lock").isSymLink()) {
                    deferred.append(i18n("%1 is in use by a browser; it will be updated on a later run.", database));
                    continue;
                }
                stores.append(reported(store.refresh(catalogue)));
            }
        }
        report.insert("lastRefresh", lastRefresh);
    } catch (const std::exception &error) {
        report.insert("error", QString::fromUtf8(error.what()));
        report.insert("lastRefresh", previousStatus.value("lastRefresh"));
    }
    report.insert("stores", stores);
    report.insert("deferred", deferred);
    report.insert("notices", notices);
    bool attention = !report.value("error").toString().isEmpty() || !notices.isEmpty() || !report.value("catalogue").toObject().value("error").toString().isEmpty();
    for (const auto &item : stores) {
        const auto store = item.toObject();
        attention |= !store.value("errors").toArray().isEmpty() || store.value("needsChoice").toInt() > 0;
    }
    report.insert("outcome", !report.value("error").toString().isEmpty() ? "failed" : attention ? "attention" : "ok");
    report.insert("summary", journalLines(report));
    try {
        publish(statusPath, QJsonDocument(report).toJson());
    } catch (const std::exception &error) {
        report.insert("statusError", QString::fromUtf8(error.what()));
    }
    return report;
}
}
