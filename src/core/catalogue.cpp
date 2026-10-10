// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core.h"
#include <KLocalizedString>
#include <QCryptographicHash>
#include <QDir>
#include <QJsonDocument>
#include <QRegularExpression>
#include <archive.h>
#include <archive_entry.h>
#include <openssl/x509v3.h>

namespace SparkyCA
{
static QJsonObject object(const QByteArray &bytes)
{
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(bytes, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) fail(i18n("Invalid catalogue JSON."));
    return document.object();
}
Catalogue::Catalogue(const QString &pinsFile, const QString &rootsDirectory)
{
    const QJsonObject pins = object(readFile(pinsFile));
    for (const auto &item : pins.value("roots").toArray()) {
        const auto pin = item.toObject();
        const QString file = pin.value("file").toString();
        if (file.isEmpty() || QFileInfo(file).fileName() != file) fail(i18n("Invalid root filename."));
        const Certificate cert(readFile(QDir(rootsDirectory).filePath(file)));
        if (!cert.root() || !cert.ca() || cert.fingerprint() != pin.value("sha256").toString()) fail(i18n("Root fingerprint mismatch: %1", file));
        if (pin.value("revoked").toBool()) m_revoked.insert(cert.fingerprint());
        m_roots.append(cert);
    }
    if (m_roots.isEmpty()) fail(i18n("No pinned roots."));
}
void Catalogue::verify(const Certificate &cert, bool current) const
{
    if (cert.root()) {
        bool pinned = false;
        for (const auto &root : m_roots) pinned |= root.fingerprint() == cert.fingerprint();
        if (!pinned) fail(i18n("Root is not pinned: %1", cert.subject()));
    }
    X509_STORE *store = X509_STORE_new();
    for (const auto &root : m_roots) X509_STORE_add_cert(store, root.get());
    STACK_OF(X509) *chain = sk_X509_new_null();
    for (const auto &entry : m_entries) if (!entry.certificate.root()) sk_X509_push(chain, entry.certificate.get());
    X509_STORE_CTX *context = X509_STORE_CTX_new();
    X509_STORE_CTX_init(context, store, cert.get(), chain);
    X509_VERIFY_PARAM *parameters = X509_STORE_CTX_get0_param(context);
    X509_VERIFY_PARAM_set_flags(parameters, X509_V_FLAG_CHECK_SS_SIGNATURE);
    if (!current) {
        X509_VERIFY_PARAM_set_flags(parameters, X509_V_FLAG_NO_CHECK_TIME);
        X509_VERIFY_PARAM_set_auth_level(parameters, 0);
    }
    const bool valid = X509_verify_cert(context) == 1;
    const QString error = QString::fromLatin1(X509_verify_cert_error_string(X509_STORE_CTX_get_error(context)));
    bool revoked = false;
    STACK_OF(X509) *verified = X509_STORE_CTX_get0_chain(context);
    for (int index = 0; verified && index < sk_X509_num(verified); ++index) {
        X509 *member = sk_X509_value(verified, index);
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
        X509_digest(member, EVP_sha256(), digest, &length);
        revoked |= m_revoked.contains(QString::fromLatin1(QByteArray(reinterpret_cast<char *>(digest), length).toHex()));
    }
    X509_STORE_CTX_free(context);
    sk_X509_free(chain);
    X509_STORE_free(store);
    if (!valid || !cert.ca()) fail(i18n("Certificate chain rejected: %1: %2", cert.subject(), error));
    if (current && (revoked || cert.state() != "valid")) fail(i18n("Certificate is expired, revoked or not yet valid: %1", cert.subject()));
}
void Catalogue::validate(const QList<Entry> &entries) const
{
    if (entries.isEmpty() || entries.size() > 1024) fail(i18n("Invalid certificate count."));
    for (const auto &entry : entries) verify(entry.certificate, false);
}
void Catalogue::load(const QByteArray &json)
{
    const QJsonObject document = object(json);
    if (document.value("schema").toInt() != 1) fail(i18n("Unsupported catalogue schema."));
    QList<Entry> entries;
    for (const auto &item : document.value("certificates").toArray()) {
        const auto entry = item.toObject();
        const QString name = entry.value("name").toString();
        Certificate cert(entry.value("pem").toString().toUtf8());
        entries.append({name, classify(name, cert), cert});
    }
    const auto previous = m_entries;
    m_entries = entries;
    try { validate(entries); } catch (...) { m_entries = previous; throw; }
}
void Catalogue::ingest(const QByteArray &zip, const QByteArray &sha512)
{
    const auto fields = sha512.trimmed().split(' ');
    const QByteArray expected = fields.value(0).toLower();
    if (!QRegularExpression("^[0-9a-f]{128}$").match(QString::fromLatin1(expected)).hasMatch()
        || QCryptographicHash::hash(zip, QCryptographicHash::Sha512).toHex() != expected) fail(i18n("Bundle SHA-512 mismatch."));
    if (zip.size() > 8 * 1024 * 1024) fail(i18n("Bundle is too large."));
    using Archive = std::unique_ptr<archive, decltype(&archive_read_free)>;
    Archive reader(archive_read_new(), archive_read_free);
    archive_read_support_format_zip(reader.get());
    if (archive_read_open_memory(reader.get(), zip.constData(), zip.size()) != ARCHIVE_OK) fail(i18n("Cannot open ZIP bundle."));
    QList<Entry> entries;
    QSet<QString> names;
    archive_entry *entry = nullptr;
    qsizetype total = 0;
    int result = 0;
    while ((result = archive_read_next_header(reader.get(), &entry)) == ARCHIVE_OK) {
        const QString name = QString::fromUtf8(archive_entry_pathname(entry));
        if (name.isEmpty() || name.contains('/') || name.contains('\\') || name.contains("..") || !name.endsWith(".crt", Qt::CaseInsensitive)
            || archive_entry_filetype(entry) != AE_IFREG || archive_entry_symlink(entry) || archive_entry_hardlink(entry)
            || names.contains(name) || names.size() >= 1024 || archive_entry_size(entry) > 256 * 1024) fail(i18n("Unsafe ZIP entry: %1", name));
        names.insert(name);
        QByteArray bytes;
        char buffer[4096];
        la_ssize_t count;
        while ((count = archive_read_data(reader.get(), buffer, sizeof(buffer))) > 0) {
            bytes.append(buffer, count);
            total += count;
            if (bytes.size() > 256 * 1024 || total > 16 * 1024 * 1024) fail(i18n("Expanded bundle is too large."));
        }
        if (count < 0) fail(i18n("Corrupt ZIP entry: %1", name));
        Certificate cert(bytes);
        entries.append({name, classify(name, cert), cert});
    }
    if (result != ARCHIVE_EOF) fail(i18n("Corrupt ZIP bundle."));
    for (const auto &root : m_roots) {
        bool found = false;
        for (const auto &entry : entries) found |= entry.certificate.fingerprint() == root.fingerprint();
        if (!found) entries.append({root.subject(), classify("ICP-Brasil", root), root});
    }
    const auto previous = m_entries;
    m_entries = entries;
    try { validate(entries); } catch (...) { m_entries = previous; throw; }
}
QByteArray Catalogue::json() const
{
    QJsonArray entries;
    for (const auto &entry : m_entries) entries.append(QJsonObject{{"name", entry.name}, {"pem", QString::fromUtf8(entry.certificate.pem())}});
    return QJsonDocument(QJsonObject{{"schema", 1}, {"certificates", entries}}).toJson();
}
QStringList classify(const QString &name, const Certificate &cert)
{
    if (cert.root()) return {"icp-roots", "chrome-roots"};
    const QString label = (name + cert.subject()).toLower();
    QStringList groups;
    for (const QString family : {"certisign", "serasa", "serpro", "soluti", "valid", "oab", "rfb"}) if (label.contains(family)) groups.append(family);
    if (label.contains("jus") || label.contains("justica") || label.contains("justiça")) groups.append("justica");
    if (label.contains("ssl")) groups.append("ssl");
    if (label.contains("codesigning") || label.contains("code signing") || name.toLower().contains("_cd")) groups.append("code-signing");
    if (groups.isEmpty()) groups.append("other");
    return groups;
}
QStringList Catalogue::groups() const
{
    QSet<QString> groups;
    for (const auto &entry : m_entries) for (const auto &group : entry.groups) groups.insert(group);
    QStringList result(groups.begin(), groups.end());
    result.sort();
    return result;
}
QString Catalogue::state(const Certificate &cert) const
{
    return m_revoked.contains(cert.fingerprint()) ? QStringLiteral("revoked") : cert.state();
}
}
