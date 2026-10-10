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
#include <algorithm>
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
    for (const auto &hash : pins.value("bundleSha512").toArray()) m_bundlePins.insert(hash.toString());
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
static bool e521Root(const Certificate &cert)
{
    return cert.fingerprint() == "5657e70580eb678983f3ed7dfce091d84cae6549389a47fccda8d0e4dc2cf576"
        && cert.signatureOid() == "1.3.6.1.4.1.44588.2.1";
}
bool Catalogue::requiresE521(const Certificate &cert) const
{
    if (e521Root(cert)) return true;
    for (const auto &root : m_roots) if (e521Root(root) && cert.issuedBy(root)) return true;
    return false;
}
QString Catalogue::verification(const Certificate &cert) const
{
    if (cert.root()) return QStringLiteral("pinned-root");
    return requiresE521(cert) ? QStringLiteral("transport-integrity-only") : QStringLiteral("signature-verified");
}
QString Catalogue::verificationNote(const Certificate &cert) const
{
    if (!requiresE521(cert)) return {};
    return i18n("Chain signature not verifiable on Linux (E-521). Linux's crypto libraries cannot use E-521 yet; these certificates help only programs that carry their own E-521 code.");
}
QString Catalogue::installationIssue(const Certificate &cert) const
{
    try { verify(cert, true); } catch (const std::exception &error) {
        return QString::fromUtf8(error.what());
    }
    return {};
}
void Catalogue::verify(const Certificate &cert, bool current) const
{
    if (cert.root()) {
        bool pinned = false;
        for (const auto &root : m_roots) pinned |= root.fingerprint() == cert.fingerprint();
        if (!pinned) fail(i18n("Root is not pinned: %1", cert.subject()));
        if (!cert.ca()) fail(i18n("Pinned certificate is not a CA."));
        if (current && state(cert) != "valid") fail(i18n("Root is expired, revoked or not yet valid."));
        return;
    }
    if (requiresE521(cert)) {
        if (!cert.ca() || cert.signatureOid() != "1.3.6.1.4.1.44588.2.1" || !m_e521Allowed.contains(cert.fingerprint())) {
            fail(i18n("E-521 certificate lacks authenticated bundle integrity evidence."));
        }
        for (const auto &root : m_roots) if (e521Root(root) && cert.issuedBy(root) && current && state(root) != "valid") fail(i18n("E-521 root is not currently valid."));
        if (current && state(cert) != "valid") fail(i18n("E-521 certificate is not currently valid."));
        return;
    }
    X509_STORE *store = X509_STORE_new();
    for (const auto &root : m_roots) X509_STORE_add_cert(store, root.get());
    STACK_OF(X509) *chain = sk_X509_new_null();
    for (const auto &entry : m_entries) if (!entry.certificate.root()) sk_X509_push(chain, entry.certificate.get());
    X509_STORE_CTX *context = X509_STORE_CTX_new();
    X509_STORE_CTX_init(context, store, cert.get(), chain);
    X509_VERIFY_PARAM *parameters = X509_STORE_CTX_get0_param(context);
    if (!current) {
        X509_VERIFY_PARAM_set_flags(parameters, X509_V_FLAG_NO_CHECK_TIME);
        X509_VERIFY_PARAM_set_auth_level(parameters, 0);
        X509_STORE_CTX_set_verify_cb(context, [](int valid, X509_STORE_CTX *context) -> int {
            // Archive explicit-curve certificates while still verifying every signature.
            return valid || X509_STORE_CTX_get_error(context) == X509_V_ERR_EC_KEY_EXPLICIT_PARAMS;
        });
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
    const auto previousAllowed = m_e521Allowed;
    const auto previousProvenance = m_provenance;
    const auto previousEntries = m_entries;
    m_e521Allowed.clear();
    m_provenance = {};
    try {
        for (const auto &source : document.value("provenance").toArray()) {
            const auto proof = source.toObject();
            const QByteArray hash = proof.value("sha512").toString().toLatin1();
            if (!m_bundlePins.contains(QString::fromLatin1(hash))) fail(i18n("Unapproved E-521 source bundle."));
            ingest(QByteArray::fromBase64(proof.value("zip").toString().toLatin1()), hash);
        }
        QList<Entry> entries;
        for (const auto &item : document.value("certificates").toArray()) {
            const auto entry = item.toObject();
            const QString name = entry.value("name").toString();
            Certificate cert(entry.value("pem").toString().toUtf8());
            entries.append({name, classify(name, cert), cert});
        }
        m_entries = entries;
        validate(entries);
    } catch (...) {
        m_entries = previousEntries; m_e521Allowed = previousAllowed; m_provenance = previousProvenance;
        throw;
    }
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
    const auto previousAllowed = m_e521Allowed;
    const auto previousProvenance = m_provenance;
    bool needsProof = false;
    for (const auto &item : entries) {
        if (!item.certificate.root() && requiresE521(item.certificate)) {
            if (!m_bundlePins.contains(QString::fromLatin1(expected))) fail(i18n("E-521 source bundle hash is not approved."));
            m_e521Allowed.insert(item.certificate.fingerprint());
            needsProof = true;
        }
    }
    if (needsProof) {
        bool recorded = false;
        for (const auto &proof : m_provenance) recorded |= proof.toObject().value("sha512").toString().toLatin1() == expected;
        if (!recorded) m_provenance.append(QJsonObject{{"sha512", QString::fromLatin1(expected)}, {"zip", QString::fromLatin1(zip.toBase64())}});
    }
    for (const auto &root : m_roots) {
        bool found = false;
        for (const auto &entry : entries) found |= entry.certificate.fingerprint() == root.fingerprint();
        for (const auto &entry : m_entries) found |= entry.certificate.fingerprint() == root.fingerprint();
        if (!found) entries.append({root.subject(), classify("ICP-Brasil", root), root});
    }
    const auto previous = m_entries;
    QSet<QString> fingerprints;
    QList<Entry> merged;
    for (const auto &item : entries + previous) {
        const QString fingerprint = item.certificate.fingerprint();
        if (!fingerprints.contains(fingerprint)) merged.append(item);
        else for (auto &retained : merged) {
            if (retained.certificate.fingerprint() == fingerprint && item.name < retained.name) retained = item;
        }
        fingerprints.insert(fingerprint);
    }
    entries = merged;
    m_entries = entries;
    try { validate(entries); } catch (...) {
        m_entries = previous; m_e521Allowed = previousAllowed; m_provenance = previousProvenance;
        throw;
    }
}
QByteArray Catalogue::json() const
{
    QJsonArray entries;
    auto ordered = m_entries;
    std::sort(ordered.begin(), ordered.end(), [](const Entry &left, const Entry &right) {
        if (left.name != right.name) return left.name < right.name;
        return left.certificate.fingerprint() < right.certificate.fingerprint();
    });
    for (const auto &entry : ordered) entries.append(QJsonObject{{"name", entry.name}, {"pem", QString::fromUtf8(entry.certificate.pem())}});
    return QJsonDocument(QJsonObject{{"schema", 1}, {"certificates", entries}, {"provenance", m_provenance}}).toJson();
}
QStringList classify(const QString &name, const Certificate &cert)
{
    if (cert.root()) {
        QStringList groups{"icp-roots", "chrome-roots"};
        if (e521Root(cert)) groups.append("e521");
        return groups;
    }
    const QString label = (name + cert.subject()).toLower();
    QStringList groups;
    if (cert.signatureOid() == "1.3.6.1.4.1.44588.2.1") groups.append("e521");
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
