// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core.h"
#include <QStandardPaths>
#include <QMap>
#include <functional>
#include <KLocalizedString>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QLockFile>
#include <QTemporaryDir>
#include <QTemporaryFile>
#include <algorithm>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>

namespace SparkyCA
{
static Certificate fromX509(X509 *certificate)
{
    const int length = i2d_X509(certificate, nullptr);
    if (length <= 0)
        fail(i18n("Cannot encode certificate."));
    QByteArray der(length, '\0');
    auto position = reinterpret_cast<unsigned char *>(der.data());
    i2d_X509(certificate, &position);
    return Certificate(der);
}
static void appendCertificates(QList<Certificate> &output, STACK_OF(X509) * certificates)
{
    for (int i = 0; certificates && i < sk_X509_num(certificates); ++i)
        output.append(fromX509(sk_X509_value(certificates, i)));
}
QList<Certificate> previewCertificates(const QByteArray &bytes, const QByteArray &password)
{
    if (bytes.size() > 16 * 1024 * 1024 || password.contains('\0'))
        fail(i18n("Invalid certificate input."));
    QList<Certificate> result;
    if (bytes.contains("-----BEGIN CERTIFICATE-----")) {
        BIO *bio = BIO_new_mem_buf(bytes.constData(), bytes.size());
        while (X509 *certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) {
            result.append(fromX509(certificate));
            X509_free(certificate);
        }
        BIO_free(bio);
        if (!result.isEmpty())
            return result;
    }
    try {
        return {Certificate(bytes)};
    } catch (const std::exception &) {
    }
    const auto start = reinterpret_cast<const unsigned char *>(bytes.constData());
    auto position = start;
    PKCS7 *p7 = nullptr;
    if (bytes.startsWith("-----BEGIN PKCS7-----")) {
        BIO *bio = BIO_new_mem_buf(bytes.constData(), bytes.size());
        p7 = PEM_read_bio_PKCS7(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
    } else {
        p7 = d2i_PKCS7(nullptr, &position, bytes.size());
        if (position != start + bytes.size()) {
            PKCS7_free(p7);
            p7 = nullptr;
        }
    }
    if (p7) {
        if (PKCS7_type_is_signed(p7))
            appendCertificates(result, p7->d.sign->cert);
        PKCS7_free(p7);
        if (!result.isEmpty())
            return result;
    }
    position = start;
    PKCS12 *p12 = d2i_PKCS12(nullptr, &position, bytes.size());
    if (!p12 || position != start + bytes.size()) {
        PKCS12_free(p12);
        fail(i18n("Cannot parse certificate file."));
    }
    EVP_PKEY *key = nullptr;
    X509 *certificate = nullptr;
    STACK_OF(X509) *chain = nullptr;
    const bool parsed = PKCS12_parse(p12, password.constData(), &key, &certificate, &chain);
    PKCS12_free(p12);
    EVP_PKEY_free(key);
    if (parsed && certificate)
        result.append(fromX509(certificate));
    X509_free(certificate);
    if (parsed)
        appendCertificates(result, chain);
    sk_X509_pop_free(chain, X509_free);
    if (result.isEmpty())
        fail(i18n("Cannot unlock PKCS#12. Check its passphrase."));
    return result;
}
static QString secretFile(QTemporaryFile &file, const QByteArray &password)
{
    if (password.contains('\0') || password.contains('\n'))
        fail(i18n("Passwords cannot contain null bytes or newlines."));
    if (!file.open() || !file.setPermissions(QFile::ReadOwner | QFile::WriteOwner) || file.write(password + '\n') != password.size() + 1 || !file.flush()) {
        fail(i18n("Cannot create a private password file."));
    }
    return file.fileName();
}
static void prepareNss(const QString &database, const QString &password)
{
    validateStorePath(database);
    for (const auto &file : {"cert9.db", "key4.db", "pkcs11.txt"})
        validateStorePath(database + "/" + file);
    if (!QDir().mkpath(database))
        fail(i18n("Cannot create NSS database directory."));
    if (!QFile::exists(database + "/cert9.db"))
        run("certutil", {"-N", "-d", "sql:" + database, "-f", password});
}
void importPersonalCertificate(const QString &file, const QString &database, const QByteArray &password, const QByteArray &databasePassword)
{
    const auto bytes = readFile(file);
    const auto start = reinterpret_cast<const unsigned char *>(bytes.constData());
    auto position = start;
    PKCS12 *p12 = d2i_PKCS12(nullptr, &position, bytes.size());
    EVP_PKEY *key = nullptr;
    X509 *certificate = nullptr;
    STACK_OF(X509) *chain = nullptr;
    const bool valid = p12 && position == start + bytes.size() && !password.contains('\0')
        && PKCS12_parse(p12, password.constData(), &key, &certificate, &chain) && key && certificate && X509_check_private_key(certificate, key);
    PKCS12_free(p12);
    EVP_PKEY_free(key);
    X509_free(certificate);
    sk_X509_pop_free(chain, X509_free);
    if (!valid)
        fail(i18n("Expected a PKCS#12 identity with its matching private key and passphrase."));
    QTemporaryFile p12Password, nssPassword, identity;
    const auto p12Path = secretFile(p12Password, password);
    const auto nssPath = secretFile(nssPassword, databasePassword);
    if (!identity.open() || !identity.setPermissions(QFile::ReadOwner | QFile::WriteOwner) || identity.write(bytes) != bytes.size() || !identity.flush()) {
        fail(i18n("Cannot create a private import file."));
    }
    prepareNss(database, nssPath);
    QLockFile lock(database + "/.sparky-ca.lock");
    if (!lock.tryLock(0))
        fail(i18n("Certificate store is busy."));
    run("pk12util", {"-d", "sql:" + database, "-i", identity.fileName(), "-w", p12Path, "-k", nssPath});
}
void registerTokenModule(const QString &database, const QString &module, const QByteArray &databasePassword)
{
    if (!QFileInfo(module).isAbsolute() || !QFileInfo(module).isFile())
        fail(i18n("Choose an installed PKCS#11 module."));
    QTemporaryFile password;
    const auto file = secretFile(password, databasePassword);
    prepareNss(database, file);
    QLockFile lock(database + "/.sparky-ca.lock");
    if (!lock.tryLock(0))
        fail(i18n("Certificate store is busy."));
    const auto modules = run("modutil", {"-list", "-dbdir", "sql:" + database});
    if (modules.contains("Sparky CA tokens"))
        fail(i18n("The token module is already registered. Inspect it before changing it."));
    const auto manifest = database + "/.sparky-ca-token.json";
    validateStorePath(manifest);
    if (QFile::exists(manifest))
        fail(i18n("An earlier token module record still exists."));
    run("modutil", {"-add", "Sparky CA tokens", "-libfile", module, "-dbdir", "sql:" + database, "-force"});
    writeFile(manifest, QJsonDocument(QJsonObject{{"library", module}}).toJson());
}
void unregisterTokenModule(const QString &database)
{
    validateStorePath(database);
    for (const auto &file : {"cert9.db", "key4.db", "pkcs11.txt", ".sparky-ca-token.json"})
        validateStorePath(database + "/" + file);
    QLockFile lock(database + "/.sparky-ca.lock");
    if (!lock.tryLock(0))
        fail(i18n("Certificate store is busy."));
    const auto manifest = database + "/.sparky-ca-token.json";
    const auto library = QJsonDocument::fromJson(readFile(manifest)).object().value("library").toString();
    const auto modules = run("modutil", {"-list", "Sparky CA tokens", "-dbdir", "sql:" + database});
    if (library.isEmpty() || !modules.contains(library.toUtf8()))
        fail(i18n("The registered token module differs from our record."));
    run("modutil", {"-delete", "Sparky CA tokens", "-dbdir", "sql:" + database, "-force"});
    if (!QFile::remove(manifest))
        fail(i18n("Cannot remove the token module record."));
}
QByteArray tokenInformation(const QString &module)
{
    QStringList arguments;
    if (!module.isEmpty()) {
        if (!QFileInfo(module).isAbsolute() || !QFileInfo(module).isFile())
            fail(i18n("Choose an installed PKCS#11 module."));
        arguments = {"--module", module};
    }
    QByteArray slotList;
    try {
        slotList = run("pkcs11-tool", arguments + QStringList{"--list-slots"});
    } catch (const std::exception &error) {
        if (!QString::fromUtf8(error.what()).contains("No slots."))
            throw;
        return i18n("No token slots detected. Check the reader and installed middleware.").toUtf8() + '\n';
    }
    if (!slotList.contains("Slot "))
        return slotList + i18n("No token slots detected. Check the reader and installed middleware.").toUtf8() + '\n';
    try {
        return slotList + run("pkcs11-tool", arguments + QStringList{"--list-objects", "--type", "cert"});
    } catch (const std::exception &error) {
        return slotList + QString::fromUtf8(error.what()).toUtf8();
    }
}
bool gpgsmAvailable()
{
    return !QStandardPaths::findExecutable("gpgsm").isEmpty();
}
static QString gpgsmManifestPath(const QString &home)
{
    return home + "/sparky-ca-gpgsm.json";
}
static QJsonObject gpgsmManifest(const QString &home)
{
    const auto path = gpgsmManifestPath(home);
    validateStorePath(path);
    if (!QFile::exists(path))
        return {{"owned", QJsonObject()}, {"groups", QJsonObject()}};
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(readFile(path), &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject())
        fail(i18n("Invalid GnuPG import record."));
    return doc.object();
}
static bool validFingerprint(const QString &id)
{
    return id.size() == 40 && std::all_of(id.cbegin(), id.cend(), [](QChar c) {
               return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
           });
}
static QString sha1Fingerprint(const Certificate &cert)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    if (!X509_digest(cert.get(), EVP_sha1(), digest, &size))
        fail(i18n("Cannot calculate GnuPG's certificate identifier."));
    return QString::fromLatin1(QByteArray(reinterpret_cast<char *>(digest), size).toHex().toUpper());
}
// gpgsm's keybox as {SHA-1 fingerprint: trust letter}. 'u' is ultimate trust, which gpgsm gives a root the user confirmed.
static QMap<QString, QString> keybox(const QString &home)
{
    QMap<QString, QString> result;
    QByteArray listing;
    try {
        listing = run("gpgsm", {"--homedir", home, "--batch", "--list-keys", "--with-colons"});
    } catch (const std::exception &) {
        return result;
    }
    QString trust;
    for (const auto &line : QString::fromUtf8(listing).split('\n')) {
        const auto fields = line.split(':');
        if (fields.value(0) == "crt")
            trust = fields.value(1);
        else if (fields.value(0) == "fpr" && validFingerprint(fields.value(9)))
            result.insert(fields.value(9), trust);
    }
    return result;
}
static void prepareGpgHome(const QString &home)
{
    validateStorePath(home);
    if (!QDir().mkpath(home) || !QFile::setPermissions(home, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner))
        fail(i18n("Cannot prepare the GnuPG directory."));
}
// Version 2.0.0 added its roots to gpgsm's trust list without asking. Take back only what it wrote.
static bool retireLegacyTrust(const QString &home)
{
    const auto trustPath = home + "/trustlist.txt";
    const auto legacy = home + "/sparky-ca-trust.json";
    validateStorePath(trustPath);
    validateStorePath(legacy);
    const QByteArray begin("# sparky-ca managed roots begin\n"), end("# sparky-ca managed roots end\n");
    bool changed = false;
    if (QFile::exists(trustPath)) {
        auto content = readFile(trustPath);
        const int first = content.indexOf(begin), last = content.indexOf(end);
        if (first >= 0 && last > first) {
            content.remove(first, last + end.size() - first);
            writeFile(trustPath, content);
            changed = true;
        }
    }
    if (QFile::exists(legacy) && QFile::remove(legacy))
        changed = true;
    if (changed && gpgsmAvailable()) {
        try {
            run("gpgconf", {"--homedir", home, "--reload", "gpg-agent"});
        } catch (const std::exception &) {
        }
    }
    return changed;
}
QJsonObject gpgsmImport(const Catalogue &catalogue, const QString &group, const QString &home)
{
    if (!gpgsmAvailable())
        fail(i18n("GnuPG's gpgsm is not installed."));
    if (!catalogue.groups().contains(group))
        fail(i18n("Unknown certificate group: %1", group));
    prepareGpgHome(home);
    QLockFile lock(home + "/.sparky-ca.lock");
    if (!lock.tryLock(0))
        fail(i18n("GnuPG certificate store is busy."));
    const bool legacy = retireLegacyTrust(home);
    auto manifest = gpgsmManifest(home);
    auto owned = manifest.value("owned").toObject();
    auto groups = manifest.value("groups").toObject();
    // The chain of every chosen certificate, up to its root, in the order gpgsm can verify it.
    const auto usable = [&](const Entry &entry) {
        return catalogue.state(entry.certificate) == "valid" && entry.certificate.signatureOid() != "1.3.6.1.4.1.44588.2.1"
            && catalogue.installationIssue(entry.certificate).isEmpty();
    };
    QList<const Entry *> chain;
    QSet<QString> seen;
    const std::function<bool(const Entry &)> add = [&](const Entry &entry) {
        if (seen.contains(entry.certificate.fingerprint()))
            return true;
        if (!usable(entry))
            return false;
        if (!entry.certificate.root()) {
            const Entry *issuer = nullptr;
            for (const auto &candidate : catalogue.entries()) {
                if (entry.certificate.issuedBy(candidate.certificate)) {
                    issuer = &candidate;
                    break;
                }
            }
            if (!issuer || !add(*issuer))
                return false;
        }
        seen.insert(entry.certificate.fingerprint());
        chain.append(&entry);
        return true;
    };
    QJsonArray skipped;
    for (const auto &entry : catalogue.entries()) {
        if (entry.groups.contains(group) && !add(entry))
            skipped.append(entry.name);
    }
    if (chain.isEmpty())
        fail(i18n("This group has no certificates gpgsm can use."));
    const auto before = keybox(home);
    QJsonArray imported, present;
    QJsonArray members;
    QTemporaryDir temporary;
    for (const Entry *entry : chain) {
        const QString sha1 = sha1Fingerprint(entry->certificate);
        catalogue.verify(entry->certificate, true);
        members.append(sha1);
        if (before.contains(sha1)) {
            present.append(entry->name);
            continue;
        }
        writeFile(temporary.path() + "/certificate.pem", entry->certificate.pem());
        run("gpgsm", {"--homedir", home, "--batch", "--import", temporary.path() + "/certificate.pem"});
        owned.insert(sha1, QJsonObject{{"sha256", entry->certificate.fingerprint()}, {"name", entry->name}, {"root", entry->certificate.root()}});
        imported.append(entry->name);
        manifest.insert("owned", owned);
        writeFile(gpgsmManifestPath(home), QJsonDocument(manifest).toJson());
    }
    groups.insert(group, members);
    manifest.insert("owned", owned);
    manifest.insert("groups", groups);
    writeFile(gpgsmManifestPath(home), QJsonDocument(manifest).toJson());
    return {{"imported", imported}, {"alreadyPresent", present}, {"skipped", skipped}, {"previousTrustRemoved", legacy}};
}
QJsonObject gpgsmRemove(const QString &group, const QString &home)
{
    if (!gpgsmAvailable())
        fail(i18n("GnuPG's gpgsm is not installed."));
    prepareGpgHome(home);
    QLockFile lock(home + "/.sparky-ca.lock");
    if (!lock.tryLock(0))
        fail(i18n("GnuPG certificate store is busy."));
    const bool legacy = retireLegacyTrust(home);
    auto manifest = gpgsmManifest(home);
    auto owned = manifest.value("owned").toObject();
    auto groups = manifest.value("groups").toObject();
    if (group != "all")
        groups.remove(group);
    else
        groups = {};
    QSet<QString> needed;
    for (const auto &members : groups)
        for (const auto &id : members.toArray())
            needed.insert(id.toString());
    QJsonArray removed;
    const auto present = keybox(home);
    for (const auto &id : owned.keys()) {
        if (needed.contains(id))
            continue;
        if (!validFingerprint(id))
            fail(i18n("Invalid GnuPG certificate identifier."));
        if (present.contains(id))
            run("gpgsm", {"--homedir", home, "--batch", "--yes", "--delete-keys", id});
        removed.append(owned.value(id).toObject().value("name").toString());
        owned.remove(id);
        manifest.insert("owned", owned);
        writeFile(gpgsmManifestPath(home), QJsonDocument(manifest).toJson());
    }
    manifest.insert("owned", owned);
    manifest.insert("groups", groups);
    writeFile(gpgsmManifestPath(home), QJsonDocument(manifest).toJson());
    return {{"removed", removed}, {"previousTrustRemoved", legacy}};
}
QJsonArray gpgsmStatus(const QString &home)
{
    QJsonArray result;
    if (!gpgsmAvailable() || !QFile::exists(gpgsmManifestPath(home)))
        return result;
    validateStorePath(home);
    const auto owned = gpgsmManifest(home).value("owned").toObject();
    const auto present = keybox(home);
    for (const auto &id : owned.keys()) {
        const auto record = owned.value(id).toObject();
        QString trust = "not imported";
        if (present.contains(id))
            trust = !record.value("root").toBool() ? "through its root" : present.value(id) == "u" ? "confirmed by you" : "not confirmed";
        result.append(QJsonObject{{"name", record.value("name")}, {"sha1", id}, {"sha256", record.value("sha256")}, {"root", record.value("root")}, {"trust", trust}});
    }
    return result;
}
QStringList gpgsmUnconfirmedRoots(const QString &home)
{
    QStringList roots;
    for (const auto &item : gpgsmStatus(home)) {
        const auto record = item.toObject();
        if (record.value("root").toBool() && record.value("trust").toString() == "not confirmed")
            roots.append(record.value("sha1").toString());
    }
    return roots;
}
}
