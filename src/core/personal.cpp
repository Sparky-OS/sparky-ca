// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core.h"
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
void setGpgsmTrust(const Catalogue &catalogue, const QString &group, const QString &home, bool trusted)
{
    if (!catalogue.groups().contains(group))
        fail(i18n("Unknown certificate group: %1", group));
    validateStorePath(home);
    if (!QDir().mkpath(home) || !QFile::setPermissions(home, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner))
        fail(i18n("Cannot prepare the GnuPG directory."));
    const auto trustPath = home + "/trustlist.txt";
    const auto manifestPath = home + "/sparky-ca-trust.json";
    validateStorePath(trustPath);
    validateStorePath(manifestPath);
    QLockFile lock(home + "/.sparky-ca.lock");
    if (!lock.tryLock(0))
        fail(i18n("GnuPG trust list is busy."));
    QJsonObject groups;
    if (QFile::exists(manifestPath)) {
        QJsonParseError error;
        const auto doc = QJsonDocument::fromJson(readFile(manifestPath), &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject())
            fail(i18n("Invalid GnuPG trust manifest."));
        groups = doc.object();
    }
    const QByteArray begin("# sparky-ca managed roots begin\n"), end("# sparky-ca managed roots end\n");
    QByteArray content = QFile::exists(trustPath) ? readFile(trustPath) : QByteArray();
    const int first = content.indexOf(begin), last = content.indexOf(end);
    if ((first < 0) != (last < 0) || (first >= 0 && (last < first || content.indexOf(begin, first + 1) >= 0 || content.indexOf(end, last + 1) >= 0))) {
        fail(i18n("Invalid managed GnuPG trust block."));
    }
    if (first >= 0)
        content.remove(first, last + end.size() - first);
    if (trusted) {
        QJsonArray roots;
        QTemporaryDir temporary;
        for (const auto &entry : catalogue.entries()) {
            if (!entry.groups.contains(group) || !entry.certificate.root() || catalogue.state(entry.certificate) != "valid")
                continue;
            if (entry.certificate.signatureOid() == "1.3.6.1.4.1.44588.2.1")
                continue;
            catalogue.verify(entry.certificate, true);
            writeFile(temporary.path() + "/root.pem", entry.certificate.pem());
            run("gpgsm", {"--homedir", home, "--batch", "--import", temporary.path() + "/root.pem"});
            unsigned char digest[EVP_MAX_MD_SIZE];
            unsigned int size = 0;
            if (!X509_digest(entry.certificate.get(), EVP_sha1(), digest, &size))
                fail(i18n("Cannot calculate GnuPG's root identifier."));
            roots.append(QString::fromLatin1(QByteArray(reinterpret_cast<char *>(digest), size).toHex().toUpper()));
        }
        if (roots.isEmpty())
            fail(i18n("This group has no current root certificates."));
        groups.insert(group, roots);
    } else
        groups.remove(group);
    QSet<QString> identifiers;
    for (auto it = groups.begin(); it != groups.end(); ++it) {
        for (const auto &root : it.value().toArray()) {
            const auto id = root.toString();
            if (id.size() != 40 || !std::all_of(id.cbegin(), id.cend(), [](QChar c) {
                    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
                }))
                fail(i18n("Invalid GnuPG root identifier."));
            identifiers.insert(id);
        }
    }
    auto ordered = identifiers.values();
    ordered.sort();
    if (!content.isEmpty() && !content.endsWith('\n'))
        content.append('\n');
    if (!ordered.isEmpty()) {
        content.append(begin);
        for (const auto &id : ordered)
            content.append(id.toLatin1() + " S\n");
        content.append(end);
    }
    writeFile(trustPath, content);
    writeFile(manifestPath, QJsonDocument(groups).toJson());
    run("gpgconf", {"--homedir", home, "--reload", "gpg-agent"});
}
}
