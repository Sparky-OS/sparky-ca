// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core.h"
#include <KLocalizedString>
#include <QFile>
#include <QProcess>
#include <QSaveFile>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdexcept>

namespace SparkyCA
{
void fail(const QString &message)
{
    throw std::runtime_error(message.toUtf8().constData());
}
QByteArray readFile(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 16 * 1024 * 1024) {
        fail(i18n("Cannot read file: %1", path));
    }
    return file.readAll();
}
void writeFile(const QString &path, const QByteArray &data)
{
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write(data) != data.size() || !file.commit()) {
        fail(i18n("Cannot write file: %1", path));
    }
}
QByteArray run(const QString &program, const QStringList &arguments)
{
    QProcess process;
    process.start(program, arguments);
    if (!process.waitForStarted() || !process.waitForFinished(60000) || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        fail(i18n("Command failed: %1: %2", program, QString::fromUtf8(process.readAllStandardError())));
    }
    return process.readAllStandardOutput();
}
Certificate::Certificate(const QByteArray &bytes)
{
    X509 *cert = nullptr;
    if (bytes.startsWith("-----BEGIN CERTIFICATE-----")) {
        BIO *bio = BIO_new_mem_buf(bytes.constData(), bytes.size());
        cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        QByteArray remaining(BIO_ctrl_pending(bio), '\0');
        BIO_read(bio, remaining.data(), remaining.size());
        BIO_free(bio);
        if (!remaining.trimmed().isEmpty()) {
            X509_free(cert);
            fail(i18n("Expected exactly one certificate."));
        }
    } else {
        const unsigned char *position = reinterpret_cast<const unsigned char *>(bytes.constData());
        cert = d2i_X509(nullptr, &position, bytes.size());
        if (position != reinterpret_cast<const unsigned char *>(bytes.constData() + bytes.size())) {
            X509_free(cert);
            fail(i18n("Invalid certificate encoding."));
        }
    }
    if (!cert) {
        fail(i18n("Cannot parse certificate."));
    }
    m_cert = std::shared_ptr<X509>(cert, X509_free);
}
QByteArray Certificate::pem() const
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, get());
    char *data = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    const QByteArray result(data, size);
    BIO_free(bio);
    return result;
}
QString Certificate::fingerprint() const
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (!X509_digest(get(), EVP_sha256(), digest, &length)) {
        fail(i18n("Cannot calculate certificate fingerprint."));
    }
    return QString::fromLatin1(QByteArray(reinterpret_cast<char *>(digest), length).toHex());
}
static QString name(X509_NAME *name)
{
    BIO *bio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
    char *data = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    const QString result = QString::fromUtf8(data, size);
    BIO_free(bio);
    return result;
}
QString Certificate::subject() const { return name(X509_get_subject_name(get())); }
QString Certificate::issuer() const { return name(X509_get_issuer_name(get())); }
bool Certificate::root() const { return X509_NAME_cmp(X509_get_subject_name(get()), X509_get_issuer_name(get())) == 0; }
bool Certificate::ca() const { return X509_check_ca(get()) > 0; }
QString Certificate::state() const
{
    const int before = X509_cmp_current_time(X509_get0_notBefore(get()));
    const int after = X509_cmp_current_time(X509_get0_notAfter(get()));
    if (before == 0 || after == 0) return QStringLiteral("invalid");
    if (before > 0) return QStringLiteral("not-yet-valid");
    if (after < 0) return QStringLiteral("expired");
    return QStringLiteral("valid");
}
QDateTime Certificate::expires() const
{
    struct tm time = {};
    if (!ASN1_TIME_to_tm(X509_get0_notAfter(get()), &time)) fail(i18n("Invalid certificate expiry."));
    return QDateTime(QDate(time.tm_year + 1900, time.tm_mon + 1, time.tm_mday), QTime(time.tm_hour, time.tm_min, time.tm_sec), QTimeZone::UTC);
}
QJsonObject describe(const Certificate &cert, const QString &name, const QString &state)
{
    return {{"name", name}, {"subject", cert.subject()}, {"issuer", cert.issuer()}, {"sha256", cert.fingerprint()},
            {"expires", cert.expires().toString(Qt::ISODate)}, {"state", state}, {"root", cert.root()}};
}
}
