// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core.h"
#include <KLocalizedString>
#include <QFile>
#include <QProcess>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <openssl/err.h>

// The message lives in its own translation domain, so that it ships in all nine of the
// edition's languages while the rest of Sparky CA ships only its complete translations.
#define ED521_DOMAIN "sparky-ca-ed521"

namespace SparkyCA
{
namespace
{
struct Result {
    bool ok = false;
    QByteArray output;
};
Result tool(const QString &program, const QStringList &arguments)
{
    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start(program, arguments);
    Result result;
    if (!process.waitForStarted() || !process.waitForFinished(20000)) {
        process.kill();
        process.waitForFinished();
        return result;
    }
    result.output = process.readAll();
    result.ok = process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
    return result;
}
bool opensslVerifies(const QString &v7File)
{
    try {
        const Certificate cert(readFile(v7File));
        EVP_PKEY *key = X509_get0_pubkey(cert.get());
        const bool verified = key && X509_verify(cert.get(), key) == 1;
        ERR_clear_error();
        return verified;
    } catch (const std::exception &) {
        ERR_clear_error();
        return false;
    }
}
std::optional<bool> nssVerifies(const QString &v7File)
{
    const QString certutil = QStandardPaths::findExecutable(QStringLiteral("certutil"));
    QTemporaryDir directory;
    if (certutil.isEmpty() || !directory.isValid())
        return std::nullopt;
    const QString database = QStringLiteral("sql:") + directory.path();
    if (!tool(certutil, {"-N", "-d", database, "--empty-password"}).ok)
        return std::nullopt;
    // NSS 3.130 already refuses to import the key type (SEC_ERROR_UNSUPPORTED_KEYALG).
    if (!tool(certutil, {"-A", "-d", database, "-n", "v7", "-t", "C,C,C", "-a", "-i", v7File}).ok)
        return false;
    const Result verified = tool(certutil, {"-V", "-d", database, "-n", "v7", "-u", "L", "-e"});
    return verified.ok && verified.output.contains("certificate is valid");
}
std::optional<bool> gnupgVerifies(const QString &v7File)
{
    const QString gpgsm = QStandardPaths::findExecutable(QStringLiteral("gpgsm"));
    QTemporaryDir directory;
    if (gpgsm.isEmpty() || !directory.isValid())
        return std::nullopt;
    const Result imported = tool(gpgsm, {"--homedir", directory.path(), "--batch", "--disable-crl-checks", "--disable-dirmngr", "--import", v7File});
    const QString gpgconf = QStandardPaths::findExecutable(QStringLiteral("gpgconf"));
    if (!gpgconf.isEmpty())
        tool(gpgconf, {"--homedir", directory.path(), "--kill", "all"});
    // gpgsm checks a root's self-signature on import; it refuses Ed521 as an unknown algorithm today.
    return imported.ok && imported.output.contains("imported: 1") && !imported.output.contains("not imported");
}
}

Ed521Support probeEd521(const QString &v7File)
{
    Ed521Support support;
    support.openssl = opensslVerifies(v7File);
    support.providerInstalled = QFile::exists(QStringLiteral("/usr/share/openssl-provider-ed521/openssl.cnf"));
    support.nss = nssVerifies(v7File);
    support.gnupg = gnupgVerifies(v7File);
    support.chromium = !QStandardPaths::findExecutable(QStringLiteral("chromium")).isEmpty();
    return support;
}

bool ed521Complete(const Ed521Support &support)
{
    return support.openssl && support.nss.value_or(true) && support.gnupg.value_or(true) && !support.chromium;
}

QString ed521State(const Ed521Support &support)
{
    auto flag = [](const std::optional<bool> &value) {
        return value ? (*value ? QStringLiteral("1") : QStringLiteral("0")) : QStringLiteral("-");
    };
    return QStringLiteral("openssl=%1;provider=%2;nss=%3;gnupg=%4;chromium=%5")
        .arg(support.openssl ? 1 : 0)
        .arg(support.providerInstalled ? 1 : 0)
        .arg(flag(support.nss), flag(support.gnupg))
        .arg(support.chromium ? 1 : 0);
}

QString ed521Message(const Ed521Support &support)
{
    if (ed521Complete(support))
        return {};
    QStringList parts;
    if (support.openssl)
        parts << i18nd(ED521_DOMAIN, "ICP-Brasil v7 (Ed521) certificates validate on this computer in the command line and in programs that use OpenSSL.");
    else if (support.providerInstalled)
        parts << i18nd(ED521_DOMAIN, "ICP-Brasil v7 (Ed521) certificates do not validate on this computer: the package openssl-provider-ed521 is installed, but OpenSSL does not use it. The command /usr/libexec/openssl-provider-ed521/system-config status shows why.");
    else
        parts << i18nd(ED521_DOMAIN, "ICP-Brasil v7 (Ed521) certificates do not validate on this computer yet. Install the package openssl-provider-ed521 to validate them in the command line and in programs that use OpenSSL.");
    if (support.nss)
        parts << (*support.nss ? i18nd(ED521_DOMAIN, "Firefox, Waterfox and Okular validate them through NSS.")
                               : i18nd(ED521_DOMAIN, "Firefox, Waterfox and Okular check certificates with NSS, which cannot validate Ed521 yet."));
    if (support.gnupg)
        parts << (*support.gnupg ? i18nd(ED521_DOMAIN, "Kleopatra and KMail validate them through GnuPG.")
                                 : i18nd(ED521_DOMAIN, "Kleopatra and KMail check certificates with GnuPG, which cannot validate Ed521 yet."));
    if (support.chromium)
        parts << i18nd(ED521_DOMAIN, "Chromium checks certificates with its own BoringSSL, which cannot validate Ed521.");
    parts << i18nd(ED521_DOMAIN, "Certificates with RSA and ECDSA keys work in all of them.");
    return parts.join(QLatin1Char(' '));
}
}
