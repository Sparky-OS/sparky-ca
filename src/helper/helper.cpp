// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/core.h"
#include <KAuth/ActionReply>
#include <KAuth/HelperSupport>
#include <KLocalizedString>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <sys/stat.h>
#include <unistd.h>

class CertificateHelper : public QObject
{
    Q_OBJECT
public:
    CertificateHelper()
    {
        KLocalizedString::setApplicationDomain("sparky-ca");
        qputenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        for (const auto name : {"OPENSSL_CONF", "OPENSSL_MODULES", "SSL_CERT_FILE", "SSL_CERT_DIR"})
            qunsetenv(name);
    }
public Q_SLOTS:
    KAuth::ActionReply automatic(const QVariantMap &arguments)
    {
        try {
            if (geteuid() != 0)
                SparkyCA::fail(i18n("The certificate helper requires root."));
            SparkyCA::applyAutomaticSwitch(arguments, "/etc/sparky-ca");
            return KAuth::ActionReply::SuccessReply();
        } catch (const std::exception &error) {
            auto reply = KAuth::ActionReply::HelperErrorReply();
            reply.setErrorDescription(QString::fromUtf8(error.what()));
            return reply;
        }
    }
    KAuth::ActionReply change(const QVariantMap &arguments)
    {
        try {
            if (geteuid() != 0)
                SparkyCA::fail(i18n("The certificate helper requires root."));
            const auto data = QStringLiteral(SPARKY_CA_DATA);
            QStringList paths{data, data + "/pins.json", data + "/catalogue.json", data + "/roots"};
            const QDir roots(data + "/roots");
            for (const auto &file : roots.entryList(QDir::Files | QDir::System))
                paths.append(roots.filePath(file));
            for (const auto &path : paths) {
                SparkyCA::validateStorePath(path);
                struct stat info{};
                if (stat(QFile::encodeName(path).constData(), &info) != 0 || info.st_uid != 0 || (info.st_mode & 0022)) {
                    SparkyCA::fail(i18n("Untrusted package certificate data."));
                }
            }
            SparkyCA::applySystemChange(arguments, data, "/usr/local/share/ca-certificates/sparky-ca", "/etc/ssl/certs/ca-certificates.crt", "/var/lib/sparky-ca");
            return KAuth::ActionReply::SuccessReply();
        } catch (const std::exception &error) {
            auto reply = KAuth::ActionReply::HelperErrorReply();
            reply.setErrorDescription(QString::fromUtf8(error.what()));
            return reply;
        }
    }
};
#ifdef SPARKY_CA_HELPER_CHECK
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (geteuid() == 0)
        return 2;
    CertificateHelper helper;
    const auto result = helper.change({{"operation", QStringLiteral("install")}, {"group", QStringLiteral("icp-roots")}, {"allowE521", false}});
    if (!result.failed() || result.errorDescription() != i18n("The certificate helper requires root."))
        return 1;
    QTextStream(stdout) << "PASS the actual KAuth helper refuses a valid request from an unprivileged process\n";
    const auto automatic = helper.automatic({{"enabled", false}});
    if (!automatic.failed() || automatic.errorDescription() != i18n("The certificate helper requires root.") || QFileInfo::exists("/etc/sparky-ca/auto-update.disabled"))
        return 1;
    QTextStream(stdout) << "PASS the actual KAuth helper refuses the automatic update switch from an unprivileged process\n";
    return 0;
}
#else
KAUTH_HELPER_MAIN("org.sparkylinux.sparkyca", CertificateHelper)
#endif
#include "helper.moc"
