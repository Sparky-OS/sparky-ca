// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "manager.h"
#include "wallet.h"
#include <KAuth/Action>
#include <KAuth/ExecuteJob>
#include <KLocalizedString>
#include <KNotification>
#include <KSslCertificateManager>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusReply>
#include <QDir>
#include <QFutureWatcher>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSslCertificate>
#include <QtConcurrent>

using namespace SparkyCA;
CertificateManager::CertificateManager(QString data, QObject *parent)
    : QObject(parent)
    , m_data(std::move(data))
{
    try {
        m_catalogue = std::make_shared<Catalogue>(loadCatalogue(m_data, SPARKY_CA_STATE));
        refresh();
    } catch (const std::exception &error) {
        m_error = QString::fromUtf8(error.what());
    }
}
static QString userConfiguration()
{
    return QDir::homePath() + "/.config/sparky-ca";
}
bool CertificateManager::automaticUpdates() const
{
    return automationEnabled("/etc/sparky-ca") && automationEnabled(userConfiguration());
}
QString CertificateManager::updateStatus() const
{
    const QString path = QStringLiteral(SPARKY_CA_STATE) + "/status.json";
    if (!trustedStateFile(path))
        return i18n("No automatic update has run on this computer yet.");
    const auto report = QJsonDocument::fromJson(readFile(path)).object();
    const auto time = QDateTime::fromString(report.value("time").toString(), Qt::ISODate).toLocalTime();
    const auto outcome = report.value("outcome").toString();
    return outcome == "ok"
        ? i18n("Last automatic update: %1. Everything is current.", QLocale().toString(time, QLocale::ShortFormat))
        : i18n("Last automatic update: %1. It needs your attention: see the system journal or run sparky-ca auto status.", QLocale().toString(time, QLocale::ShortFormat));
}
void CertificateManager::setAutomaticUpdates(bool enabled)
{
    if (m_busy)
        return;
    try {
        setAutomationEnabled(userConfiguration(), enabled);
    } catch (const std::exception &error) {
        m_error = QString::fromUtf8(error.what());
        Q_EMIT changed();
        return;
    }
    KAuth::Action action("org.sparkylinux.sparkyca.automatic");
    action.setHelperId("org.sparkylinux.sparkyca");
    action.setParentWindow(m_window.data());
    action.setArguments({{"enabled", enabled}});
    auto job = action.execute();
    m_busy = true;
    m_error.clear();
    Q_EMIT changed();
    connect(job, &KJob::result, this, [this, enabled](KJob *finished) {
        m_busy = false;
        m_error = finished->errorString();
        if (finished->error()) {
            try {
                setAutomationEnabled(userConfiguration(), !enabled);
            } catch (const std::exception &) {
            }
        } else {
            m_notice = enabled ? i18n("Your chosen certificate groups will be kept current automatically.") : i18n("Automatic certificate updates are off.");
            notify(m_notice);
        }
        Q_EMIT changed();
    });
    job->start();
}
QStringList CertificateManager::profiles() const
{
    return browserDatabases(QDir::homePath());
}
void CertificateManager::selectStore(const QString &store)
{
    if (m_busy)
        return;
    if (store != "catalogue" && store != "system" && store != "kde" && !profiles().contains(store)) {
        m_error = i18n("Choose an existing browser profile.");
        Q_EMIT changed();
        return;
    }
    m_store = store;
    refresh();
}
void CertificateManager::refresh()
{
    if (m_busy || !m_catalogue)
        return;
    m_certificates.clear();
    m_error.clear();
    try {
        if (m_store == "catalogue") {
            for (const auto &entry : m_catalogue->entries()) {
                auto row = describe(entry.certificate, entry.name, m_catalogue->state(entry.certificate));
                row.insert("groups", QJsonArray::fromStringList(entry.groups));
                row.insert("note", m_catalogue->verificationNote(entry.certificate));
                if (entry.certificate.signatureOid() == "1.3.101.113")
                    row.insert("note", i18n("Ed448 validates through OpenSSL. NSS cannot import this key type, so browser installations exclude it."));
                row.insert("installationIssue", m_catalogue->installationIssue(entry.certificate));
                m_certificates.append(row.toVariantMap());
            }
        } else if (m_store == "kde") {
            auto manager = KSslCertificateManager::self();
            for (const auto &certificate : manager->allCaCertificates()) {
                Certificate cert(certificate.toDer());
                auto row = describe(cert, cert.subject(), m_catalogue->state(cert)).toVariantMap();
                row.insert("enabled", manager->isCaCertificateEnabled(certificate));
                m_certificates.append(row);
            }
        } else {
            Store store(m_store == "system" ? "/usr/local/share/ca-certificates/sparky-ca" : QString(),
                        "/etc/ssl/certs/ca-certificates.crt",
                        m_store == "system" ? QString() : m_store);
            m_certificates = store.list(*m_catalogue).toVariantList();
        }
    } catch (const std::exception &error) {
        m_error = QString::fromUtf8(error.what());
    }
    Q_EMIT changed();
}
void CertificateManager::notify(const QString &text)
{
    auto notification = new KNotification("CertificateChanged", KNotification::CloseOnTimeout, this);
    notification->setComponentName("sparky-ca");
    notification->setTitle(i18n("Certificates"));
    notification->setText(text);
    notification->setIconName("security-high");
    notification->sendEvent();
}
void CertificateManager::task(std::function<QString()> operation, std::function<void()> success)
{
    if (m_busy)
        return;
    m_busy = true;
    m_error.clear();
    m_notice.clear();
    Q_EMIT changed();
    auto watcher = new QFutureWatcher<QVariantMap>(this);
    connect(watcher, &QFutureWatcher<QVariantMap>::finished, this, [this, watcher, success = std::move(success)] {
        const auto result = watcher->result();
        watcher->deleteLater();
        m_busy = false;
        refresh();
        m_error = result.value("error").toString();
        m_notice = result.value("notice").toString();
        if (m_error.isEmpty()) {
            try {
                if (success)
                    success();
            } catch (const std::exception &error) {
                m_error = QString::fromUtf8(error.what());
            }
            notify(m_notice);
        }
        Q_EMIT changed();
    });
    watcher->setFuture(QtConcurrent::run([operation = std::move(operation)] {
        try {
            return QVariantMap{{"notice", operation()}};
        } catch (const std::exception &error) {
            return QVariantMap{{"error", QString::fromUtf8(error.what())}};
        }
    }));
}
void CertificateManager::changeGroup(const QString &group, bool install, bool allowE521, const QString &password)
{
    if (m_busy || !m_catalogue)
        return;
    if (m_store == "system" || m_store == "catalogue") {
        KAuth::Action action("org.sparkylinux.sparkyca.change");
        action.setHelperId("org.sparkylinux.sparkyca");
        action.setParentWindow(m_window.data());
        action.setArguments({{"operation", install ? "install" : "remove"}, {"group", group}, {"allowE521", allowE521}});
        auto job = action.execute();
        m_busy = true;
        m_error.clear();
        Q_EMIT changed();
        connect(job, &KJob::result, this, [this](KJob *finished) {
            m_busy = false;
            refresh();
            m_error = finished->errorString();
            if (!finished->error()) {
                m_notice = i18n("System certificate store updated. Restart applications to reload trust.");
                notify(m_notice);
            }
            Q_EMIT changed();
        });
        job->start();
    } else if (m_store != "kde") {
        const auto catalogue = m_catalogue;
        const auto database = m_store;
        task([catalogue, database, group, install, allowE521, password] {
            Store store({}, {}, database, password.toUtf8());
            if (install)
                store.install(*catalogue, group, allowE521);
            else
                store.remove(*catalogue, group);
            return i18n(
                "Browser certificate store updated. Ed521 and Ed448 entries stay listed but are excluded because NSS does not support their key types.");
        });
    }
}
void CertificateManager::setKdeEnabled(const QString &fingerprint, bool enabled)
{
    auto manager = KSslCertificateManager::self();
    for (const auto &certificate : manager->allCaCertificates()) {
        if (Certificate(certificate.toDer()).fingerprint() != fingerprint)
            continue;
        const bool saved = manager->setCaCertificateEnabled(certificate, enabled);
        refresh();
        if (!saved)
            m_error = i18n("Cannot save the KDE trust decision.");
        else {
            m_notice = i18n("KDE certificate trust updated.");
            notify(m_notice);
        }
        Q_EMIT changed();
        return;
    }
    m_error = i18n("Certificate no longer exists in the KDE store.");
    Q_EMIT changed();
}
void CertificateManager::hostRule(const QString &fingerprint, const QString &host, bool reject, bool clear)
{
    if (!QRegularExpression("^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$").match(host).hasMatch() || host.contains("..")) {
        m_error = i18n("Enter a single lower-case host name, without a scheme or wildcard.");
        Q_EMIT changed();
        return;
    }
    auto bus = QDBusConnection::sessionBus().interface();
    if (!bus) {
        m_error = i18n("KDE's certificate service is unavailable.");
        Q_EMIT changed();
        return;
    }
    if (!bus->isServiceRegistered("org.kde.kssld6").value())
        bus->startService("org.kde.kssld6");
    const QDBusReply<bool> available = bus->isServiceRegistered("org.kde.kssld6");
    if (!available.isValid() || !available.value()) {
        m_error = i18n("KDE's certificate service is unavailable.");
        Q_EMIT changed();
        return;
    }
    auto manager = KSslCertificateManager::self();
    for (const auto &cert : manager->allCaCertificates()) {
        if (Certificate(cert.toDer()).fingerprint() != fingerprint)
            continue;
        m_error.clear();
        m_notice.clear();
        if (clear)
            manager->clearRule(cert, host);
        else {
            KSslCertificateRule rule(cert, host);
            rule.setRejected(reject);
            rule.setExpiryDateTime(QDateTime::currentDateTimeUtc().addDays(30));
            manager->setRule(rule);
        }
        const auto saved = manager->rule(cert, host);
        if ((!clear && (saved.isRejected() != reject || !saved.expiryDateTime().isValid())) || (clear && saved.expiryDateTime().isValid()))
            m_error = i18n("KDE's certificate service did not save the host rule.");
        else
            m_notice = i18n("Host rule updated. Certificate errors remain enforced; no TLS error was ignored.");
        Q_EMIT changed();
        return;
    }
}
void CertificateManager::preview(const QUrl &file, const QString &password)
{
    if (m_busy || !file.isLocalFile())
        return;
    try {
        m_certificates.clear();
        for (const auto &cert : previewCertificates(readFile(file.toLocalFile()), password.toUtf8())) {
            auto row = describe(cert, cert.subject(), m_catalogue ? m_catalogue->state(cert) : cert.state()).toVariantMap();
            row.insert("note", i18n("Preview does not establish trust. Revocation status is unknown."));
            m_certificates.append(row);
        }
        m_store = "preview";
        m_error.clear();
    } catch (const std::exception &error) {
        m_error = QString::fromUtf8(error.what());
    }
    Q_EMIT changed();
}
void CertificateManager::importIdentity(const QUrl &file, const QString &database, const QString &password, const QString &databasePassword, bool remember)
{
    if (!file.isLocalFile() || !profiles().contains(database)) {
        m_error = i18n("Choose a local PKCS#12 file and browser profile.");
        Q_EMIT changed();
        return;
    }
    const auto path = file.toLocalFile();
    task(
        [path, database, password, databasePassword] {
            importPersonalCertificate(path, database, password.toUtf8(), databasePassword.toUtf8());
            return i18n("Personal certificate imported. Choose this NSS directory in Okular's PDF certificate settings.");
        },
        [path, database, password, databasePassword, remember] {
            if (remember)
                SparkyCA::rememberPasswords(path, database, password, databasePassword);
        });
}
QVariantMap CertificateManager::rememberedPasswords(const QUrl &file, const QString &database)
{
    try {
        return SparkyCA::rememberedPasswords(file.toLocalFile(), database);
    } catch (const std::exception &error) {
        m_error = QString::fromUtf8(error.what());
        Q_EMIT changed();
        return {};
    }
}
void CertificateManager::forgetPasswords(const QUrl &file, const QString &database)
{
    try {
        SparkyCA::forgetPasswords(file.toLocalFile(), database);
        m_notice = i18n("Saved certificate passwords removed.");
    } catch (const std::exception &error) {
        m_error = QString::fromUtf8(error.what());
    }
    Q_EMIT changed();
}
void CertificateManager::tokens(const QString &module)
{
    task([module] {
        return QString::fromUtf8(tokenInformation(module)) + '\n'
            + i18n("A3 PINs are not saved. Token retry limits and authentication policy apply. SafeSign or SafeNet middleware, when required, is installed on "
                   "your machine through APTus.");
    });
}
void CertificateManager::registerModule(const QString &database, const QString &module, const QString &password)
{
    if (!profiles().contains(database))
        return;
    task([database, module, password] {
        registerTokenModule(database, module, password.toUtf8());
        return i18n("PKCS#11 module registered for this browser profile.");
    });
}
void CertificateManager::gpgTrust(const QString &group, bool trusted)
{
    if (!m_catalogue)
        return;
    const auto catalogue = m_catalogue;
    const auto home = QDir::homePath() + "/.gnupg";
    task([catalogue, group, home, trusted] {
        setGpgsmTrust(*catalogue, group, home, trusted);
        return i18n(
            "GnuPG S/MIME root trust updated for Kleopatra. Ed521 entries stay listed but are excluded because gpgsm cannot validate them. Browser trust is "
            "separate.");
    });
}
void CertificateManager::unregisterModule(const QString &database)
{
    if (!profiles().contains(database))
        return;
    task([database] {
        unregisterTokenModule(database);
        return i18n("Our PKCS#11 module registration was removed. Token certificates remain on the token.");
    });
}
void CertificateManager::expiryNotification()
{
    int count = 0;
    const auto deadline = QDateTime::currentDateTimeUtc().addDays(30);
    for (const auto &value : m_certificates) {
        const auto row = value.toMap();
        const auto expiry = QDateTime::fromString(row.value("expires").toString(), Qt::ISODate);
        if (expiry.isValid() && expiry <= deadline)
            ++count;
    }
    m_notice = i18np("One listed certificate expires within 30 days or has expired.", "%1 listed certificates expire within 30 days or have expired.", count);
    if (count)
        notify(m_notice);
    Q_EMIT changed();
}
