// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "manager.h"
#include "wallet.h"
#include <KAuth/Action>
#include <KAuth/ExecuteJob>
#include <KLocalizedString>
#include <KNotification>
#include <QDir>
#include <QFutureWatcher>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QProcess>
#include <QSettings>
#include <QStandardPaths>
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
    probeEd521();
}
static QString userConfiguration()
{
    return QDir::homePath() + "/.config/sparky-ca";
}
static QString desktopSettings()
{
    return userConfiguration() + "/desktop.conf";
}
void CertificateManager::probeEd521()
{
    // Each probe tries ITI's v7 root in a throwaway store; the external tools take a moment, so off the GUI thread.
    const QString v7 = m_data + "/roots/ICP-Brasilv7.crt";
    auto *watcher = new QFutureWatcher<Ed521Support>(this);
    connect(watcher, &QFutureWatcher<Ed521Support>::finished, this, [this, watcher] {
        m_ed521 = watcher->result();
        m_ed521Probed = true;
        m_ed521Message = SparkyCA::ed521Message(m_ed521);
        watcher->deleteLater();
        Q_EMIT ed521Changed();
    });
    watcher->setFuture(QtConcurrent::run([v7] {
        return SparkyCA::probeEd521(v7);
    }));
}
bool CertificateManager::ed521Dismissed() const
{
    // Closing the message hides it until what works where changes.
    return m_ed521Probed && QSettings(desktopSettings(), QSettings::IniFormat).value("ed521/dismissed").toString() == ed521State(m_ed521);
}
void CertificateManager::dismissEd521()
{
    if (!m_ed521Probed)
        return;
    QDir().mkpath(userConfiguration());
    QSettings settings(desktopSettings(), QSettings::IniFormat);
    settings.setValue("ed521/dismissed", ed521State(m_ed521));
    settings.sync();
    Q_EMIT ed521Changed();
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
    if (store != "catalogue" && store != "system" && store != "gpgsm" && !profiles().contains(store)) {
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
        } else if (m_store == "gpgsm") {
            for (const auto &item : gpgsmStatus(gpgHome())) {
                const auto record = item.toObject();
                m_certificates.append(QVariantMap{{"name", record.value("name").toString()}, {"issuer", record.value("sha1").toString()}, {"sha256", record.value("sha256").toString()},
                                                  {"expires", QString()}, {"state", record.value("trust").toString()}, {"root", record.value("root").toBool()}});
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
    } else if (m_store != "gpgsm") {
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
QString CertificateManager::gpgHome() const
{
    return QDir::homePath() + "/.gnupg";
}
bool CertificateManager::gpgAvailable() const
{
    return gpgsmAvailable();
}
bool CertificateManager::kleopatraAvailable() const
{
    return gpgsmAvailable() && !QStandardPaths::findExecutable("kleopatra").isEmpty();
}
void CertificateManager::gpgImport(const QString &group)
{
    if (!m_catalogue)
        return;
    const auto catalogue = m_catalogue;
    const auto home = gpgHome();
    task([catalogue, group, home] {
        const auto result = gpgsmImport(*catalogue, group, home);
        return i18n("Certificates imported for Kleopatra. They are not trusted until you confirm each root in Kleopatra or in gpgsm. Ed521 entries stay listed but are not imported because gpgsm cannot validate them.")
            + (result.value("previousTrustRemoved").toBool() ? " " + i18n("Trust entries that version 2.0.0 added to gpgsm without asking were removed.") : QString());
    });
}
void CertificateManager::gpgRemove(const QString &group)
{
    const auto home = gpgHome();
    task([group, home] {
        gpgsmRemove(group, home);
        return i18n("Certificates that Sparky CA imported into gpgsm were removed. Trust you confirmed yourself stays in gpgsm's trust list until you remove it in Kleopatra.");
    });
}
void CertificateManager::gpgConfirm()
{
    const auto home = gpgHome();
    task([home] {
        const auto roots = gpgsmUnconfirmedRoots(home);
        if (roots.isEmpty())
            return i18n("No imported root is waiting for your confirmation.");
        for (const auto &fingerprint : roots) {
            // gpgsm asks the question itself, through the user's own pinentry.
            QProcess process;
            process.start("gpgsm", {"--homedir", home, "--with-validation", "--list-keys", fingerprint});
            if (!process.waitForFinished(-1) || process.exitCode() != 0)
                fail(i18n("gpgsm could not check the root."));
        }
        return i18n("gpgsm asked about each imported root. Your answers are in its trust list.");
    });
}
void CertificateManager::openKleopatra(const QString &fingerprint)
{
    if (!kleopatraAvailable() || !QRegularExpression("^[0-9A-F]{40}$").match(fingerprint).hasMatch()) {
        m_error = i18n("Kleopatra is not installed.");
        Q_EMIT changed();
        return;
    }
    QProcess::startDetached("kleopatra", {"--query", fingerprint});
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
