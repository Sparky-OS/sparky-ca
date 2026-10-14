// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "manager.h"
#include <KLocalizedString>
#include <KPluginMetaData>
#include <KQuickConfigModule>
#include <KQuickConfigModuleLoader>
#include <KSslCertificateManager>
#include <QApplication>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QFileInfo>
#include <QJSValue>
#include <QQuickItem>
#include <QQuickWindow>
#include <QTest>
#include <QTextStream>

class Notifications : public QObject
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.freedesktop.Notifications")
public:
    int count = 0;
    QString title, body;
public Q_SLOTS:
    QStringList GetCapabilities()
    {
        return {"body"};
    }
    QString GetServerInformation(QString &vendor, QString &version, QString &specVersion)
    {
        vendor = "Fixture";
        version = "1";
        specVersion = "1.2";
        return "Fixture notification receiver";
    }
    uint Notify(const QString &, uint, const QString &, const QString &summary, const QString &text, const QStringList &, const QVariantMap &, int)
    {
        title = summary;
        body = text;
        return ++count;
    }
    void CloseNotification(uint)
    {
    }
};
static int checkCount = 0;
static void require(bool condition, const QString &message)
{
    if (!condition)
        SparkyCA::fail(message);
    ++checkCount;
    QTextStream(stdout) << "PASS " << message << '\n';
}
int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    if (argc != 3 && argc != 4)
        return 2;
    app.setApplicationName("sparky-ca-desktop-check");
    KLocalizedString::setApplicationDomain("sparky-ca");
    Notifications receiver;
    auto connection = QDBusConnection::sessionBus();
    if (!connection.registerService("org.freedesktop.Notifications")
        || !connection.registerObject("/org/freedesktop/Notifications", &receiver, QDBusConnection::ExportAllSlots))
        return 1;
    try {
        CertificateManager manager(QString::fromLocal8Bit(argv[1]));
        require(manager.error().isEmpty() && manager.certificates().size() == 331, "application backend loads all 331 catalogue entries");
        manager.expiryNotification();
        require(QTest::qWaitFor(
                    [&] {
                        return receiver.count > 0;
                    },
                    5000)
                    && receiver.title == "Certificates" && receiver.body == manager.notice(),
                "KNotifications delivers the measured expiry message over D-Bus");
        manager.selectStore("kde");
        require(manager.error().isEmpty() && !manager.certificates().isEmpty(), "application lists KIO's system CA certificates");
        auto kde = KSslCertificateManager::self();
        const auto expected = qEnvironmentVariable("SPARKY_CA_EXPECTED_ROOT");
        if (!expected.isEmpty()) {
            bool found = false;
            for (const auto &cert : kde->allCaCertificates())
                if (SparkyCA::Certificate(cert.toDer()).fingerprint() == expected)
                    found = true;
            require(found, "the generated system-store install appears in KIO's CA list");
        }
        const auto certificate = kde->allCaCertificates().first();
        const auto fingerprint = SparkyCA::Certificate(certificate.toDer()).fingerprint();
        manager.setKdeEnabled(fingerprint, false);
        require(manager.error().isEmpty() && !kde->caCertificates().contains(certificate), "application disables a known KDE CA");
        manager.setKdeEnabled(fingerprint, true);
        require(manager.error().isEmpty() && kde->caCertificates().contains(certificate), "application restores a known KDE CA");
        manager.hostRule(fingerprint, "fixture.invalid", true, false);
        require(manager.error().isEmpty() && kde->rule(certificate, "fixture.invalid").isRejected(), "actual kssld saves and returns a rejecting host rule");
        manager.hostRule(fingerprint, "https://fixture.invalid", true, false);
        require(!manager.error().isEmpty(), "a URL cannot be mistaken for a host rule");
        manager.hostRule(fingerprint, "fixture.invalid", false, true);
        require(manager.error().isEmpty() && !kde->rule(certificate, "fixture.invalid").expiryDateTime().isValid(), "actual kssld removes the host rule");
        const auto module = KQuickConfigModuleLoader::loadModule(KPluginMetaData(QFileInfo(QString::fromLocal8Bit(argv[2])).absoluteFilePath()));
        require(module.plugin != nullptr, "System Settings loads the Certificates plugin");
        auto item = module.plugin->mainUi();
        require(item != nullptr, "System Settings loads the compiled Certificates QML");
        const auto backend = module.plugin->property("manager").value<CertificateManager *>();
        require(backend && backend->certificates().size() == 331 && backend->error().isEmpty(), "the KCM shares the complete certificate backend");
        const auto binding = item->property("manager");
        auto bound = binding.value<QObject *>();
        if (binding.metaType() == QMetaType::fromType<QJSValue>())
            bound = binding.value<QJSValue>().toQObject();
        if (bound != backend)
            QTextStream(stderr) << "QML root=" << item->metaObject()->className() << " binding=" << binding.metaType().name() << '\n';
        require(bound == backend, "the rendered KCM binds to its live certificate backend");
        if (argc == 4) {
            QQuickWindow window;
            window.setTitle("Certificates — System Settings");
            window.resize(1100, 840);
            item->setParentItem(window.contentItem());
            item->setSize(window.size());
            window.show();
            QTest::qWait(3000);
            auto footer = item->findChild<QQuickItem *>("tokenActions");
            const auto position = footer ? footer->mapToScene(QPointF()) : QPointF(-1, -1);
            QTextStream(stdout) << "KCM root height=" << item->height() << " footer y=" << position.y() << " height=" << (footer ? footer->height() : 0)
                                << " window=" << window.height() << '\n';
            require(footer && position.y() >= 0 && position.y() + footer->height() <= window.height(), "KCM token actions remain inside the rendered window");
            require(window.grabWindow().save(QString::fromLocal8Bit(argv[3])), "KCM render is captured for inspection");
            item->setParentItem(nullptr);
        }
        delete module.plugin;
        QTextStream(stdout) << checkCount << " desktop/KIO/kssld/KCM/notification checks passed\n";
        return 0;
    } catch (const std::exception &error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
#include "desktop-check.moc"
