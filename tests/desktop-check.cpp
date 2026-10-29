// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "manager.h"
#include <KLocalizedString>
#include <KPluginMetaData>
#include <KQuickConfigModule>
#include <KQuickConfigModuleLoader>
#include <QApplication>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QFileInfo>
#include <QJSValue>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
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
        const auto entries = QJsonDocument::fromJson(SparkyCA::readFile(QString::fromLocal8Bit(argv[1]) + "/catalogue.json")).object().value("certificates").toArray().size();
        require(manager.error().isEmpty() && manager.certificates().size() == entries, QStringLiteral("application backend loads all %1 catalogue entries").arg(entries));
        manager.expiryNotification();
        require(QTest::qWaitFor(
                    [&] {
                        return receiver.count > 0;
                    },
                    5000)
                    && receiver.title == "Certificates" && receiver.body == manager.notice(),
                "KNotifications delivers the measured expiry message over D-Bus");
        const auto fakeLog = qEnvironmentVariable("SPARKY_CA_FAKE_KLEOPATRA_LOG");
        if (!fakeLog.isEmpty()) {
            require(manager.gpgAvailable() && manager.kleopatraAvailable(), "the application offers Kleopatra only where gpgsm and Kleopatra exist");
            const QString fingerprint(40, 'A');
            manager.openKleopatra(fingerprint);
            require(QTest::qWaitFor(
                        [&] {
                            return QFileInfo::exists(fakeLog) && SparkyCA::readFile(fakeLog).contains(("--query " + fingerprint).toUtf8());
                        },
                        5000),
                    "Open in Kleopatra starts it on exactly that certificate");
            manager.openKleopatra("not a fingerprint; rm -rf");
            require(!manager.error().isEmpty(), "anything that is not a fingerprint is refused");
        }
        const auto module = KQuickConfigModuleLoader::loadModule(KPluginMetaData(QFileInfo(QString::fromLocal8Bit(argv[2])).absoluteFilePath()));
        require(module.plugin != nullptr, "System Settings loads the Certificates plugin");
        auto item = module.plugin->mainUi();
        require(item != nullptr, "System Settings loads the compiled Certificates QML");
        const auto backend = module.plugin->property("manager").value<CertificateManager *>();
        require(backend && backend->certificates().size() == entries && backend->error().isEmpty(), "the KCM shares the complete certificate backend");
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
        QTextStream(stdout) << checkCount << " desktop/KCM/notification checks passed\n";
        return 0;
    } catch (const std::exception &error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
#include "desktop-check.moc"
