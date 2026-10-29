// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
// ed521-kcm-check message OPENSSL PROVIDER NSS GNUPG CHROMIUM   print the message for these states (1, 0, or - for absent)
// ed521-kcm-check kcm DATA PLUGIN PREFIX [close]                 load the Certificates KCM, print its Ed521 state as JSON,
//                                                               save PREFIX.png, and with "close" press the close action and save PREFIX-closed.png
#include "manager.h"
#include <KLocalizedString>
#include <KPluginMetaData>
#include <KQuickConfigModule>
#include <KQuickConfigModuleLoader>
#include <QApplication>
#include <QIcon>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QQuickItem>
#include <QQuickWindow>
#include <QTest>
#include <QTextStream>

static std::optional<bool> state(const char *value)
{
    if (QByteArray(value) == "-")
        return std::nullopt;
    return QByteArray(value) == "1";
}

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    app.setApplicationName("sparky-ca-ed521-check");
    KLocalizedString::setApplicationDomain("sparky-ca");
    // Outside Plasma no platform theme names the icon theme; screenshots name it here.
    if (qEnvironmentVariableIsSet("ED521_ICON_THEME"))
        QIcon::setThemeName(qEnvironmentVariable("ED521_ICON_THEME"));
    const QByteArray mode = argc > 1 ? argv[1] : "";
    if (mode == "message" && argc == 7) {
        SparkyCA::Ed521Support support;
        support.openssl = QByteArray(argv[2]) == "1";
        support.providerInstalled = QByteArray(argv[3]) == "1";
        support.nss = state(argv[4]);
        support.gnupg = state(argv[5]);
        support.chromium = QByteArray(argv[6]) == "1";
        QTextStream(stdout) << QJsonDocument(QJsonObject{{"complete", SparkyCA::ed521Complete(support)},
                                                         {"state", SparkyCA::ed521State(support)},
                                                         {"message", SparkyCA::ed521Message(support)}}).toJson(QJsonDocument::Compact)
                            << '\n';
        return 0;
    }
    if (mode != "kcm" || (argc != 5 && argc != 6))
        return 2;
    const auto module = KQuickConfigModuleLoader::loadModule(KPluginMetaData(QFileInfo(QString::fromLocal8Bit(argv[3])).absoluteFilePath()));
    if (!module.plugin)
        return 3;
    auto item = module.plugin->mainUi();
    const auto backend = module.plugin->property("manager").value<CertificateManager *>();
    if (!item || !backend)
        return 4;
    QQuickWindow window;
    window.setTitle("Certificates — System Settings");
    window.resize(1100, 840);
    item->setParentItem(window.contentItem());
    item->setSize(window.size());
    window.show();
    if (!QTest::qWaitFor([&] { return backend->ed521Probed(); }, 30000))
        return 5;
    QTest::qWait(1500);
    auto message = item->findChild<QQuickItem *>("ed521Message");
    QJsonObject report{{"message", backend->ed521Message()},
                       {"warning", backend->ed521Warning()},
                       {"dismissed", backend->ed521Dismissed()},
                       {"itemFound", message != nullptr},
                       {"itemVisible", message && message->isVisible()},
                       {"itemText", message ? message->property("text").toString() : QString()}};
    window.grabWindow().save(QString::fromLocal8Bit(argv[4]) + ".png");
    if (argc == 6 && QByteArray(argv[5]) == "close") {
        // Kirigami's own close button inside the message: a ToolButton labelled Close.
        QQuickItem *close = nullptr;
        if (message) {
            for (auto child : message->findChildren<QQuickItem *>()) {
                if (QByteArray(child->metaObject()->className()).contains("ToolButton") && child->property("text").toString() == QStringLiteral("Close")
                    && child->isVisible())
                    close = child;
            }
        }
        report.insert("closeFound", close != nullptr);
        if (close)
            QMetaObject::invokeMethod(close, "clicked");
        QTest::qWait(1500);
        report.insert("dismissedAfterClose", backend->ed521Dismissed());
        report.insert("itemVisibleAfterClose", message && message->isVisible());
        window.grabWindow().save(QString::fromLocal8Bit(argv[4]) + "-closed.png");
    }
    item->setParentItem(nullptr);
    QTextStream(stdout) << QJsonDocument(report).toJson(QJsonDocument::Compact) << '\n';
    delete module.plugin;
    return 0;
}
