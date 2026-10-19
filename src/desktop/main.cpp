// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "manager.h"
#include <KAboutData>
#include <KLocalizedQmlContext>
#include <KLocalizedString>
#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickItem>
#include <QQuickWindow>
#include <QTextStream>
#include <QTimer>

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    KLocalizedString::setApplicationDomain("sparky-ca");
    KAboutData about("sparky-ca",
                     i18n("Certificates"),
                     "2.0.2",
                     i18n("Manage certificate trust and personal identities"),
                     KAboutLicense::GPL_V3,
                     i18n("© 2018 Paweł Pijanowski; © 2020, 2026 Daniel Campos Ramos"));
    about.addAuthor(i18n("Paweł \"pavroo\" Pijanowski"), i18n("Original author, 2018"));
    about.addAuthor(i18n("Daniel Campos Ramos"), i18n("Brazilian certificates and KDE integration, 2020 and 2026"));
    KAboutData::setApplicationData(about);
    app.setDesktopFileName("sparky-ca");
    QCommandLineParser parser;
    about.setupCommandLine(&parser);
    parser.addOption({"data", i18n("Catalogue data directory."), "directory", SPARKY_CA_DATA});
    parser.addOption({"test-screenshot", i18n("Capture the window for an isolated UI test."), "file"});
    parser.addPositionalArgument("file", i18n("Local certificate file to preview."));
    parser.process(app);
    CertificateManager manager(parser.value("data"));
    QQmlApplicationEngine engine;
    auto context = new KLocalizedQmlContext(&engine);
    context->setTranslationDomain(QStringLiteral("sparky-ca"));
    engine.rootContext()->setContextObject(context);
    engine.rootContext()->setContextProperty("certificateManager", &manager);
    const auto files = parser.positionalArguments();
    engine.rootContext()->setContextProperty("initialCertificateFile",
                                             files.isEmpty() ? QUrl() : QUrl::fromUserInput(files.first(), QDir::currentPath(), QUrl::AssumeLocalFile));
    engine.load(QUrl("qrc:/qml/Main.qml"));
    if (engine.rootObjects().isEmpty())
        return 1;
    auto window = qobject_cast<QQuickWindow *>(engine.rootObjects().first());
    manager.setWindow(window);
    if (parser.isSet("test-screenshot")) {
        QTimer::singleShot(4000, &app, [&] {
            auto footer = window ? window->findChild<QQuickItem *>("tokenActions") : nullptr;
            if (!footer) {
                app.exit(1);
                return;
            }
            const auto position = footer->mapToScene(QPointF());
            QTextStream(stdout) << "UI footer y=" << position.y() << " height=" << footer->height() << " window=" << window->height() << '\n';
            if (position.y() < 0 || position.y() + footer->height() > window->height()) {
                app.exit(1);
                return;
            }
            const bool saved = window && window->grabWindow().save(parser.value("test-screenshot"));
            app.exit(saved ? 0 : 1);
        });
    }
    return app.exec();
}
