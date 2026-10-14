// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/core.h"
#include <KLocalizedString>
#include <KNotification>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDir>
#include <QJsonDocument>
#include <QTimer>

using namespace SparkyCA;
// Tells the desktop about the automatic updates it has not reported yet.
// The system service runs as root and cannot reach the user's session, so this runs in the session.
static QStringList noteworthy(const QJsonObject &report)
{
    QStringList lines;
    for (const auto &line : journalLines(report).split('\n')) {
        if (line.section(' ', 0, 0).toInt() <= 5) lines.append(line.section(' ', 1));
    }
    return lines;
}
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    app.setApplicationName("sparky-ca");
    KLocalizedString::setApplicationDomain("sparky-ca");
    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addOptions({{"state", i18n("Machine state folder."), "directory", SPARKY_CA_STATE},
                       {"home", i18n("Home folder holding the user's status."), "directory", QDir::homePath()}});
    parser.process(app);
    const QString userState = parser.value("home") + "/.local/state/sparky-ca";
    const QString seenPath = userState + "/notified.json";
    QJsonObject seen;
    if (trustedStateFile(seenPath)) seen = QJsonDocument::fromJson(readFile(seenPath)).object();
    QStringList paragraphs;
    for (const QString scope : {"system", "user"}) {
        const QString path = scope == "system" ? parser.value("state") + "/status.json" : userState + "/status.json";
        if (!trustedStateFile(path)) continue;
        const auto report = QJsonDocument::fromJson(readFile(path)).object();
        const QString id = report.value("runId").toString();
        if (id.isEmpty() || id == seen.value(scope).toString()) continue;
        seen.insert(scope, id);
        const auto lines = noteworthy(report);
        if (!lines.isEmpty()) paragraphs.append(lines.join('\n'));
    }
    if (paragraphs.isEmpty()) return 0;
    auto notification = new KNotification("AutomaticUpdate", KNotification::CloseOnTimeout);
    notification->setComponentName("sparky-ca");
    notification->setTitle(i18n("Certificates"));
    notification->setText(paragraphs.join('\n'));
    notification->setIconName("security-high");
    notification->sendEvent();
    // The notification service takes the message over D-Bus; give the call time to leave.
    QTimer::singleShot(1500, &app, &QCoreApplication::quit);
    app.exec();
    try {
        QDir().mkpath(userState);
        writeFile(seenPath, QJsonDocument(seen).toJson());
    } catch (const std::exception &) {
        return 1;
    }
    return 0;
}
