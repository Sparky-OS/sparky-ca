// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include <KLocalizedString>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QProcess>
#include <QTextStream>
#include <QUrl>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    KLocalizedString::setApplicationDomain("sparky-ca");
    auto arguments = app.arguments().mid(1);
    const bool tty = arguments.removeAll("--tty") > 0;
    bool gui = arguments.removeAll("--gui") > 0 && !tty;
    const bool display = !qEnvironmentVariableIsEmpty("DISPLAY") || !qEnvironmentVariableIsEmpty("WAYLAND_DISPLAY");
    if (arguments.isEmpty() && !tty && display)
        gui = true;
    if (arguments.size() == 1 && !arguments.first().startsWith('-')) {
        const auto url = QUrl::fromUserInput(arguments.first(), QDir::currentPath(), QUrl::AssumeLocalFile);
        const auto suffix = QFileInfo(url.toLocalFile()).suffix().toLower();
        if (QStringList{"crt", "cer", "pem", "p7b", "pfx", "p12"}.contains(suffix)) {
            if (!tty && display)
                gui = true;
            if (!gui) {
                arguments[0] = url.toLocalFile();
                arguments.prepend("preview");
            }
        }
    }
    const auto name = gui ? QStringLiteral("sparky-ca-gui") : QStringLiteral("sparky-ca-cli");
    QString program = app.applicationDirPath() + "/" + name;
    if (!QFileInfo::exists(program))
        program = QStringLiteral(SPARKY_CA_LIBEXEC) + "/" + name;
    if (!QFileInfo::exists(program)) {
        QTextStream(stderr) << i18n("Cannot find Sparky CA front end.") << '\n';
        return 1;
    }
    QProcess process;
    process.setProcessChannelMode(QProcess::ForwardedChannels);
    process.setInputChannelMode(QProcess::ForwardedInputChannel);
    process.start(program, arguments);
    if (!process.waitForStarted() || !process.waitForFinished(-1) || process.exitStatus() != QProcess::NormalExit)
        return 1;
    return process.exitCode();
}
