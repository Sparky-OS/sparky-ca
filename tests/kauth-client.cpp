// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
// Calls the installed helper through the system bus and polkit, as the application does.
// usage: kauth-client change <install|remove> <group> | automatic <on|off>
#include <KAuth/Action>
#include <KAuth/ExecuteJob>
#include <QCoreApplication>
#include <QTextStream>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const auto arguments = app.arguments();
    if (arguments.size() < 3)
        return 2;
    KAuth::Action action(QStringLiteral("org.sparkylinux.sparkyca.") + arguments.at(1));
    action.setHelperId("org.sparkylinux.sparkyca");
    if (arguments.at(1) == "change" && arguments.size() == 4)
        action.setArguments({{"operation", arguments.at(2)}, {"group", arguments.at(3)}, {"allowE521", false}});
    else if (arguments.at(1) == "automatic")
        action.setArguments({{"enabled", arguments.at(2) == "on"}});
    else
        return 2;
    auto job = action.execute();
    const bool ok = job->exec();
    QTextStream(stdout) << (ok ? "OK" : "FAILED: " + job->errorString()) << '\n';
    return ok ? 0 : 1;
}
