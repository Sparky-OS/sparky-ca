// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "wallet.h"
#include <KLocalizedString>
#include <QApplication>
#include <QTextStream>
int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    app.setApplicationName("sparky-ca-wallet-check");
    KLocalizedString::setApplicationDomain("sparky-ca");
    try {
        const QString identity = "/generated/identity.p12", database = "/generated/nss";
        if (!SparkyCA::rememberedPasswords(identity, database).isEmpty())
            return 1;
        SparkyCA::rememberPasswords(identity, database, " Generated A1 password ", " Generated NSS password ");
        const auto passwords = SparkyCA::rememberedPasswords(identity, database);
        if (passwords.value("password") != " Generated A1 password " || passwords.value("databasePassword") != " Generated NSS password ")
            return 1;
        if (!SparkyCA::rememberedPasswords("/different/identity.p12", database).value("password").toString().isEmpty())
            return 1;
        SparkyCA::forgetPasswords(identity, database);
        if (!SparkyCA::rememberedPasswords(identity, database).isEmpty())
            return 1;
        QTextStream(stdout)
            << "4 KWallet checks passed: no saved values before opt-in; exact A1 and NSS password round trip; identity separation; explicit removal\n";
        return 0;
    } catch (const std::exception &error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
