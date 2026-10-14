// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "wallet.h"
#include "core/core.h"
#include <KLocalizedString>
#include <KWallet>
#include <QCryptographicHash>
#include <QFileInfo>

namespace SparkyCA
{
static QString walletKey(const QString &kind, const QString &path)
{
    return kind + ':' + QString::fromLatin1(QCryptographicHash::hash(QFileInfo(path).absoluteFilePath().toUtf8(), QCryptographicHash::Sha256).toHex());
}
static std::unique_ptr<KWallet::Wallet> openWallet(bool create)
{
    std::unique_ptr<KWallet::Wallet> wallet(KWallet::Wallet::openWallet(KWallet::Wallet::LocalWallet(), 0));
    if (!wallet)
        fail(i18n("Cannot open KDE Wallet. Passwords were not saved."));
    const auto folder = QStringLiteral("Sparky CA");
    if (!wallet->hasFolder(folder) && create && !wallet->createFolder(folder))
        fail(i18n("Cannot create the certificate wallet folder."));
    if (!wallet->hasFolder(folder))
        return {};
    if (!wallet->setFolder(folder))
        fail(i18n("Cannot select the certificate wallet folder."));
    return wallet;
}
void rememberPasswords(const QString &identity, const QString &database, const QString &password, const QString &databasePassword)
{
    auto wallet = openWallet(true);
    if (wallet->writePassword(walletKey("pkcs12", identity), password) || wallet->writePassword(walletKey("nss", database), databasePassword)) {
        fail(i18n("Cannot save certificate passwords in KDE Wallet."));
    }
}
QVariantMap rememberedPasswords(const QString &identity, const QString &database)
{
    auto wallet = openWallet(false);
    QVariantMap result;
    if (!wallet)
        return result;
    for (const auto &pair :
         {std::pair{QStringLiteral("password"), walletKey("pkcs12", identity)}, std::pair{QStringLiteral("databasePassword"), walletKey("nss", database)}}) {
        if (!wallet->hasEntry(pair.second))
            continue;
        QString secret;
        if (wallet->readPassword(pair.second, secret))
            fail(i18n("Cannot read certificate passwords from KDE Wallet."));
        result.insert(pair.first, secret);
    }
    return result;
}
void forgetPasswords(const QString &identity, const QString &database)
{
    auto wallet = openWallet(false);
    if (!wallet)
        return;
    for (const auto &key : {walletKey("pkcs12", identity), walletKey("nss", database)}) {
        if (wallet->hasEntry(key) && wallet->removeEntry(key))
            fail(i18n("Cannot remove a saved certificate password."));
    }
}
}
