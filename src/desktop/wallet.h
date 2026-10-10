// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QString>
#include <QVariantMap>
namespace SparkyCA
{
void rememberPasswords(const QString &identity, const QString &database, const QString &password, const QString &databasePassword);
QVariantMap rememberedPasswords(const QString &identity, const QString &database);
void forgetPasswords(const QString &identity, const QString &database);
}
