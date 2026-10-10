// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core.h"
#include <KLocalizedString>

namespace SparkyCA
{
void applySystemChange(const QVariantMap &arguments, const QString &data, const QString &directory, const QString &bundle)
{
    if (arguments.size() != 3 || arguments.value("operation").metaType() != QMetaType::fromType<QString>()
        || arguments.value("group").metaType() != QMetaType::fromType<QString>()
        || arguments.value("allowE521").metaType() != QMetaType::fromType<bool>()) {
        fail(i18n("Invalid system certificate request."));
    }
    const auto operation = arguments.value("operation").toString();
    const auto group = arguments.value("group").toString();
    if (operation != "install" && operation != "remove") fail(i18n("Unknown system certificate operation."));
    Catalogue catalogue(data + "/pins.json", data + "/roots");
    catalogue.load(readFile(data + "/catalogue.json"));
    if (!catalogue.groups().contains(group) && !(operation == "remove" && group == "all")) fail(i18n("Unknown certificate group: %1", group));
    Store store(directory, bundle, {});
    if (operation == "install") store.install(catalogue, group, arguments.value("allowE521").toBool());
    else store.remove(catalogue, group);
}
}
