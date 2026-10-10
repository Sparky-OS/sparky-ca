// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/core.h"
#include <QCoreApplication>
#include <QDir>
#include <QJsonDocument>
#include <QTextStream>

using namespace SparkyCA;
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 3) return 2;
    const QString data = argv[1], fixture = argv[2];
    const auto directory = fixture + "/system";
    const auto bundle = fixture + "/derived/ca-certificates.crt";
    const QVariantMap good{{"operation", QStringLiteral("install")}, {"group", QStringLiteral("icp-roots")}, {"allowE521", false}};
    int checks = 0;
    try {
        for (const auto &bad : QList<QVariantMap>{
                 {{"operation", "install"}, {"group", "icp-roots"}},
                 {{"operation", "install"}, {"group", "icp-roots"}, {"allowE521", "false"}},
                 {{"operation", "install"}, {"group", "icp-roots"}, {"allowE521", false}, {"directory", "/arbitrary"}},
                 {{"operation", "execute"}, {"group", "icp-roots"}, {"allowE521", false}},
                 {{"operation", "install"}, {"group", "../icp-roots"}, {"allowE521", false}}}) {
            bool rejected = false;
            try { applySystemChange(bad, data, directory, bundle); }
            catch (const std::exception &) { rejected = true; }
            if (!rejected || QFileInfo::exists(directory)) return 1;
            ++checks;
        }
        applySystemChange(good, data, directory, bundle);
        Catalogue catalogue(data + "/pins.json", data + "/roots");
        catalogue.load(readFile(data + "/catalogue.json"));
        Store store(directory, bundle, {});
        if (store.list(catalogue).size() != 1) return 1;
        ++checks;
        applySystemChange({{"operation", QStringLiteral("remove")}, {"group", QStringLiteral("all")}, {"allowE521", false}}, data, directory, bundle);
        if (!store.list(catalogue).isEmpty()) return 1;
        ++checks;
        QTextStream(stdout) << checks << " system request checks passed: five malformed requests rejected before store creation; validated install/remove reach the real isolated updater\n";
        return 0;
    } catch (const std::exception &error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
