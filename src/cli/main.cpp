// SPDX-FileCopyrightText: 2018 Paweł "pavroo" Pijanowski <pavroo@onet.eu>
// SPDX-FileCopyrightText: 2020, 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/core.h"
#include <KLocalizedString>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDir>
#include <QJsonDocument>
#include <QProcess>
#include <QTextStream>
#include <unistd.h>

using namespace SparkyCA;
int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    application.setApplicationName("sparky-ca");
    application.setApplicationVersion("2.0.0");
    KLocalizedString::setApplicationDomain("sparky-ca");
    QCommandLineParser parser;
    parser.setApplicationDescription(i18n("Manage Brazilian CA certificates and browser trust."));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOptions({
        {"data", i18n("Package data directory."), "directory", SPARKY_CA_DATA},
        {"catalogue", i18n("Verified catalogue file."), "file"},
        {"system-dir", i18n("System certificate directory."), "directory", "/usr/local/share/ca-certificates/sparky-ca"},
        {"system-bundle", i18n("Derived system bundle; redirects the updater for isolated tests."), "file", "/etc/ssl/certs/ca-certificates.crt"},
        {"nss", i18n("Operate on this NSS database instead of the system store. Close its browser first."), "directory"},
        {"allow-e521", i18n("Choose E-521 certificates despite unavailable Linux chain verification; requires programs with their own E-521 code.")},
        {"tls-ca", i18n("TLS trust root for an isolated HTTPS fixture."), "file"},
        {"tls-issuer", i18n("Missing TLS issuer, verified against the TLS trust roots."), "file"},
        {"bundle-url", i18n("HTTPS bundle URL."), "url", "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip"},
        {"hash-url", i18n("HTTPS SHA-512 URL."), "url", "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt"},
        {"zip", i18n("Offline ZIP input for catalogue verification."), "file"},
        {"hash", i18n("Offline SHA-512 input."), "file"},
        {"output", i18n("Write refreshed catalogue here."), "file"}
    });
    parser.addPositionalArgument("command", i18n("list [installed], groups, install <group>, remove <group|all>, update, status, profiles, import <file>"));
    parser.process(application);
    QTextStream out(stdout), err(stderr), in(stdin);
    try {
        const QString data = parser.value("data");
        Catalogue catalogue(data + "/pins.json", data + "/roots");
        const QString path = parser.isSet("catalogue") ? parser.value("catalogue") : data + "/catalogue.json";
        auto arguments = parser.positionalArguments();
        QString command = arguments.value(0);
        if (command != "update" || QFileInfo::exists(path)) catalogue.load(readFile(path));
        Store store(parser.isSet("nss") ? QString() : parser.value("system-dir"), parser.value("system-bundle"), parser.value("nss"));
        if (command.isEmpty()) {
            if (!isatty(STDIN_FILENO)) parser.showHelp(1);
            out << i18n("1. List catalogue\n2. List installed certificates\n3. Install group\n4. Remove group\n5. Status\n0. Exit\nChoice: ") << Qt::flush;
            const QString choice = in.readLine();
            if (choice == "0" || choice.isNull()) return 0;
            command = choice == "1" ? "list" : choice == "2" ? "installed" : choice == "3" ? "install" : choice == "4" ? "remove" : choice == "5" ? "status" : "invalid";
            if (command == "install" || command == "remove") {
                out << catalogue.groups().join(", ") << '\n' << i18n("Group: ") << Qt::flush;
                arguments = {command, in.readLine()};
            }
        }
        if (command == "groups") {
            out << catalogue.groups().join('\n') << '\n';
        } else if (command == "profiles") {
            out << browserDatabases(QDir::homePath()).join('\n') << '\n';
        } else if (command == "list" && arguments.value(1) != "installed") {
            QJsonArray entries;
            for (const auto &entry : catalogue.entries()) {
                auto item = describe(entry.certificate, entry.name, catalogue.state(entry.certificate));
                item.insert("groups", QJsonArray::fromStringList(entry.groups));
                item.insert("revocation", "unknown");
                item.insert("verification", catalogue.verification(entry.certificate));
                item.insert("note", catalogue.verificationNote(entry.certificate));
                entries.append(item);
            }
            out << QJsonDocument(entries).toJson();
        } else if (command == "installed" || command == "list" || command == "status") {
            out << QJsonDocument(store.list(catalogue)).toJson();
        } else if (command == "install" || command == "remove") {
            if (arguments.size() != 2) fail(i18n("Specify one group."));
            if (command == "install") {
                for (const auto &entry : catalogue.entries()) {
                    if (entry.groups.contains(arguments[1]) && catalogue.requiresE521(entry.certificate)) {
                        err << catalogue.verificationNote(entry.certificate) << '\n';
                        if (!parser.isSet("allow-e521")) err << i18n("E-521 entries are skipped. Use --allow-e521 to choose them explicitly.") << '\n';
                        break;
                    }
                }
                store.install(catalogue, arguments[1], parser.isSet("allow-e521"));
            }
            else store.remove(catalogue, arguments[1]);
            out << i18n("Certificate store updated.") << '\n';
        } else if (command == "update") {
            if (!parser.isSet("output")) fail(i18n("Specify --output for the refreshed catalogue."));
            Transport transport;
            if (parser.isSet("tls-ca")) transport.caPem = readFile(parser.value("tls-ca"));
            if (parser.isSet("tls-issuer")) transport.issuerPem = readFile(parser.value("tls-issuer"));
            else if (!parser.isSet("tls-ca") && QFileInfo::exists(data + "/tls-issuers.pem")) transport.issuerPem = readFile(data + "/tls-issuers.pem");
            const QByteArray zip = parser.isSet("zip") ? readFile(parser.value("zip")) : download(QUrl(parser.value("bundle-url")), transport);
            const QByteArray hash = parser.isSet("hash") ? readFile(parser.value("hash")) : download(QUrl(parser.value("hash-url")), transport, 4096);
            catalogue.ingest(zip, hash);
            writeFile(parser.value("output"), catalogue.json());
            out << i18n("Verified catalogue written.") << '\n';
        } else if (command == "import") {
            if (!parser.isSet("nss") || arguments.size() != 2) fail(i18n("Personal certificate import requires --nss and one PKCS#12 file."));
            QProcess process;
            process.setProcessChannelMode(QProcess::ForwardedChannels);
            process.start("pk12util", {"-d", "sql:" + parser.value("nss"), "-i", arguments[1]});
            if (!process.waitForFinished(-1) || process.exitCode() != 0) fail(i18n("Personal certificate import failed."));
        } else {
            fail(i18n("Unknown command: %1", command));
        }
        return 0;
    } catch (const std::exception &exception) {
        err << QString::fromUtf8(exception.what()) << '\n';
        return 1;
    }
}
