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
#include <QFileInfo>
#include <QUrl>

using namespace SparkyCA;
static QByteArray passwordFromFile(const QString &path)
{
    if (QFileInfo(path).permissions() & (QFile::ReadGroup | QFile::WriteGroup | QFile::ReadOther | QFile::WriteOther)) fail(i18n("Use a private password file with owner-only permissions."));
    auto password = readFile(path);
    if (password.endsWith('\n')) {
        password.chop(1);
        if (password.endsWith('\r')) password.chop(1);
    }
    if (password.contains('\n') || password.contains('\0')) fail(i18n("Expected one password in a private file."));
    return password;
}
static Transport transportFrom(const QCommandLineParser &parser, const QString &data)
{
    Transport transport;
    if (parser.isSet("tls-ca")) transport.caPem = readFile(parser.value("tls-ca"));
    if (parser.isSet("tls-issuer")) transport.issuerPem = readFile(parser.value("tls-issuer"));
    else if (!parser.isSet("tls-ca") && QFileInfo::exists(data + "/tls-issuers.pem")) transport.issuerPem = readFile(data + "/tls-issuers.pem");
    return transport;
}
static int automatic(const QCommandLineParser &parser, const QString &action, QTextStream &out)
{
    const QString scope = parser.isSet("scope") ? parser.value("scope") : geteuid() == 0 ? "system" : "user";
    if (scope != "system" && scope != "user") fail(i18n("Scope must be system or user."));
    const QString configuration = parser.isSet("config-dir") ? parser.value("config-dir") : scope == "system" ? QStringLiteral("/etc/sparky-ca") : parser.value("home") + "/.config/sparky-ca";
    const QString data = parser.value("data");
    AutomationOptions options;
    options.data = data;
    options.stateDirectory = parser.value("cache-dir");
    options.scope = scope;
    options.systemDirectory = parser.value("system-dir");
    options.systemBundle = parser.value("system-bundle");
    options.home = parser.value("home");
    options.bundleUrl = QUrl(parser.value("bundle-url"));
    options.hashUrl = QUrl(parser.value("hash-url"));
    options.transport = transportFrom(parser, data);
    options.network = scope == "system" && !parser.isSet("no-network");
    options.nssDatabases = parser.isSet("nss") ? QStringList{parser.value("nss")} : browserDatabases(options.home);
    if (action == "enable" || action == "disable") {
        setAutomationEnabled(configuration, action == "enable");
        out << (action == "enable" ? i18n("Automatic updates are on.") : i18n("Automatic updates are off.")) << '\n';
        return 0;
    }
    if (action == "status") {
        const QString statusPath = automationStatusPath(options);
        QJsonObject status{{"scope", scope}, {"enabled", automationEnabled(configuration)}, {"switch", automationFlag(configuration)},
                           {"catalogue", catalogueSource(data, options.stateDirectory)}};
        QJsonArray groups;
        if (scope == "system") {
            for (const auto &group : Store(options.systemDirectory, options.systemBundle, {}).selectedGroups()) groups.append(group);
        } else {
            for (const auto &database : options.nssDatabases) {
                for (const auto &group : Store({}, {}, database).selectedGroups()) groups.append(group);
            }
        }
        status.insert("selectedGroups", groups);
        if (trustedStateFile(statusPath)) {
            auto last = QJsonDocument::fromJson(readFile(statusPath)).object();
            last.remove("stores");
            status.insert("lastRun", last);
        }
        out << QJsonDocument(status).toJson();
        return 0;
    }
    if (action != "run") fail(i18n("Specify auto status, enable, disable or run."));
    if (!parser.isSet("force") && !automationEnabled(configuration)) {
        out << i18n("Automatic updates are turned off.") << '\n';
        return 0;
    }
    if (scope == "system" && options.systemBundle == "/etc/ssl/certs/ca-certificates.crt" && geteuid() != 0) fail(i18n("System updates require root."));
    const auto report = runAutomation(options);
    const bool journal = qEnvironmentVariableIsSet("JOURNAL_STREAM");
    for (const auto &line : report.value("summary").toString().split('\n')) out << (journal ? "<" + line.section(' ', 0, 0) + ">" : QString()) << line.section(' ', 1) << '\n';
    out.flush();
    return report.value("outcome").toString() == "failed" ? 1 : 0;
}
int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    application.setApplicationName("sparky-ca");
    application.setApplicationVersion("2.0.3");
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
        {"password-file", i18n("Read the PKCS#12 passphrase from this private file."), "file"},
        {"nss-password-file", i18n("Read the NSS database password from this private file."), "file"},
        {"gpg-home", i18n("GnuPG certificate directory."), "directory", QDir::homePath() + "/.gnupg"},
        {"allow-e521", i18n("Choose E-521 certificates despite unavailable Linux chain verification; requires programs with their own E-521 code.")},
        {"tls-ca", i18n("TLS trust root for an isolated HTTPS fixture."), "file"},
        {"tls-issuer", i18n("Missing TLS issuer, verified against the TLS trust roots."), "file"},
        {"bundle-url", i18n("HTTPS bundle URL."), "url", "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip"},
        {"hash-url", i18n("HTTPS SHA-512 URL."), "url", "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt"},
        {"zip", i18n("Offline ZIP input for catalogue verification."), "file"},
        {"hash", i18n("Offline SHA-512 input."), "file"},
        {"output", i18n("Write refreshed catalogue here."), "file"},
        {"download-dir", i18n("Keep the downloaded bundle and its SHA-512 here, as received, so a failed refresh can be examined."), "directory"},
        {"cache-dir", i18n("Machine state: refreshed catalogue, revocation answers and update status."), "directory", SPARKY_CA_STATE},
        {"config-dir", i18n("Folder holding the switch for automatic updates."), "directory"},
        {"home", i18n("Home folder whose browser databases are updated."), "directory", QDir::homePath()},
        {"scope", i18n("Automatic update scope: system or user."), "scope"},
        {"force", i18n("Run an automatic update although it is turned off.")},
        {"no-network", i18n("Do not use the Internet in an automatic update.")}
    });
    parser.addPositionalArgument("command", i18n("list [installed], groups, install <group>, remove <group|all>, update, auto <status|enable|disable|run>, status, profiles, preview <file>, import <file>, tokens, register-token <module>, unregister-token, gpgsm-import <group>, gpgsm-remove <group|all>, gpgsm-status, gpgsm-confirm"));
    parser.process(application);
    QTextStream out(stdout), err(stderr), in(stdin);
    try {
        const QString data = parser.value("data");
        auto arguments = parser.positionalArguments();
        QString command = arguments.value(0);
        if (command == "auto") return automatic(parser, arguments.value(1), out);
        const QString path = parser.isSet("catalogue") ? parser.value("catalogue") : data + "/catalogue.json";
        Catalogue catalogue(data + "/pins.json", data + "/roots");
        if (command == "update") {
            if (QFileInfo::exists(path)) catalogue.load(readFile(path));
        } else {
            catalogue = loadCatalogue(data, parser.value("cache-dir"), parser.isSet("catalogue") ? parser.value("catalogue") : QString());
        }
        Store store(parser.isSet("nss") ? QString() : parser.value("system-dir"), parser.value("system-bundle"), parser.value("nss"), parser.isSet("nss-password-file") ? passwordFromFile(parser.value("nss-password-file")) : QByteArray());
        if (command.isEmpty()) {
            if (!isatty(STDIN_FILENO)) parser.showHelp(1);
            const bool gpg = gpgsmAvailable();
            out << (gpg ? i18n("1. List catalogue\n2. List installed certificates\n3. Install group\n4. Remove group\n5. Status\n6. Import group into gpgsm (Kleopatra)\n7. Remove what was imported into gpgsm\n8. Confirm an imported root\n0. Exit\nChoice: ")
                        : i18n("1. List catalogue\n2. List installed certificates\n3. Install group\n4. Remove group\n5. Status\n0. Exit\nChoice: ")) << Qt::flush;
            const QString choice = in.readLine();
            if (choice == "0" || choice.isNull()) return 0;
            command = choice == "1" ? "list" : choice == "2" ? "installed" : choice == "3" ? "install" : choice == "4" ? "remove" : choice == "5" ? "status"
                : gpg && choice == "6" ? "gpgsm-import" : gpg && choice == "7" ? "gpgsm-remove" : gpg && choice == "8" ? "gpgsm-confirm" : "invalid";
            if (command == "install" || command == "remove" || command == "gpgsm-import" || command == "gpgsm-remove") {
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
                const QString issue = catalogue.installationIssue(entry.certificate);
                item.insert("installationIssue", issue);
                item.insert("installable", issue.isEmpty() && !catalogue.requiresE521(entry.certificate));
                item.insert("requiresChoice", catalogue.requiresE521(entry.certificate));
                entries.append(item);
            }
            out << QJsonDocument(entries).toJson();
        } else if (command == "installed" || command == "list" || command == "status") {
            out << QJsonDocument(store.list(catalogue)).toJson();
        } else if (command == "install" || command == "remove") {
            if (arguments.size() != 2) fail(i18n("Specify one group."));
            if (command == "install") {
                if (parser.isSet("nss")) err << i18n("NSS installations exclude Ed521 and Ed448 entries because NSS cannot import their key types.") << '\n';
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
            const Transport transport = transportFrom(parser, data);
            const QByteArray zip = parser.isSet("zip") ? readFile(parser.value("zip")) : download(QUrl(parser.value("bundle-url")), transport);
            const QByteArray hash = parser.isSet("hash") ? readFile(parser.value("hash")) : download(QUrl(parser.value("hash-url")), transport, 4096);
            if (parser.isSet("download-dir")) {
                QDir().mkpath(parser.value("download-dir"));
                writeFile(parser.value("download-dir") + "/ACcompactado.zip", zip);
                writeFile(parser.value("download-dir") + "/hashsha512.txt", hash);
            }
            catalogue.ingest(zip, hash);
            writeFile(parser.value("output"), catalogue.json());
            out << i18n("Verified catalogue written.") << '\n';
        } else if (command == "preview") {
            if (arguments.size() != 2) fail(i18n("Specify one certificate file."));
            QJsonArray records;
            const auto password = parser.isSet("password-file") ? passwordFromFile(parser.value("password-file")) : QByteArray();
            for (const auto &cert : previewCertificates(readFile(arguments[1]), password)) records.append(describe(cert, cert.subject(), catalogue.state(cert)));
            out << QJsonDocument(records).toJson();
        } else if (command == "tokens") {
            if (arguments.size() > 2) fail(i18n("Specify at most one token module."));
            out << tokenInformation(arguments.value(1));
        } else if (command == "register-token") {
            if (arguments.size() != 2 || !parser.isSet("nss")) fail(i18n("Specify an NSS database and one installed token module."));
            registerTokenModule(parser.value("nss"), arguments[1], parser.isSet("nss-password-file") ? passwordFromFile(parser.value("nss-password-file")) : QByteArray());
        } else if (command == "gpgsm-import" || command == "gpgsm-remove") {
            if (arguments.size() != 2) fail(i18n("Specify one root group."));
            const auto result = command == "gpgsm-import" ? gpgsmImport(catalogue, arguments[1], parser.value("gpg-home")) : gpgsmRemove(arguments[1], parser.value("gpg-home"));
            out << QJsonDocument(result).toJson();
            if (result.value("previousTrustRemoved").toBool()) err << i18n("Trust entries that version 2.0.0 added to gpgsm without asking were removed.") << '\n';
            if (command == "gpgsm-import") out << i18n("Imported certificates are not trusted yet. Run gpgsm-confirm, or use Kleopatra's Trust Root Certificate, to decide.") << '\n';
        } else if (command == "gpgsm-status") {
            out << QJsonDocument(gpgsmStatus(parser.value("gpg-home"))).toJson();
        } else if (command == "gpgsm-confirm") {
            const auto roots = gpgsmUnconfirmedRoots(parser.value("gpg-home"));
            if (roots.isEmpty()) out << i18n("No imported root is waiting for your confirmation.") << '\n';
            for (const auto &fingerprint : roots) {
                // gpgsm shows the fingerprint and asks through its own prompt. Nothing here answers for the user.
                QProcess process;
                process.setProcessChannelMode(QProcess::ForwardedChannels);
                process.setInputChannelMode(QProcess::ForwardedInputChannel);
                process.start("gpgsm", {"--homedir", parser.value("gpg-home"), "--with-validation", "--list-keys", fingerprint});
                if (!process.waitForFinished(-1) || process.exitCode() != 0) fail(i18n("gpgsm could not check the root."));
            }
        } else if (command == "unregister-token") {
            if (arguments.size() != 1 || !parser.isSet("nss")) fail(i18n("Specify an NSS database."));
            unregisterTokenModule(parser.value("nss"));
        } else if (command == "import") {
            if (!parser.isSet("nss") || arguments.size() != 2) fail(i18n("Personal certificate import requires --nss and one PKCS#12 file."));
            if (parser.isSet("password-file")) {
                importPersonalCertificate(arguments[1], parser.value("nss"), passwordFromFile(parser.value("password-file")),
                    parser.isSet("nss-password-file") ? passwordFromFile(parser.value("nss-password-file")) : QByteArray());
            } else {
                QProcess process;
                process.setProcessChannelMode(QProcess::ForwardedChannels);
                process.setInputChannelMode(QProcess::ForwardedInputChannel);
                process.start("pk12util", {"-d", "sql:" + parser.value("nss"), "-i", arguments[1]});
                if (!process.waitForFinished(-1) || process.exitCode() != 0) fail(i18n("Personal certificate import failed."));
            }
        } else {
            fail(i18n("Unknown command: %1", command));
        }
        return 0;
    } catch (const std::exception &exception) {
        err << QString::fromUtf8(exception.what()) << '\n';
        return 1;
    }
}
