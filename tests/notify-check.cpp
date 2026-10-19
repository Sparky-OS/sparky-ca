// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/core.h"
#include <QCoreApplication>
#include <QDBusConnection>
#include <QDir>
#include <QEventLoop>
#include <QJsonDocument>
#include <QProcess>
#include <QTemporaryDir>
#include <QTextStream>

class Notifications : public QObject
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.freedesktop.Notifications")
public:
    QStringList titles, bodies;
public Q_SLOTS:
    QStringList GetCapabilities()
    {
        return {"body"};
    }
    QString GetServerInformation(QString &vendor, QString &version, QString &specVersion)
    {
        vendor = "Fixture";
        version = "1";
        specVersion = "1.2";
        return "Fixture notification receiver";
    }
    uint Notify(const QString &, uint, const QString &, const QString &summary, const QString &text, const QStringList &, const QVariantMap &, int)
    {
        titles.append(summary);
        bodies.append(text);
        return titles.size();
    }
    void CloseNotification(uint)
    {
    }
};
static int checks = 0;
static void require(bool condition, const QString &message)
{
    if (!condition)
        SparkyCA::fail(message);
    ++checks;
    QTextStream(stdout) << "PASS " << message << '\n';
}
static void publish(const QString &path, const QJsonObject &report, QFileDevice::Permissions permissions = QFile::ReadOwner | QFile::WriteOwner | QFile::ReadGroup | QFile::ReadOther)
{
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile::remove(path);
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write(QJsonDocument(report).toJson()) < 0)
        SparkyCA::fail("cannot write " + path);
    file.close();
    file.setPermissions(permissions);
}
static QJsonObject report(const QString &scope, const QString &id, const QJsonArray &added, const QJsonArray &removed)
{
    return {{"schema", 1}, {"scope", scope}, {"runId", id},
            {"stores", QJsonArray{QJsonObject{{"store", scope}, {"added", added}, {"removed", removed}, {"needsChoice", 0}, {"errors", QJsonArray()}}}},
            {"notices", QJsonArray()}};
}
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 3)
        return 2;
    QTemporaryDir temporary;
    const QString notifier = argv[1], home = temporary.filePath("home"), state = temporary.filePath("state");
    QDir().mkpath(temporary.filePath("xdg/knotifications6"));
    QFile::copy(argv[2], temporary.filePath("xdg/knotifications6/sparky-ca.notifyrc"));
    Notifications receiver;
    auto connection = QDBusConnection::sessionBus();
    if (!connection.registerService("org.freedesktop.Notifications") || !connection.registerObject("/org/freedesktop/Notifications", &receiver, QDBusConnection::ExportAllSlots))
        return 3;
    const auto notify = [&] {
        QProcess process;
        auto environment = QProcessEnvironment::systemEnvironment();
        environment.insert("XDG_DATA_DIRS", temporary.filePath("xdg"));
        environment.insert("QT_QPA_PLATFORM", "offscreen");
        process.setProcessEnvironment(environment);
        QEventLoop loop;
        QObject::connect(&process, &QProcess::finished, &loop, &QEventLoop::quit);
        process.start(notifier, {"--state", state, "--home", home});
        loop.exec();
        return process.exitCode();
    };
    const QJsonObject added{{"name", "AC_Renewed_G8.crt"}, {"sha256", QString(64, 'a')}};
    const QJsonObject removed{{"name", "AC_Old_G6.crt"}, {"sha256", QString(64, 'b')}, {"reason", "expired"}};
    const QString systemStatus = state + "/status.json", userStatus = home + "/.local/state/sparky-ca/status.json";

    require(notify() == 0 && receiver.titles.isEmpty(), "with no status file nothing is shown");
    publish(systemStatus, report("system", "1000", {added}, {}));
    require(notify() == 0 && receiver.titles.size() == 1, "a new system update is reported once");
    require(receiver.titles.first() == "Certificates" && receiver.bodies.first().contains("AC_Renewed_G8.crt"), "the message names the certificate that was added");
    require(notify() == 0 && receiver.titles.size() == 1, "the same run is not reported again");
    publish(systemStatus, report("system", "1001", {}, {}));
    require(notify() == 0 && receiver.titles.size() == 1, "a run that changed nothing stays silent");
    publish(userStatus, report("user", "2000", {}, {removed}));
    require(notify() == 0 && receiver.titles.size() == 2, "a user run that removed a certificate is reported");
    require(receiver.bodies.last().contains("AC_Old_G6.crt") && receiver.bodies.last().contains("expired"), "the message names the certificate and why it was removed");
    publish(systemStatus, report("system", "1002", {added}, {}), QFile::ReadOwner | QFile::WriteOwner | QFile::WriteOther);
    require(notify() == 0 && receiver.titles.size() == 2, "a world-writable status file is ignored");
    auto deferred = report("user", "2001", {}, {});
    deferred.insert("deferred", QJsonArray{"Fixture profile is in use by a browser; it will be updated on a later run."});
    publish(userStatus, deferred);
    require(SparkyCA::journalLines(deferred).startsWith("6 Fixture profile"), "a deferred browser profile remains visible at journal info priority");
    require(notify() == 0 && receiver.titles.size() == 2, "a deferred browser profile sends no notification");
    deferred.insert("runId", "2002");
    publish(userStatus, deferred);
    require(notify() == 0 && receiver.titles.size() == 2, "a repeated deferred browser profile stays silent");
    const auto actionable = [&](QJsonObject status, const QString &text) {
        status.insert("deferred", deferred.value("deferred"));
        const int before = receiver.titles.size();
        publish(userStatus, status);
        require(notify() == 0 && receiver.titles.size() == before + 1 && receiver.bodies.last().contains(text)
                    && !receiver.bodies.last().contains("Fixture profile"),
                "an actionable update still notifies beside a deferred profile: " + text);
        require(notify() == 0 && receiver.titles.size() == before + 1, "the actionable run is reported only once");
    };
    auto failed = report("user", "2003", {}, {});
    failed.insert("error", "Fixture update failure");
    actionable(failed, "Fixture update failure");
    auto refreshFailed = report("user", "2004", {}, {});
    refreshFailed.insert("catalogue", QJsonObject{{"error", "Fixture refresh failure"}});
    actionable(refreshFailed, "Fixture refresh failure");
    auto storeFailed = report("user", "2005", {}, {});
    storeFailed.insert("stores", QJsonArray{QJsonObject{{"store", "fixture"}, {"errors", QJsonArray{"Fixture store failure"}}}});
    actionable(storeFailed, "Fixture store failure");
    auto choice = report("user", "2006", {}, {});
    choice.insert("stores", QJsonArray{QJsonObject{{"store", "fixture"}, {"needsChoice", 1}}});
    actionable(choice, "needs your choice");
    auto revoked = removed;
    revoked.insert("reason", "revoked");
    actionable(report("user", "2007", {}, {revoked}), "revoked");
    auto notice = report("user", "2008", {}, {});
    notice.insert("notices", QJsonArray{"Fixture legacy attention notice"});
    actionable(notice, "Fixture legacy attention notice");
    QTextStream(stdout) << checks << " notification checks passed\n";
    return 0;
}
#include "notify-check.moc"
