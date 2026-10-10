// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QByteArray>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonObject>
#include <QSet>
#include <QStringList>
#include <QTimeZone>
#include <QUrl>
#include <QVariantMap>
#include <memory>
#include <openssl/x509.h>

namespace SparkyCA
{
void fail(const QString &message);
QByteArray readFile(const QString &path);
void writeFile(const QString &path, const QByteArray &data);
QByteArray run(const QString &program, const QStringList &arguments);

class Certificate
{
public:
    explicit Certificate(const QByteArray &bytes);
    X509 *get() const { return m_cert.get(); }
    QByteArray pem() const;
    QString fingerprint() const;
    QString subject() const;
    QString issuer() const;
    QString state() const;
    QDateTime expires() const;
    bool root() const;
    bool ca() const;
    QString signatureOid() const;
    bool issuedBy(const Certificate &issuer) const;
private:
    std::shared_ptr<X509> m_cert;
};
struct Entry {
    QString name;
    QStringList groups;
    Certificate certificate;
};
class Catalogue
{
public:
    Catalogue(const QString &pinsFile, const QString &rootsDirectory);
    void load(const QByteArray &json);
    void ingest(const QByteArray &zip, const QByteArray &sha512);
    QByteArray json() const;
    const QList<Entry> &entries() const { return m_entries; }
    QStringList groups() const;
    QString state(const Certificate &cert) const;
    bool requiresE521(const Certificate &cert) const;
    QString verification(const Certificate &cert) const;
    QString verificationNote(const Certificate &cert) const;
    QString installationIssue(const Certificate &cert) const;
    void verify(const Certificate &cert, bool current) const;
private:
    QList<Certificate> m_roots;
    bool m_e521Verified = false;
    QSet<QString> m_revoked;
    QSet<QString> m_bundlePins;
    QSet<QString> m_e521Allowed;
    QJsonArray m_provenance;
    QList<Entry> m_entries;
    void validate(const QList<Entry> &entries) const;
};
struct Transport {
    QByteArray caPem;
    QByteArray issuerPem;
};
QByteArray download(const QUrl &url, const Transport &transport, qint64 limit = 8 * 1024 * 1024);
QStringList classify(const QString &name, const Certificate &cert);
QJsonObject describe(const Certificate &cert, const QString &name, const QString &state);
QStringList browserDatabases(const QString &home);
QList<Certificate> previewCertificates(const QByteArray &bytes, const QByteArray &password = {});
void importPersonalCertificate(const QString &file, const QString &database, const QByteArray &password, const QByteArray &databasePassword);
void registerTokenModule(const QString &database, const QString &module, const QByteArray &databasePassword);
void unregisterTokenModule(const QString &database);
QByteArray tokenInformation(const QString &module = {});
void setGpgsmTrust(const Catalogue &catalogue, const QString &group, const QString &home, bool trusted);
void applySystemChange(const QVariantMap &arguments, const QString &data, const QString &directory, const QString &bundle);
void validateStorePath(const QString &path);
class Store
{
public:
    Store(QString systemDirectory, QString systemBundle, QString nssDatabase, QByteArray databasePassword = {});
    void install(const Catalogue &catalogue, const QString &group, bool allowE521 = false);
    void remove(const Catalogue &catalogue, const QString &group);
    QJsonArray list(const Catalogue &catalogue) const;
private:
    QString m_system;
    QString m_bundle;
    QString m_nss;
    QByteArray m_password;
    void rebuild();
};
}
