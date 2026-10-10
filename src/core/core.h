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
    void verify(const Certificate &cert, bool current) const;
private:
    QList<Certificate> m_roots;
    QSet<QString> m_revoked;
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
class Store
{
public:
    Store(QString systemDirectory, QString systemBundle, QString nssDatabase);
    void install(const Catalogue &catalogue, const QString &group);
    void remove(const Catalogue &catalogue, const QString &group);
    QJsonArray list(const Catalogue &catalogue) const;
private:
    QString m_system;
    QString m_bundle;
    QString m_nss;
    void rebuild();
};
}
