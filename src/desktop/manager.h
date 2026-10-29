// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/core.h"
#include <QObject>
#include <QPointer>
#include <QVariantList>
#include <QWindow>
#include <functional>

class CertificateManager : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QVariantList certificates READ certificates NOTIFY changed)
    Q_PROPERTY(QStringList groups READ groups NOTIFY changed)
    Q_PROPERTY(QStringList profiles READ profiles NOTIFY changed)
    Q_PROPERTY(QString error READ error NOTIFY changed)
    Q_PROPERTY(QString notice READ notice NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    Q_PROPERTY(QString store READ store NOTIFY changed)
    Q_PROPERTY(bool gpgAvailable READ gpgAvailable CONSTANT)
    Q_PROPERTY(bool kleopatraAvailable READ kleopatraAvailable CONSTANT)
    Q_PROPERTY(bool automaticUpdates READ automaticUpdates NOTIFY changed)
    Q_PROPERTY(QString updateStatus READ updateStatus NOTIFY changed)
    Q_PROPERTY(QString ed521Message READ ed521Message NOTIFY ed521Changed)
    Q_PROPERTY(bool ed521Warning READ ed521Warning NOTIFY ed521Changed)
    Q_PROPERTY(bool ed521Dismissed READ ed521Dismissed NOTIFY ed521Changed)
    Q_PROPERTY(bool ed521Probed READ ed521Probed NOTIFY ed521Changed)
public:
    explicit CertificateManager(QString data, QObject *parent = nullptr);
    QVariantList certificates() const
    {
        return m_certificates;
    }
    QStringList groups() const
    {
        return m_catalogue ? m_catalogue->groups() : QStringList();
    }
    QStringList profiles() const;
    QString error() const
    {
        return m_error;
    }
    QString notice() const
    {
        return m_notice;
    }
    bool busy() const
    {
        return m_busy;
    }
    QString store() const
    {
        return m_store;
    }
    bool gpgAvailable() const;
    bool kleopatraAvailable() const;
    bool automaticUpdates() const;
    QString updateStatus() const;
    QString ed521Message() const
    {
        return m_ed521Message;
    }
    bool ed521Warning() const
    {
        return m_ed521Probed && !m_ed521.openssl;
    }
    bool ed521Dismissed() const;
    bool ed521Probed() const
    {
        return m_ed521Probed;
    }
    Q_INVOKABLE void dismissEd521();
    Q_INVOKABLE void probeEd521();
    Q_INVOKABLE void setAutomaticUpdates(bool enabled);
    Q_INVOKABLE void setWindow(QWindow *window)
    {
        m_window = window;
    }
    Q_INVOKABLE void selectStore(const QString &store);
    Q_INVOKABLE void refresh();
    Q_INVOKABLE void changeGroup(const QString &group, bool install, bool allowE521, const QString &password);
    Q_INVOKABLE void preview(const QUrl &file, const QString &password);
    Q_INVOKABLE void importIdentity(const QUrl &file, const QString &database, const QString &password, const QString &databasePassword, bool remember);
    Q_INVOKABLE QVariantMap rememberedPasswords(const QUrl &file, const QString &database);
    Q_INVOKABLE void forgetPasswords(const QUrl &file, const QString &database);
    Q_INVOKABLE void tokens(const QString &module = {});
    Q_INVOKABLE void registerModule(const QString &database, const QString &module, const QString &password);
    Q_INVOKABLE void unregisterModule(const QString &database);
    Q_INVOKABLE void gpgImport(const QString &group);
    Q_INVOKABLE void gpgRemove(const QString &group);
    Q_INVOKABLE void gpgConfirm();
    Q_INVOKABLE void openKleopatra(const QString &fingerprint);
    Q_INVOKABLE void expiryNotification();
Q_SIGNALS:
    void changed();
    void ed521Changed();

private:
    std::shared_ptr<const SparkyCA::Catalogue> m_catalogue;
    QVariantList m_certificates;
    QString m_data, m_store = "catalogue", m_error, m_notice;
    bool m_busy = false;
    SparkyCA::Ed521Support m_ed521;
    bool m_ed521Probed = false;
    QString m_ed521Message;
    QPointer<QWindow> m_window;
    void task(std::function<QString()> operation, std::function<void()> success = {});
    void notify(const QString &text);
    QString gpgHome() const;
};
