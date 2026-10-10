// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "manager.h"
#include <KLocalizedString>
#include <KPluginFactory>
#include <KQuickConfigModule>

class CertificatesModule : public KQuickConfigModule
{
    Q_OBJECT
    Q_PROPERTY(CertificateManager *manager READ manager CONSTANT)
public:
    CertificatesModule(QObject *parent, const KPluginMetaData &data)
        : KQuickConfigModule(parent, data)
        , m_manager(new CertificateManager(QStringLiteral(SPARKY_CA_DATA), this))
    {
        KLocalizedString::setApplicationDomain("sparky-ca");
        setButtons(NoAdditionalButton);
    }
    CertificateManager *manager()
    {
        return m_manager;
    }

private:
    CertificateManager *m_manager;
};
K_PLUGIN_CLASS_WITH_JSON(CertificatesModule, "kcm_certificates.json")
#include "kcm.moc"
