// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core.h"
#include <KLocalizedString>
#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QTimer>

namespace SparkyCA
{
QByteArray download(const QUrl &url, const Transport &transport, qint64 limit, bool signedObject)
{
    // Plain HTTP is allowed only for objects whose own signature the caller verifies, such as CRLs.
    const bool plain = signedObject && url.scheme() == "http";
    if (!url.isValid() || (url.scheme() != "https" && !plain) || !url.userInfo().isEmpty() || url.host().isEmpty()) fail(i18n("Downloads require HTTPS."));
    QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
    if (!transport.caPem.isEmpty()) ssl.setCaCertificates(QSslCertificate::fromData(transport.caPem));
    if (!transport.issuerPem.isEmpty()) {
        QList<Certificate> issuers;
        for (const auto &cert : QSslCertificate::fromData(transport.issuerPem)) issuers.append(Certificate(cert.toPem()));
        if (issuers.isEmpty()) fail(i18n("Cannot parse TLS issuer chain."));
        X509_STORE *store = X509_STORE_new();
        if (transport.caPem.isEmpty()) {
            X509_STORE_set_default_paths(store);
        } else {
            const Certificate root(transport.caPem);
            X509_STORE_add_cert(store, root.get());
        }
        STACK_OF(X509) *chain = sk_X509_new_null();
        for (const auto &issuer : issuers) sk_X509_push(chain, issuer.get());
        bool valid = true;
        for (const auto &issuer : issuers) {
            X509_STORE_CTX *context = X509_STORE_CTX_new();
            X509_STORE_CTX_init(context, store, issuer.get(), chain);
            valid &= issuer.ca() && X509_verify_cert(context) == 1;
            X509_STORE_CTX_free(context);
        }
        sk_X509_free(chain);
        X509_STORE_free(store);
        if (!valid) fail(i18n("TLS issuer does not chain to a trusted root."));
        ssl.addCaCertificates(QSslCertificate::fromData(transport.issuerPem));
    }
    QNetworkAccessManager manager;
    QNetworkRequest request(url);
    request.setSslConfiguration(ssl);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setTransferTimeout(30000);
    QNetworkReply *reply = manager.get(request);
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(&timer, &QTimer::timeout, reply, &QNetworkReply::abort);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QByteArray bytes;
    bool oversized = false;
    QObject::connect(reply, &QNetworkReply::readyRead, &loop, [&] {
        bytes.append(reply->readAll());
        if (bytes.size() > limit) { oversized = true; reply->abort(); }
    });
    timer.start(30000);
    loop.exec();
    bytes.append(reply->readAll());
    if (oversized || bytes.size() > limit) fail(i18n("Download exceeds its size limit."));
    if (reply->error() != QNetworkReply::NoError || reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() != 200) {
        fail(i18n("HTTPS download failed: %1", reply->errorString()));
    }
    return bytes;
}
}
