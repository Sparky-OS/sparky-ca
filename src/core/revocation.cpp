// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include "core.h"
#include <KLocalizedString>
#include <QElapsedTimer>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <ctime>
#include <memory>

namespace SparkyCA
{
using Crl = std::shared_ptr<X509_CRL>;

static QList<QUrl> distributionPoints(const Certificate &cert)
{
    QList<QUrl> urls;
    auto *points = static_cast<STACK_OF(DIST_POINT) *>(X509_get_ext_d2i(cert.get(), NID_crl_distribution_points, nullptr, nullptr));
    for (int index = 0; points && index < sk_DIST_POINT_num(points); ++index) {
        const DIST_POINT *point = sk_DIST_POINT_value(points, index);
        // Indirect and partial CRLs do not give a complete answer for this certificate.
        if (point->CRLissuer || point->reasons || !point->distpoint || point->distpoint->type != 0) continue;
        for (int name = 0; name < sk_GENERAL_NAME_num(point->distpoint->name.fullname); ++name) {
            const GENERAL_NAME *general = sk_GENERAL_NAME_value(point->distpoint->name.fullname, name);
            if (general->type != GEN_URI) continue;
            const QUrl url(QString::fromLatin1(reinterpret_cast<const char *>(ASN1_STRING_get0_data(general->d.uniformResourceIdentifier)),
                                               ASN1_STRING_length(general->d.uniformResourceIdentifier)));
            if (url.isValid() && (url.scheme() == "http" || url.scheme() == "https")) urls.append(url);
        }
    }
    sk_DIST_POINT_pop_free(points, DIST_POINT_free);
    return urls;
}
static Crl parse(const QByteArray &bytes)
{
    X509_CRL *crl = nullptr;
    if (bytes.startsWith("-----BEGIN X509 CRL-----")) {
        BIO *bio = BIO_new_mem_buf(bytes.constData(), bytes.size());
        crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
    } else {
        const unsigned char *position = reinterpret_cast<const unsigned char *>(bytes.constData());
        crl = d2i_X509_CRL(nullptr, &position, bytes.size());
        if (crl && position != reinterpret_cast<const unsigned char *>(bytes.constData() + bytes.size())) {
            X509_CRL_free(crl);
            crl = nullptr;
        }
    }
    if (!crl) fail(i18n("Cannot parse CRL."));
    return Crl(crl, X509_CRL_free);
}
static QDateTime when(const ASN1_TIME *time)
{
    struct tm parts = {};
    if (!time || !ASN1_TIME_to_tm(time, &parts)) return {};
    return QDateTime(QDate(parts.tm_year + 1900, parts.tm_mon + 1, parts.tm_mday), QTime(parts.tm_hour, parts.tm_min, parts.tm_sec), QTimeZone::UTC);
}
// A complete CRL signed by the issuing CA, fresh at this moment.
static void accept(const Crl &crl, const Certificate &issuer)
{
    if (X509_NAME_cmp(X509_CRL_get_issuer(crl.get()), X509_get_subject_name(issuer.get())) != 0) fail(i18n("CRL issuer does not match."));
    EVP_PKEY *key = X509_get0_pubkey(issuer.get());
    if (!key || X509_CRL_verify(crl.get(), key) != 1) fail(i18n("CRL signature is not valid."));
    auto *scope = static_cast<ISSUING_DIST_POINT *>(X509_CRL_get_ext_d2i(crl.get(), NID_issuing_distribution_point, nullptr, nullptr));
    const bool partial = scope && (scope->indirectCRL > 0 || scope->onlyuser > 0 || scope->onlyattr > 0 || scope->onlysomereasons);
    ISSUING_DIST_POINT_free(scope);
    if (partial) fail(i18n("CRL does not cover every certificate of its issuer."));
    time_t now = time(nullptr);
    if (X509_cmp_time(X509_CRL_get0_lastUpdate(crl.get()), &now) > 0) fail(i18n("CRL is not yet valid."));
    if (!X509_CRL_get0_nextUpdate(crl.get()) || X509_cmp_time(X509_CRL_get0_nextUpdate(crl.get()), &now) <= 0) fail(i18n("CRL is stale."));
}
QJsonObject checkRevocation(const Catalogue &catalogue, const Transport &transport, const QJsonObject &previous, bool network)
{
    QJsonObject certificates, crls;
    QJsonArray errors;
    QElapsedTimer budget;
    budget.start();
    QHash<QString, Crl> fetched;
    QHash<QString, QString> failures;
    const auto previousRecords = previous.value("certificates").toObject();
    const auto previousCrls = previous.value("crls").toObject();
    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (const auto &entry : catalogue.entries()) {
        const Certificate &cert = entry.certificate;
        if (cert.root() || !cert.ca() || cert.state() != "valid") continue;
        const QString id = cert.fingerprint();
        const auto urls = distributionPoints(cert);
        QJsonObject record{{"status", "unknown"}};
        if (catalogue.requiresE521(cert)) {
            record.insert("reason", i18n("The CRL signature uses E-521, which Linux cannot verify."));
        } else if (urls.isEmpty()) {
            record.insert("reason", i18n("The certificate names no CRL."));
        } else {
            const Certificate *issuer = nullptr;
            for (const auto &candidate : catalogue.entries()) {
                if (cert.issuedBy(candidate.certificate)) { issuer = &candidate.certificate; break; }
            }
            QString reason = i18n("No CRL could be fetched.");
            bool done = false;
            for (const auto &url : urls) {
                if (!issuer) { reason = i18n("The issuer is not in the catalogue."); break; }
                const QString key = url.toString();
                try {
                    if (!fetched.contains(key)) {
                        if (failures.contains(key)) fail(failures.value(key));
                        if (!network || budget.elapsed() > 10 * 60 * 1000) fail(i18n("No network was used for this check."));
                        const Crl crl = parse(download(url, transport, 16 * 1024 * 1024, true));
                        accept(crl, *issuer);
                        fetched.insert(key, crl);
                        crls.insert(key, QJsonObject{{"issuer", issuer->subject()},
                                                     {"thisUpdate", when(X509_CRL_get0_lastUpdate(crl.get())).toString(Qt::ISODate)},
                                                     {"nextUpdate", when(X509_CRL_get0_nextUpdate(crl.get())).toString(Qt::ISODate)}});
                    }
                    const Crl &crl = fetched.value(key);
                    X509_REVOKED *revoked = nullptr;
                    const int found = X509_CRL_get0_by_cert(crl.get(), &revoked, cert.get());
                    record.insert("status", found == 1 ? "revoked" : "good");
                    record.insert("crl", key);
                    record.remove("reason");
                    done = true;
                    break;
                } catch (const std::exception &error) {
                    reason = QString::fromUtf8(error.what());
                    if (network && !failures.contains(key)) errors.append(key + ": " + reason);
                    failures.insert(key, reason);
                }
            }
            if (!done) {
                // A fetch that fails today does not discard a recent verified answer.
                const auto old = previousRecords.value(id).toObject();
                const auto oldCrl = previousCrls.value(old.value("crl").toString()).toObject();
                const QDateTime next = QDateTime::fromString(oldCrl.value("nextUpdate").toString(), Qt::ISODate);
                // A revocation is permanent; a good answer is kept only until the CRL that gave it expires.
                if (old.value("status") == "revoked" || (old.value("status") == "good" && next.isValid() && next > now)) {
                    record = old;
                    crls.insert(old.value("crl").toString(), oldCrl);
                } else {
                    record.insert("reason", reason);
                }
            }
        }
        certificates.insert(id, record);
    }
    return {{"schema", 1}, {"checked", now.toString(Qt::ISODate)}, {"certificates", certificates}, {"crls", crls}, {"errors", errors}};
}
}
