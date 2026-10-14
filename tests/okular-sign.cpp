// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
#include <QApplication>
#include <QMimeDatabase>
#include <QTextStream>
#include <QUrl>
#include <okular/core/document.h>
#include <okular/core/settings_core.h>
#include <okular/core/signatureutils.h>
#include <poppler-form.h>

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    if (argc != 5)
        return 2;
    Okular::SettingsCore::instance(QStringLiteral("okular-fixture"));
    Poppler::setNSSDir(QString::fromLocal8Bit(argv[1]));
    if (!Poppler::setActiveCryptoSignBackend(Poppler::CryptoSignBackend::NSS))
        return 1;
    Okular::Document document(nullptr);
    const QString input = argv[2], output = argv[3], nickname = argv[4];
    if (document.openDocument(input, QUrl::fromLocalFile(input), QMimeDatabase().mimeTypeForName("application/pdf")) != Okular::Document::OpenSuccess) {
        QTextStream(stderr) << document.openError() << '\n';
        return 1;
    }
    if (!document.certificateStore())
        return 1;
    bool cancelled = false;
    const auto certificates = document.certificateStore()->signingCertificates(&cancelled);
    bool found = false;
    for (const auto &cert : certificates)
        if (cert.nickName() == nickname)
            found = true;
    if (!found || cancelled)
        return 1;
    QTextStream(stdout) << "PASS imported generated identity appears in Okular's certificate store: " << nickname << '\n';
    Okular::NewSignatureData data;
    data.setCertNickname(nickname);
    data.setCertSubjectCommonName(nickname);
    data.setPage(0);
    data.setBoundingRectangle(Okular::NormalizedRect(0.1, 0.6, 0.9, 0.85));
    data.setReason("Generated container fixture");
    data.setLocation("Isolated test");
    const auto result = document.sign(data, output);
    if (result.first != Okular::SigningSuccess) {
        QTextStream(stderr) << "Signing failed: " << result.first << ' ' << result.second << '\n';
        return 1;
    }
    QTextStream(stdout) << "PASS Okular signs the fixture PDF through its NSS backend\n";
    return 0;
}
