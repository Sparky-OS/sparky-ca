// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import org.kde.kirigami as Kirigami

Kirigami.ApplicationWindow {
    id: window
    visible: true
    width: 1100
    height: 840
    title: i18n("Certificates")
    pageStack.initialPage: CertificatePage {
        manager: certificateManager
        Component.onCompleted: if (initialCertificateFile.toString().length > 0) Qt.callLater(() => openFile(initialCertificateFile))
    }
}
