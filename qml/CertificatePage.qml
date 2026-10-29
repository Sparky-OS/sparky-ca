// SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import org.kde.kirigami as Kirigami

Kirigami.Page {
    id: page
    required property var manager
    property bool inlineActions: false
    property var selected: ({})
    property url chosenFile: ""
    title: i18n("Certificates")
    padding: Kirigami.Units.largeSpacing
    Component.onCompleted: manager.setWindow(page.Window.window)
    FileDialog {
        id: filePicker
        title: i18n("Open certificate or personal identity")
        nameFilters: [i18n("Certificate files (*.crt *.cer *.pem *.p7b *.pfx *.p12)"), i18n("All files (*)")]
        onAccepted: page.openFile(selectedFile)
    }
    function openFile(file) {
        chosenFile = file
        if (/\.(p12|pfx)$/i.test(file.toString())) {
            importDialog.open()
        } else {
            manager.preview(file, "")
            if (manager.certificates.length > 0) selected = manager.certificates[0]
        }
    }
    actions: [
        Kirigami.Action { text: i18n("Open Certificate…"); icon.name: "document-open"; enabled: !manager.busy; onTriggered: filePicker.open() },
        Kirigami.Action { text: i18n("Refresh"); icon.name: "view-refresh"; enabled: !manager.busy; onTriggered: manager.refresh() },
        Kirigami.Action { text: i18n("Check Expiries"); icon.name: "appointment-soon"; enabled: !manager.busy; onTriggered: manager.expiryNotification() },
        Kirigami.Action {
            id: automaticUpdates
            text: i18n("Keep Chosen Groups Current")
            icon.name: "view-refresh"
            checkable: true
            checked: manager.automaticUpdates
            enabled: !manager.busy
            onTriggered: manager.setAutomaticUpdates(checked)
        }
    ]
    Connections {
        target: manager
        function onChanged() {
            page.selected = ({})
            automaticUpdates.checked = Qt.binding(() => manager.automaticUpdates)
        }
    }
    ColumnLayout {
        anchors.fill: parent
        spacing: Kirigami.Units.smallSpacing
        Kirigami.ActionToolBar { Layout.fillWidth: true; visible: page.inlineActions; actions: page.actions; alignment: Qt.AlignLeft }
        Kirigami.InlineMessage {
            objectName: "ed521Message"
            Layout.fillWidth: true
            visible: manager.ed521Message.length > 0 && !manager.ed521Dismissed
            type: manager.ed521Warning ? Kirigami.MessageType.Warning : Kirigami.MessageType.Information
            text: manager.ed521Message
            showCloseButton: true
            // The close button hides the message; remember that, but not when the page itself is hidden.
            onVisibleChanged: {
                if (!visible && page.visible && manager.ed521Message.length > 0 && !manager.ed521Dismissed)
                    manager.dismissEd521()
            }
        }
        Controls.Label { Layout.fillWidth: true; text: manager.updateStatus; textFormat: Text.PlainText; wrapMode: Text.Wrap; opacity: 0.7 }
        Kirigami.InlineMessage { Layout.fillWidth: true; visible: manager.error.length > 0; type: Kirigami.MessageType.Error; text: manager.error }
        Controls.Label { Layout.fillWidth: true; visible: manager.notice.length > 0; text: manager.notice; textFormat: Text.PlainText; wrapMode: Text.Wrap; maximumLineCount: 5; elide: Text.ElideRight }
        RowLayout {
            Layout.fillWidth: true
            Controls.Label { text: i18n("Store:") }
            Controls.ComboBox {
                id: storeChooser
                Layout.preferredWidth: 350
                model: manager.gpgAvailable ? [i18n("Certificate catalogue"), i18n("System trust"), i18n("GnuPG S/MIME (Kleopatra)"), ...manager.profiles] : [i18n("Certificate catalogue"), i18n("System trust"), ...manager.profiles]
                enabled: !manager.busy
                onActivated: manager.selectStore(currentIndex === 0 ? "catalogue" : currentIndex === 1 ? "system" : manager.gpgAvailable && currentIndex === 2 ? "gpgsm" : manager.profiles[currentIndex - (manager.gpgAvailable ? 3 : 2)])
            }
            Controls.TextField { id: search; Layout.fillWidth: true; placeholderText: i18n("Search name, issuer or fingerprint") }
            Controls.BusyIndicator { running: manager.busy; visible: running; Layout.preferredWidth: 30; Layout.preferredHeight: 30 }
        }
        RowLayout {
            visible: manager.store !== "gpgsm" && manager.store !== "preview"
            Layout.fillWidth: true
            Controls.ComboBox { id: groupChooser; model: manager.groups; Layout.preferredWidth: 180; enabled: !manager.busy }
            Controls.Button { text: i18n("Install Group…"); enabled: !manager.busy; onClicked: { changeDialog.installing = true; changeDialog.open() } }
            Controls.Button { text: i18n("Remove Group…"); enabled: !manager.busy; onClicked: { changeDialog.installing = false; changeDialog.open() } }
            Controls.Button { visible: manager.gpgAvailable; text: i18n("Kleopatra…"); enabled: !manager.busy; onClicked: gpgDialog.open() }
            Item { Layout.fillWidth: true }
            Controls.Label { text: i18np("One certificate", "%1 certificates", manager.certificates.length) }
        }
        Controls.ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            ListView {
                id: certificates
                clip: true
                model: manager.certificates
                delegate: Controls.ItemDelegate {
                    required property var modelData
                    width: ListView.view.width
                    visible: search.text.length === 0 || (modelData.name + modelData.issuer + modelData.sha256).toLowerCase().includes(search.text.toLowerCase())
                    height: visible ? implicitHeight : 0
                    text: modelData.name + "\n" + modelData.issuer + " · " + page.stateLabel(modelData.state) + " · " + modelData.expires
                    contentItem: Controls.Label { text: parent.text; textFormat: Text.PlainText; elide: Text.ElideRight }
                    highlighted: page.selected.sha256 === modelData.sha256
                    onClicked: page.selected = modelData
                    Accessible.name: text
                }
            }
        }
        Kirigami.Separator { Layout.fillWidth: true }
        Controls.Label {
            Layout.fillWidth: true
            visible: page.selected.sha256 !== undefined
            text: i18n("SHA-256: %1\nIssuer: %2\nExpires: %3\n%4", page.selected.sha256 || "", page.selected.issuer || "", page.selected.expires || "", page.selected.note || page.selected.installationIssue || "")
            wrapMode: Text.WrapAnywhere
            textFormat: Text.PlainText
        }
        RowLayout {
            visible: manager.store === "gpgsm" && manager.kleopatraAvailable && page.selected.issuer !== undefined
            Controls.Button { text: i18n("Open in Kleopatra"); onClicked: manager.openKleopatra(page.selected.issuer) }
        }
        RowLayout {
            objectName: "tokenActions"
            Layout.fillWidth: true
            Controls.Button { text: i18n("Detect Tokens"); enabled: !manager.busy; onClicked: manager.tokens() }
            Controls.Button { text: i18n("Register Token Module…"); enabled: !manager.busy; onClicked: tokenDialog.open() }
            Controls.Label { Layout.fillWidth: true; text: i18n("A3 PINs are not stored. Install vendor middleware locally through APTus when required."); wrapMode: Text.Wrap }
        }
    }
    function stateLabel(state) {
        if (state === "valid") return i18n("Within validity dates")
        if (state === "expired") return i18n("Expired")
        if (state === "revoked") return i18n("Revoked")
        if (state === "not-yet-valid") return i18n("Not yet valid")
        if (state === "confirmed by you") return i18n("Trusted: you confirmed it")
        if (state === "not confirmed") return i18n("Imported, not trusted yet")
        if (state === "through its root") return i18n("Trusted through its root")
        return i18n("Invalid")
    }
    Controls.Dialog {
        id: changeDialog
        property bool installing: true
        title: installing ? i18n("Install chosen group") : i18n("Remove chosen group")
        modal: true
        anchors.centerIn: parent
        standardButtons: Controls.Dialog.Ok | Controls.Dialog.Cancel
        onAccepted: { manager.changeGroup(groupChooser.currentText, installing, allowE521.checked, changePassword.text); changePassword.clear() }
        ColumnLayout {
            Controls.Label { text: i18n("Group: %1", groupChooser.currentText) }
            Controls.Label { Layout.preferredWidth: 480; wrapMode: Text.Wrap; text: manager.store === "catalogue" || manager.store === "system" ? i18n("This changes system trust and requests administrator authorization. Expired and revoked catalogue entries are excluded.") : i18n("Close this browser before changing its NSS database.") }
            Controls.CheckBox { id: allowE521; visible: manager.store === "system" || manager.store === "catalogue"; text: i18n("Choose Ed521 certificates when native chain verification is unavailable") }
            Controls.TextField { id: changePassword; visible: manager.store !== "catalogue" && manager.store !== "system"; echoMode: TextInput.Password; placeholderText: i18n("NSS database password") }
        }
    }
    Controls.Dialog {
        id: importDialog
        title: i18n("Preview or import personal certificate")
        modal: true
        anchors.centerIn: parent
        standardButtons: Controls.Dialog.Close
        ColumnLayout {
            Controls.Label { Layout.preferredWidth: 540; wrapMode: Text.WrapAnywhere; text: page.chosenFile.toString() }
            Controls.TextField { id: personalPassword; Layout.fillWidth: true; echoMode: TextInput.Password; placeholderText: i18n("PKCS#12 passphrase (for .p12 or .pfx)") }
            Controls.Button { text: i18n("Preview"); onClicked: { manager.preview(page.chosenFile, personalPassword.text); importDialog.close(); personalPassword.clear() } }
            Kirigami.Separator { Layout.fillWidth: true }
            Controls.ComboBox { id: targetProfile; Layout.fillWidth: true; model: manager.profiles }
            Controls.Label { Layout.preferredWidth: 540; wrapMode: Text.Wrap; text: i18n("Okular can sign with a supported identity from this NSS directory. Browser TLS trust does not grant PDF certificate trust; that requires a separate S/MIME trust decision in NSS.") }
            Controls.TextField { id: databasePassword; Layout.fillWidth: true; echoMode: TextInput.Password; placeholderText: i18n("NSS database password") }
            Controls.CheckBox { id: remember; checked: false; text: i18n("Save A1 and NSS passwords in KDE Wallet") }
            Controls.Label { Layout.preferredWidth: 540; wrapMode: Text.Wrap; text: i18n("Close the browser before import. Private keys remain in its NSS database. A3 PINs are never saved here.") }
            RowLayout {
                Controls.Button { text: i18n("Import A1"); enabled: !manager.busy; onClicked: { manager.importIdentity(page.chosenFile, targetProfile.currentText, personalPassword.text, databasePassword.text, remember.checked); personalPassword.clear(); databasePassword.clear(); importDialog.close() } }
                Controls.Button { text: i18n("Read from Wallet"); onClicked: { const saved = manager.rememberedPasswords(page.chosenFile, targetProfile.currentText); personalPassword.text = saved.password || ""; databasePassword.text = saved.databasePassword || "" } }
                Controls.Button { text: i18n("Forget Saved Passwords"); onClicked: manager.forgetPasswords(page.chosenFile, targetProfile.currentText) }
            }
        }
        onRejected: { personalPassword.clear(); databasePassword.clear() }
    }
    Controls.Dialog {
        id: gpgDialog
        title: i18n("Kleopatra / GnuPG S/MIME")
        modal: true
        anchors.centerIn: parent
        standardButtons: Controls.Dialog.Close
        ColumnLayout {
            Controls.Label { Layout.preferredWidth: 480; wrapMode: Text.Wrap; text: i18n("Import the chosen group's certificates, with the chain up to their roots, into gpgsm so that Kleopatra and KMail see them. Nothing is trusted by importing. You decide about each root yourself, in Kleopatra or when gpgsm asks. Ed521 certificates are not imported because gpgsm cannot validate them.") }
            Controls.Button { text: i18n("Import Chosen Group"); onClicked: { manager.gpgImport(groupChooser.currentText); gpgDialog.close() } }
            Controls.Button { text: i18n("Show What Was Imported"); onClicked: { manager.selectStore("gpgsm"); gpgDialog.close() } }
            Controls.Button { text: i18n("Ask gpgsm About Imported Roots"); onClicked: { manager.gpgConfirm(); gpgDialog.close() } }
            Controls.Button { text: i18n("Remove What We Imported"); onClicked: { manager.gpgRemove(groupChooser.currentText); gpgDialog.close() } }
        }
    }
    Controls.Dialog {
        id: tokenDialog
        title: i18n("Register a PKCS#11 module")
        modal: true
        anchors.centerIn: parent
        standardButtons: Controls.Dialog.Ok | Controls.Dialog.Cancel
        onAccepted: { manager.registerModule(tokenProfile.currentText, modulePath.text, tokenDatabasePassword.text); tokenDatabasePassword.clear() }
        ColumnLayout {
            Controls.Label { Layout.preferredWidth: 500; wrapMode: Text.Wrap; text: i18n("Close the browser first. Choose the installed p11-kit proxy to expose configured token modules. Loading a module runs its code as your user.") }
            Controls.ComboBox { id: tokenProfile; Layout.fillWidth: true; model: manager.profiles }
            Controls.TextField { id: modulePath; Layout.fillWidth: true; placeholderText: i18n("Absolute path to p11-kit-proxy.so") }
            Controls.Button { text: i18n("Inspect This Module"); enabled: !manager.busy; onClicked: { manager.tokens(modulePath.text); tokenDialog.close() } }
            Controls.TextField { id: tokenDatabasePassword; Layout.fillWidth: true; echoMode: TextInput.Password; placeholderText: i18n("NSS database password") }
            Controls.Button { text: i18n("Remove Our Module Registration"); enabled: !manager.busy; onClicked: { manager.unregisterModule(tokenProfile.currentText); tokenDialog.close(); tokenDatabasePassword.clear() } }
        }
    }
}
