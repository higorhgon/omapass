import QtQuick

// Turns PIN unlock on for a Bitwarden account: the master password is kept
// in the system keyring, encrypted with a key derived from the PIN, so the
// password has to be typed once here. A short PIN is accepted, but the
// warning below says in as many words how little it protects.
Modal {
    id: root

    property bool busy: false

    signal submitted(string masterPassword, string pin)

    readonly property string warning: controller.pinWeakWarning(pinField.text)

    heading: i18n.t("bitwarden.pin_setup_title")
    hint: i18n.t("bitwarden.pin_setup_footer")
    cardWidth: Math.round(480 * s)

    capturesKeys: false

    onShown: {
        revealPassword.checked = false;
        revealPin.checked = false;
        passwordField.text = "";
        pinField.text = "";
        confirmField.text = "";
        passwordField.field.forceActiveFocus();
    }

    function submit() {
        if (passwordField.text.length === 0) {
            passwordField.field.forceActiveFocus();
            return;
        }
        const invalid = controller.validatePin(pinField.text, confirmField.text);
        if (invalid.length > 0) {
            controller.showMessage(invalid, true);
            pinField.field.forceActiveFocus();
            return;
        }
        root.submitted(passwordField.text, pinField.text);
    }

    Field {
        id: passwordField
        width: parent.width
        label: i18n.t("bitwarden.master_password_label")
        echoMode: revealPassword.checked ? TextInput.Normal : TextInput.Password
        enabled: !root.busy

        onSubmitted: pinField.field.forceActiveFocus()
        onNextRequested: pinField.field.forceActiveFocus()
        onPreviousRequested: confirmField.field.forceActiveFocus()
        onCancelled: root.dismissed()
    }

    RevealBox {
        id: revealPassword
    }

    Field {
        id: pinField
        width: parent.width
        label: i18n.t("bitwarden.pin_label")
        echoMode: revealPin.checked ? TextInput.Normal : TextInput.Password
        field.inputMethodHints: Qt.ImhDigitsOnly
        enabled: !root.busy

        onSubmitted: confirmField.field.forceActiveFocus()
        onNextRequested: confirmField.field.forceActiveFocus()
        onPreviousRequested: passwordField.field.forceActiveFocus()
        onCancelled: root.dismissed()
    }

    Field {
        id: confirmField
        width: parent.width
        label: i18n.t("bitwarden.pin_confirm_label")
        echoMode: revealPin.checked ? TextInput.Normal : TextInput.Password
        field.inputMethodHints: Qt.ImhDigitsOnly
        enabled: !root.busy

        onSubmitted: root.submit()
        onNextRequested: passwordField.field.forceActiveFocus()
        onPreviousRequested: pinField.field.forceActiveFocus()
        onCancelled: root.dismissed()
    }

    RevealBox {
        id: revealPin
        text: i18n.t("bitwarden.pin_show")
    }

    Text {
        width: parent.width
        visible: root.warning.length > 0
        text: root.warning
        color: theme.alertWarn
        wrapMode: Text.WordWrap
        font.pixelSize: Math.round(12 * root.s)
    }
}
