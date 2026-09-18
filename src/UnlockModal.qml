import QtQuick

// Asks for the master password (KeePassXC, Bitwarden) or the GPG passphrase
// (pass) of the database about to be opened. A Bitwarden account with a PIN
// set opens on the PIN instead, with Tab switching to the master password.
Modal {
    id: root

    property string databaseName: ""
    property string errorText: ""
    property bool busy: false
    // A PIN is stored for this database; it is asked for first.
    property bool pinAvailable: false

    property bool usingPin: pinAvailable

    signal submitted(string password)
    signal pinSubmitted(string pin)

    accentColor: errorText.length > 0 ? theme.alertError : theme.alertInfo
    heading: i18n.t("db_app.unlock_title", { "db": databaseName })
    hint: busy ? i18n.t("db_app.unlocking")
               : errorText.length > 0 ? errorText
               : usingPin ? i18n.t("pin.footer")
               : i18n.t("common.footer_confirm_cancel")
    hintColor: errorText.length > 0 ? theme.alertError : theme.guidance

    capturesKeys: false

    onShown: {
        root.usingPin = root.pinAvailable;
        passwordField.text = "";
        pinField.text = "";
        focusCurrentField();
    }

    // A PIN removed after too many wrong tries (or a stale one) takes the
    // sheet back to the master password without it having to be reopened.
    onPinAvailableChanged: {
        root.usingPin = root.pinAvailable;
        focusCurrentField();
    }

    function focusCurrentField() {
        if (root.usingPin)
            pinField.field.forceActiveFocus();
        else
            passwordField.field.forceActiveFocus();
    }

    function useMasterPassword() {
        if (!root.usingPin)
            return;
        root.usingPin = false;
        focusCurrentField();
    }

    // A failed attempt clears the box and puts the cursor back, so the next
    // try starts clean without a trip to the mouse.
    onErrorTextChanged: {
        if (errorText.length > 0) {
            passwordField.text = "";
            pinField.text = "";
            focusCurrentField();
        }
    }

    Field {
        id: pinField
        width: parent.width
        visible: root.usingPin
        label: i18n.t("pin.label")
        echoMode: TextInput.Password
        enabled: !root.busy

        onSubmitted: root.pinSubmitted(text)
        onCancelled: root.dismissed()
        // Tab, next and previous all mean the same thing here: give up on
        // the PIN and type the master password.
        onNextRequested: root.useMasterPassword()
        onPreviousRequested: root.useMasterPassword()
    }

    Field {
        id: passwordField
        width: parent.width
        visible: !root.usingPin
        label: i18n.t("common.password_label")
        echoMode: TextInput.Password
        enabled: !root.busy

        onSubmitted: root.submitted(text)
        onCancelled: root.dismissed()
    }
}
