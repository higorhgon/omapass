import QtQuick

// Adds a 1Password account. `op` needs four things the first time — the
// sign-in address, the e-mail, the Secret Key and the master password — and
// then, only if the account asks for one, a two-step code. The step comes
// from the controller, which follows what `op account add` is prompting for.
Modal {
    id: root

    property string step: "opCredentials"
    // 1Password's own default, which is what most accounts use.
    property string address: "my.1password.com"
    property string email: ""
    property string errorText: ""
    property bool busy: false

    readonly property bool askingCode: step === "opCode"

    signal credentialsSubmitted(string address, string email, string secretKey, string password,
                                string shorthand)
    signal codeSubmitted(string code)

    heading: i18n.t("onepassword.login_title")
    hint: busy ? i18n.t("onepassword.logging_in")
               : errorText.length > 0 ? errorText
               : root.askingCode ? i18n.t("onepassword.code_hint")
               : i18n.t("onepassword.login_footer")
    hintColor: errorText.length > 0 ? theme.alertError : theme.guidance
    accentColor: errorText.length > 0 ? theme.alertError : theme.alertInfo
    cardWidth: Math.round(520 * s)

    capturesKeys: false

    // Through Qt.callLater because the step, the busy flag and the modal's
    // own opening land in whatever order they land: focusing at the end of
    // the cycle is the only moment all three are settled.
    function focusLater() {
        Qt.callLater(focusFirstField);
    }

    function focusFirstField() {
        if (root.step === "opCode") {
            codeField.text = "";
            codeField.field.forceActiveFocus();
        } else if (addressField.text.length === 0) {
            addressField.field.forceActiveFocus();
        } else if (emailField.text.length === 0) {
            emailField.field.forceActiveFocus();
        } else {
            secretKeyField.field.forceActiveFocus();
        }
    }

    onShown: {
        addressField.text = root.address;
        emailField.text = root.email;
        shorthandField.text = "";
        secretKeyField.text = "";
        passwordField.text = "";
        codeField.text = "";
        focusLater();
    }

    onStepChanged: if (visible) focusLater()
    onBusyChanged: if (visible && !busy) focusLater()

    // A failed attempt clears the secrets and puts the cursor back on the
    // first field that is still empty.
    onErrorTextChanged: {
        if (errorText.length > 0) {
            secretKeyField.text = "";
            passwordField.text = "";
            focusLater();
        }
    }

    function submitCredentials() {
        if (addressField.text.trim().length === 0)
            addressField.field.forceActiveFocus();
        else if (emailField.text.trim().length === 0)
            emailField.field.forceActiveFocus();
        else if (secretKeyField.text.trim().length === 0)
            secretKeyField.field.forceActiveFocus();
        else if (passwordField.text.length === 0)
            passwordField.field.forceActiveFocus();
        else
            root.credentialsSubmitted(addressField.text, emailField.text, secretKeyField.text,
                                      passwordField.text, shorthandField.text);
    }

    Field {
        id: addressField
        width: parent.width
        visible: !root.askingCode
        label: i18n.t("onepassword.address_label")
        enabled: !root.busy

        onSubmitted: emailField.field.forceActiveFocus()
        onNextRequested: emailField.field.forceActiveFocus()
        onPreviousRequested: passwordField.field.forceActiveFocus()
        onCancelled: root.dismissed()
    }

    Field {
        id: emailField
        width: parent.width
        visible: !root.askingCode
        label: i18n.t("onepassword.email_label")
        enabled: !root.busy

        onSubmitted: secretKeyField.field.forceActiveFocus()
        onNextRequested: secretKeyField.field.forceActiveFocus()
        onPreviousRequested: addressField.field.forceActiveFocus()
        onCancelled: root.dismissed()
    }

    Field {
        id: secretKeyField
        width: parent.width
        visible: !root.askingCode
        label: i18n.t("onepassword.secret_key_label")
        echoMode: TextInput.Password
        enabled: !root.busy

        onSubmitted: passwordField.field.forceActiveFocus()
        onNextRequested: passwordField.field.forceActiveFocus()
        onPreviousRequested: emailField.field.forceActiveFocus()
        onCancelled: root.dismissed()
    }

    Field {
        id: passwordField
        width: parent.width
        visible: !root.askingCode
        label: i18n.t("onepassword.master_password_label")
        echoMode: TextInput.Password
        enabled: !root.busy

        onSubmitted: shorthandField.field.forceActiveFocus()
        onNextRequested: shorthandField.field.forceActiveFocus()
        onPreviousRequested: secretKeyField.field.forceActiveFocus()
        onCancelled: root.dismissed()
    }

    Field {
        id: shorthandField
        width: parent.width
        visible: !root.askingCode
        label: i18n.t("onepassword.shorthand_label")
        placeholderText: i18n.t("onepassword.shorthand_hint")
        enabled: !root.busy

        onSubmitted: root.submitCredentials()
        onNextRequested: addressField.field.forceActiveFocus()
        onPreviousRequested: passwordField.field.forceActiveFocus()
        onCancelled: root.dismissed()
    }

    Field {
        id: codeField
        width: parent.width
        visible: root.askingCode
        label: i18n.t("onepassword.code_label")
        enabled: !root.busy

        onSubmitted: if (text.trim().length > 0) root.codeSubmitted(text)
        onCancelled: root.dismissed()
    }
}
