import QtQuick

// Logs into a Bitwarden account. Two shapes: server, e-mail and master
// password first, then — only if the account asks for one — a single code (two-step
// login or new-device verification). The step comes from the controller,
// which follows what `bw login` is actually prompting for.
Modal {
    id: root

    property string step: "credentials"
    // bitwarden.com, the EU cloud or a server of your own (Vaultwarden,
    // self-hosted Bitwarden); comes filled with where bw points now.
    property string server: "bitwarden.com"
    property string email: ""
    property string errorText: ""
    property bool busy: false

    readonly property bool askingCode: step === "code" || step === "deviceCode"

    signal credentialsSubmitted(string server, string email, string password)
    signal codeSubmitted(string code)

    heading: i18n.t("bitwarden.login_title")
    hint: busy ? i18n.t("bitwarden.logging_in")
               : errorText.length > 0 ? errorText
               : step === "deviceCode" ? i18n.t("bitwarden.device_code_hint")
               : step === "code" ? i18n.t("bitwarden.code_hint")
               : i18n.t("common.footer_confirm_cancel")
    hintColor: errorText.length > 0 ? theme.alertError : theme.guidance
    accentColor: errorText.length > 0 ? theme.alertError : theme.alertInfo

    capturesKeys: false

    function focusFirstField() {
        if (root.askingCode) {
            codeField.text = "";
            codeField.field.forceActiveFocus();
        } else if (serverField.text.trim().length === 0) {
            serverField.field.forceActiveFocus();
        } else if (emailField.text.length === 0) {
            emailField.field.forceActiveFocus();
        } else {
            passwordField.field.forceActiveFocus();
        }
    }

    onShown: {
        serverField.text = root.server;
        emailField.text = root.email;
        passwordField.text = "";
        codeField.text = "";
        focusFirstField();
    }

    onStepChanged: if (visible) focusFirstField()
    onBusyChanged: if (visible && !busy) focusFirstField()

    // A failed attempt clears the secret and puts the cursor back on it.
    onErrorTextChanged: {
        if (errorText.length > 0) {
            passwordField.text = "";
            focusFirstField();
        }
    }

    function submitCredentials() {
        if (serverField.text.trim().length === 0)
            serverField.field.forceActiveFocus();
        else if (emailField.text.trim().length === 0)
            emailField.field.forceActiveFocus();
        else if (passwordField.text.length === 0)
            passwordField.field.forceActiveFocus();
        else
            root.credentialsSubmitted(serverField.text, emailField.text, passwordField.text);
    }

    Field {
        id: serverField
        objectName: "serverField"
        width: parent.width
        visible: !root.askingCode
        label: i18n.t("bitwarden.server_label")
        enabled: !root.busy

        onSubmitted: emailField.field.forceActiveFocus()
        onNextRequested: emailField.field.forceActiveFocus()
        onPreviousRequested: passwordField.field.forceActiveFocus()
        onCancelled: root.dismissed()
    }

    Field {
        id: emailField
        objectName: "emailField"
        width: parent.width
        visible: !root.askingCode
        label: i18n.t("bitwarden.email_label")
        enabled: !root.busy

        onSubmitted: passwordField.field.forceActiveFocus()
        onNextRequested: passwordField.field.forceActiveFocus()
        onPreviousRequested: serverField.field.forceActiveFocus()
        onCancelled: root.dismissed()
    }

    Field {
        id: passwordField
        objectName: "passwordField"
        width: parent.width
        visible: !root.askingCode
        label: i18n.t("bitwarden.master_password_label")
        echoMode: TextInput.Password
        enabled: !root.busy

        onSubmitted: root.submitCredentials()
        onNextRequested: serverField.field.forceActiveFocus()
        onPreviousRequested: emailField.field.forceActiveFocus()
        onCancelled: root.dismissed()
    }

    Field {
        id: codeField
        width: parent.width
        visible: root.askingCode
        label: root.step === "deviceCode" ? i18n.t("bitwarden.device_code_label")
                                          : i18n.t("bitwarden.code_label")
        enabled: !root.busy

        onSubmitted: if (text.trim().length > 0) root.codeSubmitted(text)
        onCancelled: root.dismissed()
    }
}
