import QtQuick

// First stage: pick a database, then unlock it. Also where new KeePassXC
// databases and pass stores are created, and Bitwarden and 1Password
// accounts logged into.
FocusScope {
    id: page

    property string mode: controller.anyDatabaseFound ? "list" : "confirmCreate"

    readonly property bool unlocking: Object.keys(controller.pendingDatabase).length > 0
    readonly property bool loggingIn: controller.loginStep.length > 0

    // Ctrl+C keeps its clipboard meaning wherever text is being typed, and
    // only quits from the plain list.
    Binding {
        target: window
        property: "editingText"
        value: page.mode !== "list" || page.loggingIn || pane.typing
    }

    ListPane {
        id: pane
        anchors.fill: parent
        focus: !page.unlocking && !page.loggingIn && page.mode === "list"
        acceptsKeys: !page.unlocking && !page.loggingIn && page.mode === "list"

        searchPlaceholder: i18n.t("db_app.filter_title")
        model: controller.databases
        tagFor: function(item) { return "[" + item.kind + "]"; }
        onQueryChanged: controller.databaseQuery = query

        footerText: controller.hasMessage ? controller.message
                  : page.mode === "list" ? (searchMode ? i18n.t("db_app.footer_search")
                                                       : i18n.t("db_app.footer_normal"))
                  : ""
        footerColor: controller.hasMessage
            ? (controller.messageIsError ? theme.alertError : theme.alertInfo)
            : theme.guidance

        onActivated: function(index) { controller.selectDatabase(index); }
        onAddRequested: page.mode = "chooseType"
        onDeleteRequested: {
            if (controller.isBitwardenDatabase(currentIndex))
                page.mode = "confirmLogout";
            else if (controller.isOnePasswordDatabase(currentIndex))
                page.mode = "confirmLogoutOp";
        }
        onHelpRequested: page.mode = "help"
        onQuitRequested: Qt.quit()
    }

    ConfirmModal {
        visible: page.mode === "confirmCreate"
        accentColor: theme.alertWarn
        question: i18n.t("db_app.no_db_found_confirm")

        onAccepted: page.mode = "chooseType"
        onDismissed: Qt.quit()
    }

    // Built as a list rather than written out, so a backend whose CLI is not
    // installed simply drops out without shifting what the others do.
    ChoiceModal {
        id: typeChoice

        readonly property var choices: {
            const list = [{"label": "KeePassXC (.kdbx)", "action": "createDb"},
                          {"label": "pass", "action": "createPass"}];
            if (controller.bitwardenAvailable)
                list.push({"label": "Bitwarden", "action": "bitwarden"});
            if (controller.onePasswordAvailable)
                list.push({"label": "1Password", "action": "onepassword"});
            return list;
        }

        visible: page.mode === "chooseType"
        heading: i18n.t("db_app.new_db_title")
        hint: i18n.t("db_app.footer_choose_type")
        cardWidth: Math.round(360 * window.s)
        options: choices.map(function(choice) { return choice.label; })

        onChosen: function(index) {
            const action = typeChoice.choices[index].action;
            if (action === "bitwarden") {
                page.mode = "list";
                controller.addBitwardenAccount();
            } else if (action === "onepassword") {
                page.mode = "list";
                controller.addOnePasswordAccount();
            } else {
                page.mode = action;
            }
        }
        onDismissed: page.mode = controller.anyDatabaseFound ? "list" : "confirmCreate"
    }

    CreateDatabaseModal {
        visible: page.mode === "createDb"
        busy: controller.busy
        errorText: controller.unlockError

        onSubmitted: function(name, password) { controller.createKeepassDatabase(name, password); }
        onDismissed: page.mode = "chooseType"
    }

    CreatePassStoreModal {
        visible: page.mode === "createPass"
        busy: controller.busy
        errorText: controller.unlockError

        onSubmitted: function(directory, keyId) { controller.createPassStore(directory, keyId); }
        onDismissed: page.mode = "chooseType"
    }

    LoginModal {
        visible: controller.loginStep === "credentials" || controller.loginStep === "code"
                 || controller.loginStep === "deviceCode"
        step: controller.loginStep
        email: controller.loginEmail
        errorText: controller.unlockError
        busy: controller.busy

        onCredentialsSubmitted: function(email, password) { controller.bitwardenLogin(email, password); }
        onCodeSubmitted: function(code) { controller.sendBitwardenCode(code); }
        onDismissed: controller.cancelBitwardenLogin()
    }

    OnePasswordLoginModal {
        visible: controller.loginStep === "opCredentials" || controller.loginStep === "opCode"
        step: controller.loginStep
        email: controller.loginEmail
        errorText: controller.unlockError
        busy: controller.busy

        onCredentialsSubmitted: function(address, email, secretKey, password) {
            controller.onePasswordLogin(address, email, secretKey, password);
        }
        onCodeSubmitted: function(code) { controller.sendOnePasswordCode(code); }
        onDismissed: controller.cancelOnePasswordLogin()
    }

    // Shown when the account has several two-step methods: bw would ask with
    // a menu of its own, so the choice is made here and bw is started again
    // with it. The values are bw's TwoFactorProviderType.
    ChoiceModal {
        readonly property var methods: [0, 1, 3]

        visible: controller.loginStep === "method"
        heading: i18n.t("bitwarden.method_title")
        hint: controller.busy ? i18n.t("bitwarden.logging_in") : i18n.t("db_app.footer_choose_type")
        cardWidth: Math.round(360 * window.s)
        options: [i18n.t("bitwarden.method_authenticator"), i18n.t("bitwarden.method_email"),
                  i18n.t("bitwarden.method_yubikey")]

        onChosen: function(index) { controller.chooseBitwardenMethod(methods[index]); }
        onDismissed: controller.cancelBitwardenLogin()
    }

    ConfirmModal {
        visible: page.mode === "confirmLogout"
        accentColor: theme.alertWarn
        question: i18n.t("bitwarden.logout_confirm")

        onAccepted: {
            page.mode = "list";
            controller.logoutBitwarden();
        }
        onDismissed: page.mode = "list"
    }

    ConfirmModal {
        visible: page.mode === "confirmLogoutOp"
        accentColor: theme.alertWarn
        question: i18n.t("onepassword.logout_confirm")

        onAccepted: {
            page.mode = "list";
            controller.logoutOnePassword();
        }
        onDismissed: page.mode = "list"
    }

    UnlockModal {
        visible: page.unlocking
        databaseName: controller.pendingDatabase.name || ""
        errorText: controller.unlockError
        busy: controller.busy
        pinAvailable: controller.pinAvailable

        onSubmitted: function(password) { controller.unlock(password); }
        onPinSubmitted: function(pin) { controller.unlockWithPin(pin); }
        onDismissed: {
            controller.cancelUnlock();
            page.mode = "list";
        }
    }

    HelpModal {
        visible: page.mode === "help"
        sections: [
            {
                "title": i18n.t("help.nav_section"),
                "items": [["j/k, ↑/↓", i18n.t("help.move_selection")],
                          ["gg / G", i18n.t("help.go_top_bottom")],
                          ["CTRL-U/D", i18n.t("help.half_page")],
                          ["CTRL-N/P", i18n.t("help.next_prev")]]
            },
            {
                "title": i18n.t("help.actions_section"),
                "items": [["ENTER", i18n.t("db_app.help_select_db")],
                          ["CTRL-A", i18n.t("db_app.help_create_new_db")],
                          ["CTRL-X", i18n.t("db_app.help_logout")]]
            },
            {
                "title": i18n.t("help.search_section"),
                "items": [["/, f, i", i18n.t("help.enter_search")],
                          ["ESC", i18n.t("db_app.help_exit_search")]]
            },
            {
                "title": i18n.t("help.general_section"),
                "items": [["CTRL+?", i18n.t("help.this_help")],
                          ["CTRL-O", i18n.t("settings.help")],
                          ["CTRL-C, CTRL-Q", i18n.t("help.quit_app")]]
            }
        ]

        onDismissed: page.mode = "list"
    }

    // A database created here opens straight away, so the creation sheet
    // steps aside as soon as it succeeds.
    Connections {
        target: controller

        function onDatabaseCreated() {
            page.mode = "list";
        }
    }
}
