import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs

// The settings that can change while omapass is running, read from and
// written back to config.toml. Theme and language are not here: they are
// read once at start-up, so changing them from the sheet would only look
// like it worked.
Modal {
    id: root

    property string wordlist: "auto"
    property string wordlistInUse: ""
    property string configPath: ""

    signal submitted(var values)

    heading: i18n.t("settings.title")
    hint: i18n.t("settings.footer")
    cardWidth: Math.round(620 * s)

    capturesKeys: false

    onShown: {
        const values = controller.settings();
        pathField.text = values.path;
        recencyBox.checked = values.recency;
        lockBox.checked = values.lockEnabled;
        lockField.text = String(values.lockMinutes);
        root.wordlist = values.wordlist;
        root.wordlistInUse = values.wordlistInUse;
        root.configPath = values.configPath;
        wordlistField.text = values.wordlist;
        refreshPaths();
        pathField.field.forceActiveFocus();
    }

    function refreshPaths() {
        pathSuggestions.model = controller.directorySuggestions(pathField.text);
        pathSuggestions.currentIndex = 0;
    }

    function submit() {
        root.submitted({
            "path": pathField.text,
            "recency": recencyBox.checked,
            "lockEnabled": lockBox.checked,
            "lockMinutes": parseInt(lockField.text) || 10,
            "wordlist": wordlistField.text
        });
    }

    // Picking a file copies it into omapass' own directory, so the list
    // keeps working even if the original is moved or deleted.
    FileDialog {
        id: wordlistDialog
        title: i18n.t("settings.wordlist_pick")
        nameFilters: [i18n.t("settings.wordlist_filter"), i18n.t("settings.all_files")]

        onAccepted: {
            const imported = controller.importWordlist(selectedFile);
            if (imported.length > 0)
                wordlistField.text = imported;
        }
    }

    Shortcut {
        sequences: ["Ctrl+F"]
        enabled: root.visible
        onActivated: wordlistDialog.open()
    }

    Field {
        id: pathField
        width: parent.width
        label: i18n.t("settings.path_label")

        onTextChanged: root.refreshPaths()
        onSubmitted: root.submit()
        onCancelled: root.dismissed()
        onNextRequested: lockField.field.forceActiveFocus()
        onPreviousRequested: wordlistField.field.forceActiveFocus()
        onListNext: pathSuggestions.next()
        onListPrevious: pathSuggestions.previous()
    }

    SuggestionList {
        id: pathSuggestions
        width: parent.width

        onPicked: {
            pathField.text = pathSuggestions.model[pathSuggestions.currentIndex];
            root.refreshPaths();
        }
    }

    CheckOption {
        id: recencyBox
        text: i18n.t("settings.recency")
    }

    CheckOption {
        id: lockBox
        text: i18n.t("settings.lock_enabled")
    }

    Field {
        id: lockField
        width: parent.width
        visible: lockBox.checked
        label: i18n.t("settings.lock_minutes_label")
        field.inputMethodHints: Qt.ImhDigitsOnly

        onSubmitted: root.submit()
        onCancelled: root.dismissed()
        onNextRequested: wordlistField.field.forceActiveFocus()
        onPreviousRequested: pathField.field.forceActiveFocus()
    }

    Field {
        id: wordlistField
        width: parent.width
        label: i18n.t("settings.wordlist_label")

        onSubmitted: root.submit()
        onCancelled: root.dismissed()
        onNextRequested: pathField.field.forceActiveFocus()
        onPreviousRequested: lockBox.checked ? lockField.field.forceActiveFocus()
                                             : pathField.field.forceActiveFocus()
    }

    Text {
        width: parent.width
        text: root.wordlistInUse.length > 0
            ? i18n.t("settings.wordlist_in_use", { "path": root.wordlistInUse })
            : i18n.t("generator.no_wordlist")
        color: root.wordlistInUse.length > 0 ? theme.guidance : theme.alertWarn
        wrapMode: Text.WrapAnywhere
        font.pixelSize: Math.round(11 * root.s)
    }

    Text {
        width: parent.width
        text: i18n.t("settings.config_path", { "path": root.configPath })
        color: theme.guidance
        wrapMode: Text.WrapAnywhere
        font.pixelSize: Math.round(11 * root.s)
    }
}
