import QtQuick
import QtQuick.Controls

// Generates a password (or a diceware passphrase) in-process, which
// answers in milliseconds — so every change to the options regenerates right
// away and what you see is what you get.
//
// Opened from the entry form it fills the password field, which is what
// `fillMode` switches. Anywhere else (with or without a database open) it
// copies and stays open: the clipboard is wiped after a few seconds, and a
// password pasted into a site that then has to be typed again would be lost
// if the sheet had gone with it.
//
// The options are KeePassXC's: the letter and number classes, the symbols in
// its six groups, extended ASCII, characters to draw from as well, and
// whether every group must show up.
Modal {
    id: root

    property bool fillMode: false
    readonly property bool passphrase: modeTabs.currentIndex === 1
    property string password: ""
    property real entropy: 0
    property string quality: ""
    property bool passphraseAvailable: false
    // The password on show is the one last copied.
    property bool copied: false
    // Set while the fields are being filled from the stored options, so
    // their onTextChanged does not regenerate once per field.
    property bool loading: false

    signal accepted(string password)

    heading: i18n.t("generator.title")
    acceptText: fillMode ? i18n.t("generator.use") : i18n.t("common.copy")
    cancelText: fillMode ? i18n.t("common.cancel") : i18n.t("common.close")
    acceptEnabled: root.password.length > 0
    cardWidth: Math.round(600 * s)

    onAcceptRequested: root.submit()

    // Enter and the main button: hand the password to the form, or copy it
    // and leave the sheet open.
    function submit() {
        if (root.password.length === 0)
            return;
        if (root.fillMode) {
            root.accepted(root.password);
            return;
        }
        root.copyPassword();
    }

    // Ctrl+C, in either mode: copies and leaves the sheet as it is.
    function copyPassword() {
        if (root.password.length === 0)
            return;
        controller.copySecret(root.password);
        root.copied = true;
    }

    firstField: root.passphrase ? wordsField.field : lengthField.field

    // The tick boxes, each with the option it stands for.
    readonly property var boxes: [
        [lowerBox, "lower"], [upperBox, "upper"], [numbersBox, "numbers"],
        [extendedBox, "extendedAscii"],
        [logogramsBox, "logograms"], [punctuationBox, "punctuation"], [quotesBox, "quotes"],
        [dashesBox, "dashes"], [mathBox, "math"], [bracesBox, "braces"],
        [similarBox, "excludeSimilar"], [everyGroupBox, "everyGroup"]
    ]

    onShown: {
        const options = controller.generatorOptions();
        root.passphraseAvailable = options.passphraseAvailable;

        root.copied = false;
        root.loading = true;
        modeTabs.currentIndex = options.passphrase && options.passphraseAvailable ? 1 : 0;
        lengthField.text = String(options.length);
        for (const pair of root.boxes)
            pair[0].checked = !!options[pair[1]];
        extraField.text = options.extra || "";
        excludeField.text = options.exclude;
        customField.text = options.custom;
        wordsField.text = String(options.words);
        separatorField.text = options.separator;
        root.loading = false;

        regenerate();
    }

    function currentOptions() {
        const options = {
            "passphrase": modeTabs.currentIndex === 1,
            "length": parseInt(lengthField.text) || 0,
            "extra": extraField.text,
            "exclude": excludeField.text,
            "custom": customField.text,
            "words": parseInt(wordsField.text) || 0,
            "separator": separatorField.text
        };
        for (const pair of root.boxes)
            options[pair[1]] = pair[0].checked;
        return options;
    }

    // Tab walks every option in reading order; the ones the current mode
    // hides (and the passphrase toggle when there is no wordlist) are
    // skipped by moveFocus.
    readonly property var tabOrder: [
        modeTabs, lengthField,
        lowerBox, upperBox, numbersBox, extendedBox,
        logogramsBox, punctuationBox, quotesBox, dashesBox, mathBox, bracesBox,
        similarBox, everyGroupBox,
        extraField, excludeField, customField,
        wordsField, separatorField
    ]

    function focusNext(from) { root.moveFocus(root.tabOrder, from, 1); }
    function focusPrevious(from) { root.moveFocus(root.tabOrder, from, -1); }

    // Every tick box and field answers the same way: a change draws a new
    // password, Enter accepts, Escape gives the keyboard back to the sheet,
    // and Tab moves along tabOrder.
    Component.onCompleted: {
        for (const item of root.tabOrder) {
            if (item === modeTabs)
                continue;
            if (item.checkedChanged)
                item.checkedChanged.connect(root.regenerate);
            else
                item.textChanged.connect(root.regenerate);
            if (item.copyRequested) {
                item.copyWhenNothingSelected = true;
                item.copyRequested.connect(root.copyPassword);
            }
            item.submitted.connect(root.submit);
            item.cancelled.connect(root.takeKeyboard);
            item.nextRequested.connect(function() { root.focusNext(item); });
            item.previousRequested.connect(function() { root.focusPrevious(item); });
        }
    }

    function regenerate() {
        if (root.loading)
            return;

        const result = controller.generate(currentOptions());
        root.copied = false;
        root.password = result.password || "";
        root.entropy = result.entropy || 0;
        root.quality = result.quality || "";
    }

    // Reachable wherever the focus is, which a field would otherwise swallow.
    Shortcut {
        sequences: ["Ctrl+R"]
        enabled: root.visible
        onActivated: root.regenerate()
    }

    // Ctrl+C copies the password from anywhere in the sheet. A field takes
    // the key before a Shortcut sees it, so the fields hand it over through
    // copyRequested, except when text in them is selected: then Ctrl+C
    // copies that text, as anywhere else.
    Shortcut {
        sequences: [StandardKey.Copy]
        enabled: root.visible
        onActivated: root.copyPassword()
    }

    // A password or a passphrase, as two tabs over the options for each.
    Segmented {
        id: modeTabs
        objectName: "generatorMode"
        visible: root.passphraseAvailable
        options: [i18n.t("generator.mode_password"), i18n.t("generator.mode_passphrase")]
        onCurrentIndexChanged: root.regenerate()
        onSubmitted: root.submit()
        onCancelled: root.takeKeyboard()
        onNextRequested: root.focusNext(modeTabs)
        onPreviousRequested: root.focusPrevious(modeTabs)
    }

    // What Enter copies (or uses), in the monospace family where l, 1 and I
    // differ, with a button to draw another.
    Rectangle {
        width: parent.width
        height: Math.max(passwordText.implicitHeight, regenerateButton.height) + Math.round(20 * root.s)
        color: theme.background
        radius: Math.min(4, theme.radius)
        border.width: 1
        border.color: theme.border

        Text {
            id: passwordText
            objectName: "generatedPassword"
            anchors.left: parent.left
            anchors.right: regenerateButton.left
            anchors.leftMargin: Math.round(14 * root.s)
            anchors.rightMargin: Math.round(8 * root.s)
            anchors.verticalCenter: parent.verticalCenter
            text: root.password
            color: theme.foreground
            wrapMode: Text.WrapAnywhere
            font.family: systemTheme.monoFamily
            font.pixelSize: Math.round(18 * root.s)
        }

        IconButton {
            id: regenerateButton
            anchors.right: parent.right
            anchors.rightMargin: Math.round(6 * root.s)
            anchors.verticalCenter: parent.verticalCenter
            iconName: "dice"
            description: i18n.t("generator.regenerate")
            onClicked: root.regenerate()
        }
    }

    // How strong the result is, as KeePassXC shows it: a bar in the band's
    // colour, the band, the size and the bits.
    Column {
        objectName: "generatorStrength"
        width: parent.width
        visible: root.password.length > 0
        spacing: Math.round(6 * root.s)

        readonly property color bandColor: root.quality === "excellent" ? theme.alertInfo
                                         : root.quality === "good" ? theme.alertWarn
                                         : root.quality === "weak" ? theme.important
                                         : theme.alertError

        Rectangle {
            width: parent.width
            height: Math.round(4 * root.s)
            radius: height / 2
            color: theme.border

            Rectangle {
                height: parent.height
                radius: parent.radius
                // Full at 128 bits, past which more makes no difference.
                width: parent.width * Math.min(1, root.entropy / 128)
                color: parent.parent.bandColor
            }
        }

        Text {
            objectName: "generatorStrengthText"
            width: parent.width
            text: i18n.t("generator.strength", {
                "quality": root.quality ? i18n.t("generator.quality_" + root.quality) : "",
                "size": root.passphrase
                        ? i18n.t("generator.size_words", { "count": parseInt(wordsField.text) || 0 })
                        : i18n.t("generator.size_chars", { "count": root.password.length }),
                "bits": Math.round(root.entropy)
            })
            color: theme.muted
            elide: Text.ElideRight
            font.pixelSize: Math.round(12 * root.s)
        }

        Text {
            objectName: "generatorCopied"
            width: parent.width
            visible: root.copied
            text: i18n.t("generator.copied_stays")
            color: theme.alertInfo
            wrapMode: Text.WordWrap
            font.pixelSize: Math.round(12 * root.s)
        }
    }

    Field {
        id: lengthField
        width: parent.width
        visible: !root.passphrase
        label: i18n.t("generator.length_label")
        field.inputMethodHints: Qt.ImhDigitsOnly
    }

    // The character groups, KeePassXC's: the letters, numbers and extended
    // ASCII, then the symbols in six groups shown by what they hold.
    Column {
        width: parent.width
        visible: !root.passphrase
        spacing: Math.round(4 * root.s)

        readonly property real half: (width - Math.round(8 * root.s)) / 2
        readonly property real third: (width - 2 * Math.round(8 * root.s)) / 3

        Text {
            text: i18n.t("generator.characters_label")
            color: theme.muted
            font.pixelSize: Math.round(13 * root.s)
        }

        Grid {
            columns: 2
            columnSpacing: Math.round(8 * root.s)

            CheckOption { id: lowerBox; width: parent.parent.half; text: i18n.t("generator.lower") }
            CheckOption { id: upperBox; width: parent.parent.half; text: i18n.t("generator.upper") }
            CheckOption { id: numbersBox; width: parent.parent.half; text: i18n.t("generator.numbers") }
            CheckOption { id: extendedBox; width: parent.parent.half; text: i18n.t("generator.extended_ascii") }
        }

        Text {
            topPadding: Math.round(6 * root.s)
            text: i18n.t("generator.symbols_label")
            color: theme.muted
            font.pixelSize: Math.round(13 * root.s)
        }

        Grid {
            columns: 3
            columnSpacing: Math.round(8 * root.s)

            CheckOption { id: logogramsBox; width: parent.parent.third; font.family: systemTheme.monoFamily; text: "# $ % & @ ^ ` ~" }
            CheckOption { id: punctuationBox; width: parent.parent.third; font.family: systemTheme.monoFamily; text: ". , : ;" }
            CheckOption { id: quotesBox; width: parent.parent.third; font.family: systemTheme.monoFamily; text: "\" '" }
            CheckOption { id: dashesBox; width: parent.parent.third; font.family: systemTheme.monoFamily; text: "\\ / | _ -" }
            CheckOption { id: mathBox; width: parent.parent.third; font.family: systemTheme.monoFamily; text: "< > * + ! ? =" }
            CheckOption { id: bracesBox; width: parent.parent.third; font.family: systemTheme.monoFamily; text: "{ [ ( ) ] }" }
        }

        Item { width: 1; height: Math.round(4 * root.s) }

        CheckOption { id: similarBox; text: i18n.t("generator.exclude_similar") }
        CheckOption { id: everyGroupBox; text: i18n.t("generator.every_group") }
    }

    Field {
        id: extraField
        width: parent.width
        visible: !root.passphrase
        label: i18n.t("generator.extra_label")
    }

    Field {
        id: excludeField
        width: parent.width
        visible: !root.passphrase
        label: i18n.t("generator.exclude_label")
    }

    Field {
        id: customField
        width: parent.width
        visible: !root.passphrase
        label: i18n.t("generator.custom_label")
    }

    Field {
        id: wordsField
        width: parent.width
        visible: root.passphrase
        label: i18n.t("generator.words_label")
        field.inputMethodHints: Qt.ImhDigitsOnly
    }

    Field {
        id: separatorField
        width: parent.width
        visible: root.passphrase
        label: i18n.t("generator.separator_label")
        // A space reads as an empty field; the placeholder says which it is.
        placeholderText: i18n.t("generator.separator_space")
    }
}
