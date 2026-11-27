import QtQuick
import QtQuick.Controls

// A labelled single-line field in Hype's style: a muted label above a box on
// the window's background, whose border takes the accent while focused.
Item {
    id: root

    property string label: ""
    property alias text: input.text
    property alias echoMode: input.echoMode
    property alias placeholderText: input.placeholderText
    property alias field: input
    readonly property bool active: input.activeFocus
    // The value is a secret (a password, a code): in the monospace family,
    // where l, 1 and I differ once it is revealed.
    property bool monospace: false
    // Ctrl+C with nothing selected is handed to the sheet (copyRequested)
    // instead of copying nothing: the field takes the key before any
    // Shortcut sees it.
    property bool copyWhenNothingSelected: false

    signal copyRequested()
    signal submitted()
    signal cancelled()
    signal nextRequested()
    signal previousRequested()
    signal listNext()
    signal listPrevious()
    signal generateRequested()

    readonly property real s: systemTheme.textScale

    implicitHeight: (labelText.visible ? labelText.height + Math.round(6 * s) : 0) + input.height
    height: implicitHeight

    Text {
        id: labelText
        anchors.top: parent.top
        visible: text.length > 0
        text: root.label.trim()
        color: root.active ? theme.foreground : theme.muted
        font.pixelSize: Math.round(13 * root.s)
    }

    TextField {
        id: input
        anchors.top: labelText.visible ? labelText.bottom : parent.top
        anchors.topMargin: labelText.visible ? Math.round(6 * root.s) : 0
        width: parent.width
        height: Math.round(38 * root.s)
        color: theme.foreground
        placeholderTextColor: theme.muted
        selectionColor: theme.selection
        selectedTextColor: theme.selectionText
        font.pixelSize: Math.round(14 * root.s)
        font.family: root.monospace ? systemTheme.monoFamily : Qt.application.font.family
        leftPadding: Math.round(12 * root.s)
        rightPadding: Math.round(12 * root.s)
        opacity: enabled ? 1 : 0.6

        background: Rectangle {
            color: theme.background
            radius: Math.min(4, theme.radius)
            border.width: 1
            border.color: root.active ? theme.accent : theme.border
        }

        Keys.onPressed: function(event) {
            if (root.copyWhenNothingSelected && input.selectedText.length === 0
                && event.matches(StandardKey.Copy)) {
                root.copyRequested();
                event.accepted = true;
                return;
            }
            if (event.modifiers & Qt.ControlModifier) {
                // Readline-style navigation for the suggestion dropdowns:
                // this is a text field, so j/k cannot navigate here.
                if (event.key === Qt.Key_G) {
                    root.generateRequested();
                    event.accepted = true;
                } else if (event.key === Qt.Key_N) {
                    root.listNext();
                    event.accepted = true;
                } else if (event.key === Qt.Key_P) {
                    root.listPrevious();
                    event.accepted = true;
                }
                return;
            }

            switch (event.key) {
            case Qt.Key_Escape:
                root.cancelled();
                break;
            case Qt.Key_Return:
            case Qt.Key_Enter:
                root.submitted();
                break;
            case Qt.Key_Tab:
                root.nextRequested();
                break;
            case Qt.Key_Backtab:
                root.previousRequested();
                break;
            case Qt.Key_Down:
                root.listNext();
                break;
            case Qt.Key_Up:
                root.listPrevious();
                break;
            default:
                return;
            }
            event.accepted = true;
        }
    }
}
