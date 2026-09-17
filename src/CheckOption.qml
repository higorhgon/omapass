import QtQuick
import QtQuick.Controls

// A tick box in the Omarchy palette — the Basic style draws its own against
// its palette instead. Used for "show the secret" next to password fields
// and for the generator's options.
CheckBox {
    id: root

    readonly property real s: systemTheme.textScale

    font.pixelSize: Math.round(12 * s)
    // Never steals the Tab order from the fields around it.
    focusPolicy: Qt.NoFocus

    indicator: Rectangle {
        implicitWidth: Math.round(16 * root.s)
        implicitHeight: Math.round(16 * root.s)
        y: (root.height - height) / 2
        radius: Math.round(3 * root.s)
        color: "transparent"
        border.width: Math.max(1, Math.round(root.s))
        border.color: root.checked ? theme.annotation : theme.guidance

        Rectangle {
            anchors.centerIn: parent
            width: parent.width / 2
            height: parent.height / 2
            radius: Math.round(2 * root.s)
            visible: root.checked
            color: theme.annotation
        }
    }

    contentItem: Text {
        text: root.text
        color: theme.guidance
        leftPadding: root.indicator.width + Math.round(6 * root.s)
        verticalAlignment: Text.AlignVCenter
        font: root.font
    }
}
