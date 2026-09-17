import QtQuick
import QtQuick.Controls

// The "show the secret" tick used next to password and PIN fields: the
// Basic style's own checkbox is drawn against its palette instead of the
// Omarchy one, so the indicator is drawn here.
CheckBox {
    id: root

    readonly property real s: systemTheme.textScale

    text: i18n.t("ui.show_password")
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
