import QtQuick
import QtQuick.Controls

// The right-click menu over the entry list. Appears at the pointer when one
// was used, and centred over the list when opened from the keyboard with
// Space — the same two ways the TUI anchored it.
Popup {
    id: root

    property var options: []
    property int selected: 0
    property real anchorX: -1
    property real anchorY: -1

    signal chosen(int index)

    readonly property real s: systemTheme.textScale
    readonly property real fontSize: Math.round(13 * s)
    readonly property real itemMargin: Math.round(8 * s)

    // Wide enough for the longest option: the entries are translated and the
    // list changes with the backend, so a fixed width would clip them.
    FontMetrics {
        id: metrics
        // The interface font is the desktop's monospace one, which is wider
        // than the default; measuring with anything else clips the options.
        font.family: Qt.application.font.family
        font.pixelSize: root.fontSize
    }

    readonly property real optionsWidth: {
        let widest = 0;
        for (let i = 0; i < options.length; ++i)
            widest = Math.max(widest, metrics.advanceWidth(options[i]));
        return widest;
    }

    width: Math.min(Math.max(Math.round(200 * s), optionsWidth + (itemMargin + padding) * 2),
                    parent ? parent.width - Math.round(40 * s) : Math.round(420 * s))
    padding: Math.round(6 * s)
    modal: true
    focus: true
    closePolicy: Popup.NoAutoClose

    x: anchorX >= 0 ? Math.min(anchorX, parent.width - width) : (parent.width - width) / 2
    y: anchorY >= 0 ? Math.min(anchorY, parent.height - height) : (parent.height - height) / 2

    Overlay.modal: Rectangle {
        color: "transparent"

        TapHandler {
            onTapped: root.close()
        }
    }

    background: Rectangle {
        color: theme.background
        radius: Math.round(6 * root.s)
        border.width: Math.max(1, Math.round(root.s))
        border.color: theme.title
    }

    contentItem: Column {
        spacing: Math.round(2 * root.s)

        Item {
            width: 0
            height: 0
            focus: true

            Keys.onPressed: function(event) {
                switch (event.key) {
                case Qt.Key_Escape:
                    root.close();
                    break;
                case Qt.Key_Down:
                case Qt.Key_J:
                    root.selected = (root.selected + 1) % root.options.length;
                    break;
                case Qt.Key_Up:
                case Qt.Key_K:
                    root.selected = (root.selected + root.options.length - 1) % root.options.length;
                    break;
                case Qt.Key_Return:
                case Qt.Key_Enter:
                    root.chosen(root.selected);
                    break;
                default:
                    return;
                }
                event.accepted = true;
            }
        }

        Repeater {
            model: root.options

            Rectangle {
                required property int index
                required property var modelData

                width: root.availableWidth
                height: Math.round(28 * root.s)
                radius: Math.round(4 * root.s)
                color: root.selected === index ? theme.selection : "transparent"

                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.leftMargin: root.itemMargin
                    anchors.rightMargin: root.itemMargin
                    text: modelData
                    color: theme.base
                    elide: Text.ElideRight
                    font.pixelSize: root.fontSize
                }

                HoverHandler {
                    onHoveredChanged: if (hovered) root.selected = index
                }

                TapHandler {
                    onTapped: root.chosen(index)
                }
            }
        }
    }
}
