import QtQuick

// Shown while an account backend is being asked whether it is still signed
// in. That answer usually comes from a file and is instant, but it can fall
// back to running the backend's CLI, which takes seconds — and the password
// sheet must not come up before it: asking for a master password to open an
// account that turns out to be logged out means typing it for nothing.
Modal {
    id: root

    property string accountName: ""

    signal cancelled()

    accentColor: theme.alertInfo
    heading: i18n.t("db_app.account_check_title")
    hint: i18n.t("db_app.account_check_hint")
    cardWidth: Math.round(460 * s)

    onKeyPressed: function(event) {
        if (event.key === Qt.Key_Escape) {
            root.cancelled();
            event.accepted = true;
        }
    }
    onDismissed: root.cancelled()

    Text {
        objectName: "accountCheckText"
        width: parent.width
        text: i18n.t("db_app.account_check_body", {"account": root.accountName})
        color: theme.base
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.WordWrap
        font.pixelSize: Math.round(14 * root.s)
    }
}
