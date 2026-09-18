import QtQuick
import QtTest
import "qrc:/"

// The database list: what each row shows. A row used to print the path it is
// keyed by, which for an account is an internal identifier ("1password:my"),
// and the tag came out empty for a backend whose label was never written.
TestCase {
    id: testCase
    name: "ListPane"
    when: windowShown
    visible: true
    width: 600
    height: 400

    ListPane {
        id: pane
        anchors.fill: parent
        model: [
            { "path": "1password:minha", "label": "pessoa@exemplo.com", "kind": "1Password" },
            { "path": "/casa/cofre.kdbx", "label": "/casa/cofre.kdbx", "kind": "KeePassXC" }
        ]
        tagFor: function(item) { return "[" + item.kind + "]"; }
    }

    function test_row_shows_the_label_not_the_key() {
        const text = findChild(pane, "rowText");
        const tag = findChild(pane, "rowTag");
        verify(text !== null, "a lista desenhou alguma linha");
        compare(text.text, "pessoa@exemplo.com");
        compare(tag.text, "[1Password]");
    }
}
