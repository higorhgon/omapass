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

    ListPane {
        id: table
        visible: false
        anchors.fill: parent
        model: [{ "path": "Trabalho/Deploy", "name": "Deploy", "typeLabel": "ssh", "group": "Trabalho" }]
        columns: [
            { "key": "typeLabel", "title": "Tipo", "weight": 1 },
            { "key": "name", "title": "Nome", "weight": 3 },
            { "key": "group", "title": "Grupo", "weight": 2 }
        ]
    }

    ListPane {
        id: fitted
        visible: false
        width: 800
        height: 300
        model: [{ "name": "Deploy", "group": "" }]
        columns: [
            { "key": "name", "title": "Nome", "weight": 3 },
            { "key": "group", "title": "Grupo", "weight": 2.5, "fit": true }
        ]
    }

    function test_fit_column_gives_its_room_to_the_others() {
        const group = fitted.columnWidth(1, 800);
        const name = fitted.columnWidth(0, 800);
        verify(group > 0);
        verify(group < 100);
        verify(name > 800 * 3 / 5.5);
        verify(Math.abs(name + group + fitted.columnSpacing - (800 - Math.round(20 * fitted.s))) < 1);
    }

    function test_columns_show_one_cell_per_key() {
        compare(findChild(table, "cell_typeLabel").text, "ssh");
        compare(findChild(table, "cell_name").text, "Deploy");
        compare(findChild(table, "cell_group").text, "Trabalho");
        compare(findChild(table, "columnHeader").text, "Tipo");
    }
}
