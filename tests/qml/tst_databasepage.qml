import QtQuick
import QtTest
import "qrc:/"

// What the first screen decides to show. An empty list means two different
// things — "still looking" and "there is nothing here" — and only the second
// one should offer to create a database.
//
// The regression this guards: the scan flag and the list arrive as two
// separate signals, and when the flag came first the page concluded there
// was nothing, put the create offer up, and stayed there after the list
// arrived behind it.
TestCase {
    id: testCase
    name: "DatabasePage"
    when: windowShown
    visible: true
    width: 700
    height: 500

    property var bancos: [
        { "path": "/casa/cofre.kdbx", "name": "cofre", "label": "/casa/cofre.kdbx",
          "kind": "KeePassXC" },
        { "path": "bitwarden:pessoa@exemplo.com", "name": "pessoa@exemplo.com",
          "label": "pessoa@exemplo.com", "kind": "Bitwarden" }
    ]

    function init() {
        controller.emitDatabases([]);
        controller.emitScanning(true);
        page.mode = page.defaultMode();
    }

    DatabasePage {
        id: page
        anchors.fill: parent
    }

    function test_scanning_does_not_offer_to_create_yet() {
        compare(page.mode, "list", "enquanto procura, a lista fica");
    }

    // The order the application actually produces.
    function test_list_before_flag_keeps_the_list() {
        controller.emitDatabases(testCase.bancos);
        controller.emitScanning(false);
        compare(page.mode, "list");
    }

    // The order that produced the bug: the flag first, list still empty.
    function test_flag_before_list_recovers_when_the_list_lands() {
        controller.emitScanning(false);
        compare(page.mode, "confirmCreate", "sem lista e sem varredura, a oferta e correta");

        controller.emitDatabases(testCase.bancos);
        compare(page.mode, "list", "a lista chegando desfaz a oferta");
    }

    function test_nothing_found_offers_to_create() {
        controller.emitScanning(false);
        controller.emitDatabases([]);
        compare(page.mode, "confirmCreate");
    }
}
