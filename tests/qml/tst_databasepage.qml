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

    function test_startup_keyboard_navigates_databases() {
        page.forceActiveFocus();
        controller.emitDatabases(testCase.bancos);
        const list = findChild(page, "entryList");
        waitForRendering(list);
        list.currentIndex = 0;
        keyClick(Qt.Key_J);
        compare(list.currentIndex, 1);
        keyClick(Qt.Key_Slash);
        keyClick(Qt.Key_X);
        compare(controller.databaseQuery, "x");
        keyClick(Qt.Key_Backspace);
        keyClick(Qt.Key_Escape);
    }

    // The generator needs no database: Ctrl+G opens it from this screen.
    function test_ctrl_g_opens_the_generator_without_a_database() {
        page.forceActiveFocus();
        controller.emitDatabases(testCase.bancos);
        controller.emitScanning(false);
        compare(page.mode, "list");
        keyClick(Qt.Key_G, Qt.ControlModifier);
        compare(page.mode, "generate");
        // Ctrl+C quits from this screen's list, but in the generator it
        // copies the password: the window has to know the quit is off.
        verify(window.editingText, "Ctrl+C não fecha o app com o gerador aberto");
        page.mode = "list";
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

    // The two-step methods offered are the account's own, in the order the
    // controller gives them, and picking one passes its provider number on.
    function test_method_choice_lists_only_the_accounts_methods() {
        controller.loginMethods = [0, 3];
        controller.loginStep = "method";
        const choice = findChild(page, "methodChoice");
        verify(choice !== null);
        tryVerify(function() { return choice.visible; }, 3000);
        compare(choice.options.length, 2);
        compare(choice.options[0], i18n.t("bitwarden.method_authenticator"));
        compare(choice.options[1], i18n.t("bitwarden.method_yubikey"));
        controller.loginStep = "";
    }

    // Clicking a kind of database opens its sheet. The same click once
    // reached the dimmed backdrop as well, which read it as a click outside
    // and sent the page straight back to the list.
    function test_clicking_a_kind_opens_its_sheet() {
        controller.emitScanning(false);
        controller.emitDatabases(testCase.bancos);
        page.mode = "chooseType";
        const choice = findChild(page, "typeChoice");
        tryVerify(function() { return choice.opened; }, 3000);
        let keepass = null;
        tryVerify(function() {
            keepass = findChild(choice.contentItem, "choice2");
            return keepass !== null && keepass.visible;
        }, 3000);
        wait(300);

        mouseClick(keepass);
        tryCompare(page, "mode", "createDb", 3000);
        wait(300);
        compare(page.mode, "createDb", "o clique não fecha a janela que acabou de abrir");

        page.mode = "list";
    }
}
