import QtQuick
import QtTest
import "qrc:/"

// The entries page is only loaded once a vault is open, so a mistake in it
// (an import missing, a type misspelled) would not show at start-up. It is
// compiled here, without the controller it needs to run.
TestCase {
    id: testCase
    name: "EntriesPage"
    when: windowShown
    visible: true
    width: 320
    height: 160

    ActionsMenu {
        id: menu
        options: ["Adicionar", "Remover", "Editar", "Copiar senha", "Configurar SSH", "Gerar senha"]
    }

    SignalSpy {
        id: menuChoice
        target: menu
        signalName: "chosen"
    }

    function test_page_compiles() {
        const component = Qt.createComponent("qrc:/EntriesPage.qml");
        compare(component.status, Component.Ready, component.errorString());
    }

    function test_bitwarden_shows_collections_only_with_an_organization() {
        const component = Qt.createComponent("qrc:/EntriesPage.qml");
        const page = createTemporaryObject(component, testCase, {width: 320, height: 160});
        const pane = findChild(page, "entriesPane");
        try {
            controller.bitwardenBackend = true;
            controller.bitwardenOrganizations = [];
            compare(pane.columns[2].key, "group");
            controller.bitwardenOrganizations = [{ "id": "org-1", "name": "Equipe" }];
            compare(pane.columns[2].key, "collections");
        } finally {
            controller.bitwardenBackend = false;
            controller.bitwardenOrganizations = [];
        }
    }

    function test_context_menu_matches_the_selected_entry() {
        const component = Qt.createComponent("qrc:/EntriesPage.qml");
        const page = createTemporaryObject(component, testCase, {width: 320, height: 160});
        const list = findChild(page, "entryList");
        const actions = findChild(page, "entryActions");
        for (let index = 0; index < 2; ++index) {
            list.currentIndex = index;
            findChild(page, "entriesPane").leaveSearch();
            keyClick(Qt.Key_Space);
            tryCompare(actions, "opened", true);
            compare(actions.actions.includes("copyPassword"), index === 0);
            compare(actions.actions.includes("copyUsername"), index === 1);
            compare(actions.actions.includes("copyUrl"), index === 0);
            compare(actions.actions.includes("openUrl"), index === 0);
            compare(actions.actions.includes("copyOtp"), index === 1);
            verify(!actions.actions.includes("add") && !actions.actions.includes("generate"));
            keyClick(Qt.Key_Escape);
            tryCompare(actions, "opened", false);
        }
    }

    SignalSpy { id: switched; target: controller; signalName: "databaseSwitched" }
    SignalSpy { id: picker; target: controller; signalName: "databasePickerRequested" }

    function test_switch_databases_from_header() {
        const component = Qt.createComponent("qrc:/EntriesPage.qml");
        const page = createTemporaryObject(component, testCase, {width: 460, height: 160});
        const heading = findChild(page, "headerTitle");
        const menu = findChild(page, "databasesMenu");
        waitForRendering(page);
        verify(heading.width <= heading.implicitWidth + 1);
        compare(menu.dim, false);
        mouseClick(heading);
        tryCompare(menu, "opened", true);
        compare(menu.options[1], "Trabalho · pass");
        keyClick(Qt.Key_Down);
        keyClick(Qt.Key_Return);
        tryCompare(switched, "count", 1);
        compare(switched.signalArguments[0][0], "/trabalho");
        tryCompare(menu, "opened", false);
        keyClick(Qt.Key_Tab, Qt.ControlModifier);
        tryCompare(menu, "opened", true);
        keyClick(Qt.Key_Up);
        keyClick(Qt.Key_Return);
        tryCompare(picker, "count", 1);
    }

    function test_click_outside_dismisses_without_choosing() {
        menuChoice.clear();
        menu.open();
        tryCompare(menu, "opened", true);
        mouseClick(testCase, 5, 5);
        tryCompare(menu, "opened", false);
        compare(menuChoice.count, 0);
    }

    function test_long_menu_keeps_keyboard_selection_visible() {
        menu.selected = 0;
        menuChoice.clear();
        menu.open();
        tryCompare(menu, "opened", true);
        compare(menu.height, 160);
        keyClick(Qt.Key_Up);
        compare(menu.selected, menu.options.length - 1);
        verify(menu.contentItem.contentY > 0);
        keyClick(Qt.Key_Return);
        compare(menuChoice.count, 1);
        compare(menuChoice.signalArguments[0][0], menu.options.length - 1);
        menu.close();
        tryCompare(menu, "opened", false);
    }

    function test_ctrl_s_focuses_open_sidebar_before_closing() {
        const component = Qt.createComponent("qrc:/EntriesPage.qml");
        const page = createTemporaryObject(component, testCase, {width: 600, height: 300});
        const sidebarList = findChild(page, "sidebarList");
        const pane = findChild(page, "entriesPane");
        waitForRendering(page);

        compare(page.sidebarOpen, false);
        keyClick(Qt.Key_S, Qt.ControlModifier);
        compare(page.sidebarOpen, true);
        tryCompare(sidebarList, "activeFocus", true);

        keyClick(Qt.Key_Escape);
        compare(page.sidebarOpen, true);
        compare(page.sidebarFocused, false);
        tryCompare(pane, "activeFocus", true);

        keyClick(Qt.Key_S, Qt.ControlModifier);
        compare(page.sidebarOpen, true);
        compare(page.sidebarFocused, true);
        tryCompare(sidebarList, "activeFocus", true);

        keyClick(Qt.Key_S, Qt.ControlModifier);
        compare(page.sidebarOpen, false);
        compare(page.sidebarFocused, false);
        tryCompare(pane, "activeFocus", true);
    }

    function test_sidebar_deletes_only_empty_groups_after_confirming() {
        controller.sidebarItems = [
            { "id": "all", "label": "Todos", "kind": "section", "count": 3 },
            { "id": "group:Trabalho", "label": "Trabalho", "kind": "item", "depth": 0, "count": 3 },
            { "id": "group:Vazio", "label": "Vazio", "kind": "item", "depth": 0, "count": 0 }
        ];
        controller.deletedSidebarId = "";
        controller.lastMessage = "";
        const component = Qt.createComponent("qrc:/EntriesPage.qml");
        const page = createTemporaryObject(component, testCase, {width: 600, height: 300});
        const sidebarList = findChild(page, "sidebarList");
        try {
            waitForRendering(page);
            keyClick(Qt.Key_S, Qt.ControlModifier);
            tryCompare(sidebarList, "activeFocus", true);

            // A group with entries is refused, with no question asked.
            page.sidebarCursor = 1;
            keyClick(Qt.Key_Delete);
            compare(page.mode, "list");
            compare(controller.lastMessage, "not empty");
            compare(controller.deletedSidebarId, "");

            // An empty one asks first; "n" keeps it.
            page.sidebarCursor = 2;
            keyClick(Qt.Key_X, Qt.ControlModifier);
            compare(page.mode, "confirmSidebarDelete");
            keyClick(Qt.Key_N);
            compare(page.mode, "list");
            compare(controller.deletedSidebarId, "");
            tryCompare(sidebarList, "activeFocus", true);

            // "y" deletes it.
            keyClick(Qt.Key_Delete);
            compare(page.mode, "confirmSidebarDelete");
            keyClick(Qt.Key_Y);
            compare(page.mode, "list");
            compare(controller.deletedSidebarId, "group:Vazio");
        } finally {
            controller.sidebarItems = [];
        }
    }
}
