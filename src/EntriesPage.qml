import QtQuick
import QtQuick.Dialogs

// Second stage: the entries of the open vault, with everything that can be
// done to them.
FocusScope {
    id: page

    property string mode: "list"
    property bool sidebarOpen: false
    property bool sidebarFocused: false
    property int sidebarCursor: 0
    property string selectedEntry: ""
    property string selectedEntryLabel: ""
    property string selectedSidebarId: ""
    property string selectedSidebarLabel: ""
    property string iconEntry: ""
    property string iconRequest: ""

    readonly property bool menuOpen: actionsMenu.opened || databasesMenu.opened || sidebarAddMenu.opened
                                     || sidebarItemMenu.opened

    Binding {
        target: window
        property: "editingText"
        value: page.mode !== "list" || pane.typing
    }

    function currentEntry() {
        return controller.entryPathAt(pane.currentIndex);
    }

    function openInfo() {
        const entry = currentEntry();
        if (entry.length === 0)
            return;

        const details = controller.entryDetails(entry);
        if (Object.keys(details).length === 0)
            return;

        page.selectedEntry = entry;
        infoModal.details = details;
        page.mode = "info";
    }

    // The file dialog answers later; the entry is the one selected now.
    function chooseIcon() {
        const entry = currentEntry();
        if (entry.length === 0) {
            controller.showMessage(i18n.t("app.no_entry_selected"), true);
            return;
        }
        page.iconEntry = entry;
        const activeDb = controller.openDatabases.find(db => db.active) || controller.openDatabases[0];
        page.iconRequest = "entryIcon/" + JSON.stringify([activeDb.path, entry]);
        if (filePicker.available)
            filePicker.openFile(page.iconRequest, i18n.t("ui.icon_pick_title"),
                                [{ "name": i18n.t("ui.icon_filter"),
                                   "patterns": ["*.png", "*.jpg", "*.jpeg", "*.ico", "*.webp", "*.gif", "*.bmp"] },
                                 { "name": i18n.t("settings.all_files"), "patterns": ["*"] }]);
        else
            iconDialog.open();
    }

    Connections {
        target: filePicker

        function onPicked(purpose, path) {
            if (purpose === page.iconRequest && path.length > 0)
                controller.chooseEntryIcon(page.iconEntry, path);
        }
        function onFailed(purpose, error) {
            if (purpose === page.iconRequest)
                controller.showMessage(error, true);
        }
    }

    FileDialog {
        id: iconDialog
        title: i18n.t("ui.icon_pick_title")
        nameFilters: [i18n.t("ui.icon_filter"), i18n.t("settings.all_files")]
        onAccepted: controller.chooseEntryIcon(page.iconEntry, selectedFile)
    }

    function openAddForm() {
        formModal.isEdit = false;
        formModal.fields = {};
        page.mode = "form";
    }

    // Editing an ordinary entry opens the form; editing an empty group opens
    // the rename sheet instead.
    function editEntry(entry) {
        if (entry.length === 0) {
            controller.showMessage(i18n.t("app.no_entry_selected"), true);
            return;
        }

        page.selectedEntry = entry;
        if (controller.isEmptyGroup(entry)) {
            const group = controller.groupNameOf(entry);
            renameModal.currentName = group.split("/").pop();
            page.mode = "rename";
        } else {
            formModal.isEdit = true;
            formModal.fields = controller.entryFields(entry);
            page.mode = "form";
        }
    }

    // Every backend can have a PIN of its own, so the shortcut works
    // wherever a database is open.
    function togglePin() {
        page.mode = controller.pinConfigured ? "pinDisable" : "pin";
    }

    // Copying or opening needs an entry under the cursor; the controller
    // says why when the entry has nothing to give.
    function withEntry(action) {
        const entry = currentEntry();
        if (entry.length === 0) {
            controller.showMessage(i18n.t("app.no_entry_selected"), true);
            return;
        }
        action(entry);
    }

    function confirmDelete(explicitEntry) {
        const entry = (explicitEntry !== undefined && explicitEntry.length > 0) ? explicitEntry : currentEntry();
        if (entry.length === 0) {
            controller.showMessage(i18n.t("app.no_entry_selected"), true);
            return;
        }

        page.selectedEntry = entry;
        page.selectedEntryLabel = (entry.startsWith("trash:") || entry.startsWith("send:"))
            ? controller.entryLabelFor(entry) : entry;
        page.mode = "confirmDelete";
    }

    function focusSidebar() {
        if (!page.sidebarOpen)
            return;
        const items = controller.sidebarItems;
        let idx = -1;
        for (let i = 0; i < items.length; ++i) {
            if (items[i].id === controller.activeSection) {
                idx = i;
                break;
            }
        }
        if (idx < 0) {
            for (let i = 0; i < items.length; ++i) {
                if (items[i].kind !== "header") {
                    idx = i;
                    break;
                }
            }
        }
        if (idx >= 0)
            page.sidebarCursor = idx;
        page.sidebarFocused = true;
        sidebarList.forceActiveFocus();
        Qt.callLater(sidebarList.forceActiveFocus);
    }

    // Groups and collections go from the sidebar, once they are empty; the
    // controller says why one cannot.
    function confirmSidebarDelete(item) {
        if (!item || !item.id)
            return;
        const blocker = controller.sidebarDeleteBlocker(item.id);
        if (blocker.length > 0) {
            controller.showMessage(blocker, true);
            return;
        }
        page.selectedSidebarId = item.id;
        page.selectedSidebarLabel = item.id.slice(item.id.indexOf(":") + 1);
        page.mode = "confirmSidebarDelete";
    }

    // Back from a sheet opened from the sidebar, on the row it was opened on.
    function returnToSidebar() {
        if (!page.sidebarOpen)
            return;
        page.sidebarFocused = true;
        sidebarList.forceActiveFocus();
        Qt.callLater(sidebarList.forceActiveFocus);
    }

    function leaveSidebar() {
        page.sidebarFocused = false;
        pane.claimKeyboard();
    }

    function moveSidebarCursor(delta) {
        const items = controller.sidebarItems;
        if (items.length === 0)
            return;
        let idx = page.sidebarCursor;
        for (let step = 0; step < items.length; ++step) {
            idx = (idx + delta + items.length) % items.length;
            if (items[idx].kind !== "header") {
                page.sidebarCursor = idx;
                sidebarList.positionViewAtIndex(idx, ListView.Contain);
                return;
            }
        }
    }

    Rectangle {
        id: sidebar
        objectName: "entriesSidebar"
        visible: page.sidebarOpen
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        width: visible ? Math.round(230 * systemTheme.textScale) : 0
        color: theme.panel

        Rectangle {
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.right: parent.right
            width: 1
            color: theme.border
        }

        ListView {
            id: sidebarList
            objectName: "sidebarList"
            anchors.fill: parent
            anchors.margins: Math.round(10 * systemTheme.textScale)
            anchors.rightMargin: Math.round(11 * systemTheme.textScale)
            anchors.bottomMargin: Math.round(50 * systemTheme.textScale)
            clip: true
            spacing: Math.round(2 * systemTheme.textScale)
            model: controller.sidebarItems
            focus: page.sidebarFocused

            onCountChanged: {
                if (page.sidebarCursor >= count)
                    page.sidebarCursor = Math.max(0, count - 1);
            }

            Keys.onPressed: function(event) {
                if (!page.sidebarOpen || !page.sidebarFocused)
                    return;
                if ((event.modifiers & Qt.ControlModifier) && event.key === Qt.Key_S
                    && !(event.modifiers & Qt.ShiftModifier)) {
                    page.sidebarOpen = false;
                    page.leaveSidebar();
                    event.accepted = true;
                    return;
                }

                const items = controller.sidebarItems;
                const item = (page.sidebarCursor >= 0 && page.sidebarCursor < items.length)
                    ? items[page.sidebarCursor] : null;

                // Ctrl+X deletes in the list too; Delete is the key a mouse
                // user reaches for.
                if ((event.key === Qt.Key_X && event.modifiers === Qt.ControlModifier)
                    || (event.key === Qt.Key_Delete && event.modifiers === Qt.NoModifier)) {
                    page.confirmSidebarDelete(item);
                    event.accepted = true;
                    return;
                }
                if (event.modifiers & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier))
                    return;

                switch (event.key) {
                case Qt.Key_Escape:
                case Qt.Key_Tab:
                    page.leaveSidebar();
                    event.accepted = true;
                    return;
                case Qt.Key_J:
                case Qt.Key_N:
                case Qt.Key_Down:
                    page.moveSidebarCursor(1);
                    event.accepted = true;
                    return;
                case Qt.Key_K:
                case Qt.Key_P:
                case Qt.Key_Up:
                    page.moveSidebarCursor(-1);
                    event.accepted = true;
                    return;
                case Qt.Key_L:
                case Qt.Key_Right:
                    if (item && item.hasChildren && !item.expanded) {
                        controller.setSidebarNodeExpanded(item.expandKey, true);
                    } else {
                        if (item && item.id)
                            controller.selectSection(item.id);
                        page.leaveSidebar();
                    }
                    event.accepted = true;
                    return;
                case Qt.Key_H:
                case Qt.Key_Left:
                    if (item && item.hasChildren && item.expanded) {
                        controller.setSidebarNodeExpanded(item.expandKey, false);
                    } else if (item && item.parentId && item.parentId.length > 0) {
                        for (let i = 0; i < items.length; ++i) {
                            if (items[i].id === item.parentId) {
                                page.sidebarCursor = i;
                                sidebarList.positionViewAtIndex(i, ListView.Contain);
                                break;
                            }
                        }
                    }
                    event.accepted = true;
                    return;
                case Qt.Key_Space:
                    if (item) {
                        if (item.hasChildren)
                            controller.toggleSidebarNode(item.expandKey);
                        else if (item.id)
                            controller.selectSection(item.id);
                    }
                    event.accepted = true;
                    return;
                case Qt.Key_Return:
                case Qt.Key_Enter:
                    if (item && item.id)
                        controller.selectSection(item.id);
                    page.leaveSidebar();
                    event.accepted = true;
                    return;
                }
            }

            delegate: Item {
                required property int index
                required property var modelData
                width: ListView.view.width
                height: modelData.kind === "header"
                    ? Math.round(28 * systemTheme.textScale)
                    : Math.round(32 * systemTheme.textScale)

                Text {
                    visible: modelData.kind === "header"
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    anchors.leftMargin: Math.round(8 * systemTheme.textScale)
                    anchors.bottomMargin: Math.round(4 * systemTheme.textScale)
                    text: modelData.label
                    color: theme.muted
                    font.pixelSize: Math.round(11 * systemTheme.textScale)
                    font.weight: Font.DemiBold
                    elide: Text.ElideRight
                }

                Rectangle {
                    visible: modelData.kind !== "header"
                    anchors.fill: parent
                    radius: Math.min(4, theme.radius)
                    readonly property bool selected: controller.activeSection === modelData.id
                    readonly property bool focusedRow: page.sidebarFocused && page.sidebarCursor === index
                    readonly property int indentPx: Math.round((modelData.depth || 0) * 14 * systemTheme.textScale)
                    color: focusedRow ? theme.selection
                         : selected ? Qt.rgba(theme.selection.r, theme.selection.g, theme.selection.b, 0.45)
                         : (hoverArea.containsMouse ? theme.hover : "transparent")
                    border.width: selected && !focusedRow ? 1 : 0
                    border.color: theme.accent

                    Item {
                        id: chevronBox
                        visible: !!(modelData.hasChildren)
                        anchors.left: parent.left
                        anchors.leftMargin: Math.round(6 * systemTheme.textScale) + parent.indentPx
                        anchors.verticalCenter: parent.verticalCenter
                        width: Math.round(18 * systemTheme.textScale)
                        height: parent.height
                        z: 2

                        Text {
                            anchors.centerIn: parent
                            text: modelData.expanded ? "▾" : "▸"
                            color: parent.parent.focusedRow ? theme.selectionText : theme.muted
                            font.pixelSize: Math.round(12 * systemTheme.textScale)
                        }

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                page.sidebarCursor = index;
                                controller.toggleSidebarNode(modelData.expandKey);
                            }
                        }
                    }

                    Text {
                        anchors.left: parent.left
                        anchors.right: countLabel.visible ? countLabel.left : parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.leftMargin: Math.round((modelData.hasChildren ? 26 : 12) * systemTheme.textScale) + parent.indentPx
                        anchors.rightMargin: Math.round(6 * systemTheme.textScale)
                        text: modelData.label
                        color: parent.focusedRow ? theme.selectionText : theme.foreground
                        font.pixelSize: Math.round(13 * systemTheme.textScale)
                        font.weight: parent.selected || parent.focusedRow ? Font.DemiBold : Font.Normal
                        elide: Text.ElideRight
                    }

                    Text {
                        id: countLabel
                        visible: modelData.count !== undefined
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.rightMargin: Math.round(10 * systemTheme.textScale)
                        text: modelData.count !== undefined ? String(modelData.count) : ""
                        color: parent.focusedRow ? theme.selectionText : theme.muted
                        font.pixelSize: Math.round(11 * systemTheme.textScale)
                    }

                    MouseArea {
                        id: hoverArea
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        acceptedButtons: Qt.LeftButton | Qt.RightButton
                        onClicked: function(mouse) {
                            page.sidebarCursor = index;
                            if (mouse.button === Qt.RightButton) {
                                const id = modelData.id || "";
                                if (!id.startsWith("group:") && !id.startsWith("collection:"))
                                    return;
                                const pt = hoverArea.mapToItem(page, mouse.x, mouse.y);
                                sidebarItemMenu.item = modelData;
                                sidebarItemMenu.anchorX = pt.x;
                                sidebarItemMenu.anchorY = pt.y;
                                sidebarItemMenu.selected = 0;
                                sidebarItemMenu.open();
                                return;
                            }
                            controller.selectSection(modelData.id);
                            page.leaveSidebar();
                        }
                    }
                }
            }
        }

        Rectangle {
            id: sidebarAddButton
            objectName: "sidebarAddButton"
            visible: !controller.onePasswordBackend
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            anchors.rightMargin: Math.round(12 * systemTheme.textScale)
            anchors.bottomMargin: Math.round(10 * systemTheme.textScale)
            width: Math.round(32 * systemTheme.textScale)
            height: width
            radius: Math.min(6, theme.radius)
            color: sidebarAddHover.containsMouse ? theme.accent : theme.background
            border.width: 1
            border.color: sidebarAddHover.containsMouse ? theme.accent : theme.border
            z: 5

            Text {
                anchors.centerIn: parent
                text: "+"
                color: sidebarAddHover.containsMouse ? theme.selectionText : theme.foreground
                font.pixelSize: Math.round(18 * systemTheme.textScale)
                font.weight: Font.Medium
            }

            MouseArea {
                id: sidebarAddHover
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                    const pt = sidebarAddButton.mapToItem(page, sidebarAddButton.width, 0);
                    const gap = Math.round(6 * systemTheme.textScale);
                    const margin = Math.round(8 * systemTheme.textScale);
                    sidebarAddMenu.anchorX = Math.max(margin, pt.x - sidebarAddMenu.width);
                    sidebarAddMenu.anchorY = Math.max(margin, pt.y - sidebarAddMenu.height - gap);
                    sidebarAddMenu.selected = 0;
                    sidebarAddMenu.open();
                }
            }
        }
    }

    ListPane {
        id: pane
        objectName: "entriesPane"
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.left: sidebar.right
        anchors.right: parent.right
        focus: page.mode === "list" && !page.menuOpen && !page.sidebarFocused
        acceptsKeys: page.mode === "list" && !page.menuOpen && !page.sidebarFocused
        onActiveFocusChanged: if (activeFocus && page.sidebarFocused) page.sidebarFocused = false

        searchPlaceholder: i18n.t("ui.search_title")
        model: controller.entryRows
        columns: [
            { "key": "typeLabel", "title": i18n.t("ui.column_type"), "weight": 1 },
            { "key": "name", "title": i18n.t("ui.column_name"), "weight": 3 },
            // Collections belong to organizations: with none, Bitwarden only
            // has folders, which are the groups.
            controller.bitwardenBackend && controller.bitwardenOrganizations.length > 0
                ? { "key": "collections", "title": i18n.t("ui.column_collection"), "weight": 2.5, "fit": true }
                : { "key": "group", "title": i18n.t("ui.column_group"), "weight": 2.5, "fit": true },
            { "key": "username", "title": i18n.t("ui.column_login"), "weight": 2 },
            { "key": "url", "title": i18n.t("ui.column_url"), "weight": 2.5 }
        ]
        onQueryChanged: controller.query = query

        hasHeadingMenu: true
        onHeadingMenuRequested: function(x, y) {
            databasesMenu.anchorX = x - databasesMenu.width / 2;
            databasesMenu.anchorY = y;
            databasesMenu.selected = 0;
            databasesMenu.open();
        }
        heading: controller.vaultLabel
        headerActions: {
            const actions = [
                { "icon": "plus", "description": i18n.t("ui.help_add_entry"),
                  "action": function() { page.openAddForm(); } }
            ];
            if (controller.bitwardenBackend) {
                actions.push({ "icon": "send", "description": i18n.t("bitwarden.send_help"),
                               "action": function() { page.mode = "send"; } });
            }
            actions.push(
                { "icon": "dice", "description": i18n.t("generator.help"),
                  "action": function() { page.mode = "generate"; } },
                { "icon": "key", "description": controller.pinConfigured ? i18n.t("pin.disable_title")
                                                                         : i18n.t("pin.setup_title"),
                  "action": function() { page.togglePin(); } },
                { "icon": "settings", "description": i18n.t("settings.help"),
                  "action": function() { window.settingsOpen = true; } },
                { "icon": "lock", "description": i18n.t("ui.lock"),
                  "action": function() { controller.lock(); } }
            );
            return actions;
        }

        footerText: controller.hasMessage ? controller.message
                  : controller.busy ? i18n.t("app.working")
                  : controller.syncing ? i18n.t("bitwarden.syncing")
                  : ""
        footerColor: controller.hasMessage
            ? (controller.messageIsError ? theme.error : theme.alertInfo)
            : theme.muted
        footerHint: i18n.t("common.shortcuts_hint")

        onActivated: function(index) {
            const entry = page.currentEntry();
            if (entry.length === 0)
                return;
            if (entry.startsWith("send:")) {
                const url = controller.sendUrlFor(entry);
                if (url.length > 0)
                    controller.copyText(url);
                return;
            }
            if (entry.startsWith("trash:")) {
                actionsMenu.anchorX = -1;
                actionsMenu.anchorY = -1;
                actionsMenu.selected = 0;
                actionsMenu.entry = entry;
                actionsMenu.fields = ({});
                actionsMenu.sshOptions = ({});
                actionsMenu.open();
                return;
            }
            const kind = controller.entryKind(entry);
            if (kind === "note" || kind === "card" || kind === "identity")
                page.openInfo();
            else
                controller.copyPassword(entry);
        }
        onDetailsRequested: {
            const entry = page.currentEntry();
            if (!entry.startsWith("send:") && !entry.startsWith("trash:"))
                page.openInfo();
        }
        onAddRequested: page.openAddForm()
        onEditRequested: {
            const entry = page.currentEntry();
            if (!entry.startsWith("send:") && !entry.startsWith("trash:"))
                page.editEntry(entry);
        }
        onDeleteRequested: page.confirmDelete()
        onGenerateRequested: page.mode = "generate"
        onSendRequested: if (controller.bitwardenBackend) page.mode = "send"
        onSyncRequested: controller.syncBitwarden()
        onToggleSidebarRequested: {
            if (!page.sidebarOpen) {
                page.sidebarOpen = true;
                page.focusSidebar();
            } else if (!page.sidebarFocused) {
                page.focusSidebar();
            } else {
                page.sidebarOpen = false;
                page.leaveSidebar();
            }
        }
        onFocusSidebarRequested: if (page.sidebarOpen) page.focusSidebar()
        onPinToggleRequested: page.togglePin()
        onCopyPasswordRequested: {
            const entry = page.currentEntry();
            if (entry.length === 0) {
                controller.showMessage(i18n.t("app.no_entry_selected"), true);
                return;
            }
            if (entry.startsWith("send:")) {
                const url = controller.sendUrlFor(entry);
                if (url.length > 0)
                    controller.copyText(url);
                return;
            }
            if (!entry.startsWith("trash:"))
                controller.copyPassword(entry);
        }
        onCopyUsernameRequested: page.withEntry(controller.copyUsername)
        onCopyOtpRequested: page.withEntry(controller.copyOtp)
        onCopyUrlRequested: page.withEntry(controller.copyUrl)
        onOpenUrlRequested: page.withEntry(controller.openUrl)
        onHelpRequested: page.mode = "help"
        // With a database open, ESC and q lock it and go back to the list
        // instead of quitting: leaving the app is Ctrl+Q, and stepping out
        // of the vault should not need the whole window to close.
        onQuitRequested: controller.lock()
        onMenuRequested: function(menuX, menuY) {
            actionsMenu.anchorX = menuX;
            actionsMenu.anchorY = menuY;
            actionsMenu.selected = 0;
            actionsMenu.entry = page.currentEntry();
            actionsMenu.fields = controller.entryMenuFields(actionsMenu.entry);
            actionsMenu.sshOptions = controller.sshKeyOptions(actionsMenu.entry);
            actionsMenu.open();
        }
    }

    ActionsMenu {
        id: databasesMenu
        objectName: "databasesMenu"
        parent: page
        readonly property var databases: controller.openDatabases
        options: databases.map(function(db) {
            const duplicate = databases.some(other => other.path !== db.path && other.name === db.name && other.kind === db.kind);
            return (duplicate ? db.path : db.name) + " · " + db.kind;
        }).concat([i18n.t("db_app.open_another")])
        groupStarts: [databases.length]
        onClosed: pane.claimKeyboard()
        onChosen: function(index) {
            close();
            if (index === databases.length)
                controller.chooseAnotherDatabase();
            else
                controller.switchDatabase(databases[index].path);
        }
    }

    ActionsMenu {
        id: actionsMenu
        objectName: "entryActions"
        parent: page
        property string entry: ""
        property var fields: ({})
        property var sshOptions: ({})
        readonly property var groups: {
            if (entry.startsWith("trash:"))
                return [["restoreTrash", "purgeTrash"]];
            if (entry.startsWith("send:"))
                return [["copySendUrl", "deleteSend"]];
            const entryActions = [];
            if (fields.hasPassword)
                entryActions.push("copyPassword");
            if (fields.hasUsername)
                entryActions.push("copyUsername");
            if (fields.hasUrl)
                entryActions.push("copyUrl", "openUrl");
            if (fields.hasOtp)
                entryActions.push("copyOtp");
            const result = [entryActions.concat(["edit", "delete", "info"])];
            if (Object.keys(sshOptions).length > 0)
                result.push([sshOptions.inAgent ? "removeSsh" : "addSsh", "configureSsh"]);
            result.push(["chooseIcon", "clearIcon"]);
            return result;
        }
        readonly property var actions: [].concat.apply([], groups)
        readonly property var labels: ({
            "copyPassword": i18n.t("ui.context_copy_password"),
            "copyUsername": i18n.t("ui.context_copy_username"),
            "copyUrl": i18n.t("ui.context_copy_url"),
            "openUrl": i18n.t("ui.context_open_url"),
            "copyOtp": i18n.t("ui.context_copy_otp"),
            "chooseIcon": i18n.t("ui.context_choose_icon"),
            "clearIcon": i18n.t("ui.context_clear_icon"),
            "info": i18n.t("ui.context_info"),
            "edit": i18n.t("ui.context_edit"),
            "delete": i18n.t("ui.context_delete"),
            "restoreTrash": i18n.t("ui.context_restore"),
            "purgeTrash": i18n.t("ui.context_purge"),
            "copySendUrl": i18n.t("ui.context_copy_send_url"),
            "deleteSend": i18n.t("ui.context_delete"),
            "addSsh": i18n.t("ssh.add"),
            "removeSsh": i18n.t("ssh.remove"),
            "configureSsh": i18n.t("ssh.options")
        })
        options: actions.map(function(action) { return labels[action]; })
        groupStarts: {
            const starts = [];
            let at = 0;
            for (let i = 0; i < groups.length - 1; ++i) {
                at += groups[i].length;
                starts.push(at);
            }
            return starts;
        }

        onChosen: function(index) {
            close();
            const action = actions[index];
            if (action === "copyPassword")
                controller.copyPassword(entry);
            else if (action === "copyUsername")
                controller.copyUsername(entry);
            else if (action === "copyUrl")
                controller.copyUrl(entry);
            else if (action === "openUrl")
                controller.openUrl(entry);
            else if (action === "copyOtp")
                controller.copyOtp(entry);
            else if (action === "addSsh")
                controller.addSshKey(entry);
            else if (action === "removeSsh")
                controller.removeSshKey(entry);
            else if (action === "configureSsh") {
                page.selectedEntry = entry;
                sshModal.options = sshOptions;
                page.mode = "ssh";
            }
            else if (action === "chooseIcon")
                page.chooseIcon();
            else if (action === "clearIcon")
                page.withEntry(controller.clearEntryIcon);
            else if (action === "info")
                page.openInfo();
            else if (action === "edit")
                page.editEntry(entry);
            else if (action === "delete")
                page.confirmDelete(entry);
            else if (action === "restoreTrash")
                controller.restoreTrashEntry(entry.slice(6));
            else if (action === "purgeTrash")
                page.confirmDelete(entry);
            else if (action === "copySendUrl") {
                const url = controller.sendUrlFor(entry);
                if (url.length > 0)
                    controller.copyText(url);
            } else if (action === "deleteSend")
                page.confirmDelete(entry);
        }
        onClosed: pane.claimKeyboard()
    }

    Modal {
        id: sshModal
        visible: page.mode === "ssh"
        firstField: onUnlock
        heading: i18n.t("ssh.options")
        subtitle: page.selectedEntry
        acceptText: i18n.t("common.save")
        acceptEnabled: lifetime.field.acceptableInput && Number(lifetime.text) <= 2147483647
        status: controller.hasMessage && controller.messageIsError ? controller.message : ""
        statusIsError: true

        property var options: ({})
        readonly property var tabOrder: [onUnlock, confirmation, lifetime]

        function save() {
            if (acceptEnabled && controller.saveSshKeyOptions(page.selectedEntry, onUnlock.checked,
                                                              confirmation.checked, Number(lifetime.text)))
                page.mode = "list";
        }

        onShown: {
            onUnlock.checked = options.addOnUnlock;
            confirmation.checked = options.confirm;
            lifetime.text = String(options.lifetimeSeconds);
        }
        onAcceptRequested: save()
        onDismissed: page.mode = "list"

        CheckOption {
            id: onUnlock
            text: i18n.t("ssh.on_unlock")
            onSubmitted: sshModal.save()
            onCancelled: sshModal.takeKeyboard()
            onNextRequested: sshModal.moveFocus(sshModal.tabOrder, onUnlock, 1)
            onPreviousRequested: sshModal.moveFocus(sshModal.tabOrder, onUnlock, -1)
        }

        CheckOption {
            id: confirmation
            text: i18n.t("ssh.confirm")
            onSubmitted: sshModal.save()
            onCancelled: sshModal.takeKeyboard()
            onNextRequested: sshModal.moveFocus(sshModal.tabOrder, confirmation, 1)
            onPreviousRequested: sshModal.moveFocus(sshModal.tabOrder, confirmation, -1)
        }

        Field {
            id: lifetime
            width: parent.width
            label: i18n.t("ssh.lifetime")
            field.inputMethodHints: Qt.ImhDigitsOnly
            field.validator: RegularExpressionValidator { regularExpression: /[0-9]+/ }
            onSubmitted: sshModal.save()
            onCancelled: sshModal.takeKeyboard()
            onNextRequested: sshModal.moveFocus(sshModal.tabOrder, lifetime, 1)
            onPreviousRequested: sshModal.moveFocus(sshModal.tabOrder, lifetime, -1)
        }
    }

    // Turning the PIN off asks first: it is quick to undo, but undoing it
    // means typing the master password again.
    ConfirmModal {
        objectName: "pinDisable"
        visible: page.mode === "pinDisable"
        heading: i18n.t("pin.disable_title")
        question: i18n.t("pin.disable_text")
        acceptText: i18n.t("pin.disable")
        destructive: true

        onAccepted: {
            controller.disablePin();
            page.mode = "list";
        }
        onDismissed: page.mode = "list"
    }

    PinSetupModal {
        visible: page.mode === "pin"
        busy: controller.busy

        onSubmitted: function(masterPassword, pin, allowText) {
            controller.enablePin(masterPassword, pin, allowText);
            page.mode = "list";
        }
        onDismissed: page.mode = "list"
    }

    EntryFormModal {
        id: formModal
        objectName: "entryFormModal"
        sshSupported: !controller.passBackend && !controller.onePasswordBackend && Qt.platform.os !== "windows"
        noteSupported: controller.bitwardenBackend
        cardSupported: controller.bitwardenBackend
        identitySupported: controller.bitwardenBackend
        status: controller.messageIsError ? controller.message : ""
        statusIsError: true
        visible: page.mode === "form"
        passBackend: controller.passBackend
        groupRequired: controller.onePasswordBackend

        onSubmitted: function(payload) {
            if (controller.saveEntry(payload))
                page.mode = "list";
        }
        onGenerateRequested: {
            resumeDraft = true;
            page.mode = "generateForForm";
        }
        onDismissed: page.mode = "list"
    }

    // The same sheet either copies what it generated (and stays open) or
    // hands it to the form that asked for it, which stays open underneath.
    GeneratorModal {
        visible: page.mode === "generate" || page.mode === "generateForForm"
        fillMode: page.mode === "generateForForm"

        onAccepted: function(password) {
            formModal.setPassword(password);
            page.mode = "form";
        }
        onDismissed: page.mode = page.mode === "generateForForm" ? "form" : "list"
    }

    BitwardenSendModal {
        id: sendModal
        objectName: "bitwardenSendModal"
        visible: page.mode === "send"
        status: controller.messageIsError ? controller.message : ""
        statusIsError: true

        onSubmitted: function(payload) {
            if (controller.createBitwardenSend(payload))
                page.mode = "list";
        }
        onDismissed: page.mode = "list"
    }

    EntryInfoModal {
        id: infoModal
        objectName: "entryInfoModal"
        visible: page.mode === "info"
        passBackend: controller.passBackend

        onVisibleChanged: if (!visible) controller.forgetShownOtp()
        onAcceptRequested: page.editEntry(page.selectedEntry)
        onDismissed: page.mode = "list"
    }

    ActionsMenu {
        id: sidebarAddMenu
        objectName: "sidebarAddMenu"
        parent: page
        readonly property bool canCreateCollection:
            controller.bitwardenBackend && controller.bitwardenOrganizations.length > 0
        readonly property var actionKeys: canCreateCollection ? ["newGroup", "newCollection"] : ["newGroup"]
        options: canCreateCollection
            ? [i18n.t("sidebar.new_group"), i18n.t("sidebar.new_collection")]
            : [i18n.t("sidebar.new_group")]
        onChosen: function(index) {
            close();
            if (actionKeys[index] === "newCollection")
                page.mode = "createCollection";
            else
                page.mode = "createGroup";
        }
        onClosed: if (page.mode === "list") pane.claimKeyboard()
    }

    ActionsMenu {
        id: sidebarItemMenu
        objectName: "sidebarItemMenu"
        parent: page
        property var item: null
        options: [i18n.t("common.delete")]
        onChosen: function(index) {
            close();
            page.confirmSidebarDelete(item);
        }
        onClosed: if (page.mode === "list") pane.claimKeyboard()
    }

    Modal {
        id: createGroupModal
        visible: page.mode === "createGroup"
        firstField: newGroupNameField.field
        heading: i18n.t("sidebar.new_group")
        acceptText: i18n.t("common.save")
        acceptEnabled: newGroupNameField.text.trim().length > 0
        status: controller.hasMessage && controller.messageIsError ? controller.message : ""
        statusIsError: true

        function submit() {
            if (!acceptEnabled)
                return;
            if (controller.createGroup(newGroupNameField.text))
                page.mode = "list";
        }

        onShown: newGroupNameField.text = ""
        onAcceptRequested: submit()
        onDismissed: page.mode = "list"

        Field {
            id: newGroupNameField
            width: parent.width
            label: i18n.t("sidebar.group_name_label")
            placeholderText: i18n.t("sidebar.group_name_placeholder")
            onSubmitted: createGroupModal.submit()
            onCancelled: createGroupModal.takeKeyboard()
        }
    }

    Modal {
        id: createCollectionModal
        visible: page.mode === "createCollection"
        firstField: newCollectionNameField.field
        heading: i18n.t("sidebar.new_collection")
        acceptText: i18n.t("common.save")
        acceptEnabled: newCollectionNameField.text.trim().length > 0 && controller.bitwardenOrganizations.length > 0
        status: controller.hasMessage && controller.messageIsError ? controller.message : ""
        statusIsError: true

        function submit() {
            if (!acceptEnabled)
                return;
            const orgs = controller.bitwardenOrganizations;
            const org = orgs[orgSelector.currentIndex] || orgs[0];
            if (org && controller.createBitwardenCollection(org.id, newCollectionNameField.text))
                page.mode = "list";
        }

        onShown: {
            orgSelector.currentIndex = 0;
            newCollectionNameField.text = "";
        }
        onAcceptRequested: submit()
        onDismissed: page.mode = "list"

        Column {
            visible: controller.bitwardenOrganizations.length > 1
            width: parent.width
            spacing: Math.round(6 * systemTheme.textScale)

            Text {
                text: i18n.t("sidebar.organization_label")
                color: theme.muted
                font.pixelSize: Math.round(13 * systemTheme.textScale)
            }

            Segmented {
                id: orgSelector
                options: controller.bitwardenOrganizations.map(function(o) { return o.name; })
                onSubmitted: createCollectionModal.submit()
                onCancelled: createCollectionModal.takeKeyboard()
            }
        }

        Field {
            id: newCollectionNameField
            width: parent.width
            label: i18n.t("sidebar.collection_name_label")
            placeholderText: i18n.t("sidebar.collection_name_placeholder")
            onSubmitted: createCollectionModal.submit()
            onCancelled: createCollectionModal.takeKeyboard()
        }
    }

    RenameGroupModal {
        id: renameModal
        visible: page.mode === "rename"

        onSubmitted: function(name) {
            controller.renameGroup(page.selectedEntry, name);
            page.mode = "list";
        }
        onDismissed: page.mode = "list"
    }

    ConfirmModal {
        visible: page.mode === "confirmDelete"
        acceptText: i18n.t("common.delete")
        destructive: true
        question: page.selectedEntry.startsWith("trash:")
            ? i18n.t("ui.confirm_purge", { "entry": page.selectedEntryLabel })
            : page.selectedEntry.startsWith("send:")
                ? i18n.t("ui.confirm_delete_send", { "entry": page.selectedEntryLabel })
                : i18n.t("ui.confirm_delete", { "entry": page.selectedEntryLabel })

        onAccepted: {
            if (page.selectedEntry.startsWith("trash:"))
                controller.purgeTrashEntry(page.selectedEntry.slice(6));
            else if (page.selectedEntry.startsWith("send:"))
                controller.deleteBitwardenSend(page.selectedEntry.slice(5));
            else
                controller.deleteEntry(page.selectedEntry);
            page.mode = "list";
        }
        onDismissed: page.mode = "list"
    }

    ConfirmModal {
        objectName: "confirmSidebarDelete"
        visible: page.mode === "confirmSidebarDelete"
        acceptText: i18n.t("common.delete")
        destructive: true
        question: page.selectedSidebarId.startsWith("collection:")
            ? i18n.t("ui.confirm_delete_collection", { "name": page.selectedSidebarLabel })
            : i18n.t("ui.confirm_delete_group", { "name": page.selectedSidebarLabel })

        onAccepted: {
            controller.deleteSidebarItem(page.selectedSidebarId);
            page.mode = "list";
        }
        onDismissed: {
            page.mode = "list";
            page.returnToSidebar();
        }
    }

    HelpModal {
        visible: page.mode === "help"
        sections: [
            {
                "title": i18n.t("help.actions_section"),
                "items": [["Enter / Ctrl+C", i18n.t("ui.help_copy_password")],
                          ["Ctrl+U", i18n.t("ui.help_copy_username")],
                          ["Ctrl+L", i18n.t("ui.help_copy_url")],
                          ["Ctrl+Shift+L", i18n.t("ui.help_open_url")],
                          ["Ctrl+T", i18n.t("ui.help_copy_otp")],
                          ["Tab", i18n.t("ui.help_view_details")],
                          [i18n.t("common.space_key"), i18n.t("ui.help_open_menu")],
                          ["Ctrl+N", i18n.t("ui.help_add_entry")],
                          ["Ctrl+E", i18n.t("ui.help_edit_entry")],
                          ["Ctrl+X", i18n.t("ui.help_delete_entry")],
                          ["Ctrl+G", i18n.t("generator.help")],
                          ["Ctrl+S", i18n.t("ui.help_sidebar")],
                          ["Ctrl+X / Delete", i18n.t("ui.help_delete_sidebar_item")],
                          ["Ctrl+Shift+S", i18n.t("bitwarden.send_help")],
                          ["Ctrl+R", i18n.t("ui.help_sync")],
                          ["Ctrl+I", i18n.t("pin.help")]]
            },
            {
                "title": i18n.t("help.nav_section"),
                "items": [["j / k / n / p", i18n.t("help.move_selection")],
                          ["g g / G", i18n.t("help.go_top_bottom")],
                          ["u / d", i18n.t("help.half_page")],
                          ["Ctrl+Tab / Ctrl+1..9", i18n.t("db_app.switch_database")]]
            },
            {
                "title": i18n.t("help.search_section"),
                "items": [["/ i", i18n.t("help.enter_search")],
                          ["f", i18n.t("help.click_hints")],
                          ["Esc", i18n.t("ui.help_exit_search")]]
            },
            {
                "title": i18n.t("ui.help_sheets_section"),
                "items": [["Enter", i18n.t("ui.help_sheet_confirm")],
                          ["Esc", i18n.t("ui.help_sheet_cancel")],
                          ["Tab / Shift+Tab", i18n.t("ui.help_sheet_fields")],
                          ["Ctrl+G", i18n.t("ui.help_sheet_generate")],
                          ["Ctrl+R", i18n.t("ui.help_sheet_regenerate")],
                          ["Ctrl+C", i18n.t("ui.help_sheet_copy_generated")],
                          ["Ctrl+Enter", i18n.t("ui.help_sheet_save_notes")],
                          ["o", i18n.t("ui.help_sheet_open_url")],
                          ["Ctrl+D / Ctrl+F", i18n.t("ui.help_sheet_choose")],
                          ["y / n", i18n.t("ui.help_sheet_yes_no")]]
            },
            {
                "title": i18n.t("ui.help_mouse_section"),
                "items": [[i18n.t("ui.help_click_label"), i18n.t("ui.help_select_entry")],
                          [i18n.t("ui.help_double_click_label"), i18n.t("ui.help_copy_password")],
                          [i18n.t("ui.help_right_click_label"), i18n.t("ui.help_context_menu_desc")]]
            },
            {
                "title": i18n.t("help.general_section"),
                "items": [["? / Ctrl+?", i18n.t("help.this_help")],
                          ["Ctrl+O", i18n.t("settings.help")],
                          ["Esc / q", i18n.t("ui.help_lock")],
                          ["Ctrl+Q", i18n.t("help.quit_app")]]
            }
        ]

        onDismissed: page.mode = "list"
    }

    // Returning from any sheet puts the keyboard back on the list, in
    // whichever mode it was left in.
    onModeChanged: if (mode === "list") pane.claimKeyboard()
}
