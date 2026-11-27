import QtQuick
import QtTest
import "qrc:/"

// The generator's options are tick boxes between text fields. Tab has to
// stop on each of them, Space has to tick the one that has the focus, and
// the boxes the current mode hides have to be skipped — otherwise the
// sheet cannot be used without a mouse.
TestCase {
    id: testCase
    name: "GeneratorModal"
    when: windowShown
    visible: true
    width: 700
    height: 700

    GeneratorModal {
        id: modal
        visible: false
    }

    function open() {
        modal.visible = true;
        tryVerify(function() { return modal.opened; }, 3000);
    }

    function cleanup() {
        modal.visible = false;
        tryVerify(function() { return !modal.opened; }, 3000);
    }

    function focused() {
        const order = modal.tabOrder;
        for (let i = 0; i < order.length; ++i) {
            const item = order[i].field || order[i];
            if (item.activeFocus)
                return order[i];
        }
        return null;
    }

    function test_tab_walks_through_every_option() {
        open();
        compare(focused(), null);
        keyClick(Qt.Key_Tab);
        tryVerify(function() { return focused() === modal.tabOrder[1]; }, 3000,
                  "o teclado começa no comprimento");

        // length → twelve boxes → extra → exclude → custom → passphrase toggle
        const expected = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 1];
        for (let i = 0; i < expected.length; ++i) {
            keyClick(Qt.Key_Tab);
            compare(focused(), modal.tabOrder[expected[i]], "Tab nº " + (i + 1));
        }
    }

    function test_backtab_walks_back() {
        open();
        compare(focused(), null);
        keyClick(Qt.Key_Tab);
        tryVerify(function() { return focused() === modal.tabOrder[1]; }, 3000);

        keyClick(Qt.Key_Backtab);
        compare(focused(), modal.tabOrder[0], "volta para o modo frase-senha");
        keyClick(Qt.Key_Backtab);
        compare(focused(), modal.tabOrder[16], "e dá a volta até o último campo");
    }

    function test_space_ticks_the_focused_box() {
        open();
        compare(focused(), null);
        keyClick(Qt.Key_Tab);
        tryVerify(function() { return focused() === modal.tabOrder[1]; }, 3000);

        keyClick(Qt.Key_Tab);
        const lower = modal.tabOrder[2];
        compare(focused(), lower);
        verify(lower.checked);

        keyClick(Qt.Key_Space);
        verify(!lower.checked, "Espaço desmarca");
        keyClick(Qt.Key_Space);
        verify(lower.checked, "e marca de novo");
        compare(focused(), lower, "sem perder o foco");
    }

    function test_passphrase_mode_skips_the_password_options() {
        open();
        compare(focused(), null);
        keyClick(Qt.Key_Tab);
        tryVerify(function() { return focused() === modal.tabOrder[1]; }, 3000);

        keyClick(Qt.Key_Backtab);
        const passphrase = modal.tabOrder[0];
        compare(focused(), passphrase);
        // The mode is a pair of tabs: Space (or →) moves to the passphrase.
        keyClick(Qt.Key_Space);
        verify(modal.passphrase);

        // mode tabs → words → separator → mode tabs
        keyClick(Qt.Key_Tab);
        compare(focused(), modal.tabOrder[17]);
        keyClick(Qt.Key_Tab);
        compare(focused(), modal.tabOrder[18]);
        keyClick(Qt.Key_Tab);
        compare(focused(), passphrase);
    }

    // ← and → move between the two tabs; the password comes back with ←.
    function test_mode_tabs_follow_the_arrows() {
        open();
        compare(focused(), null);
        keyClick(Qt.Key_Tab);
        tryVerify(function() { return focused() === modal.tabOrder[1]; }, 3000);
        keyClick(Qt.Key_Backtab);
        keyClick(Qt.Key_Right);
        verify(modal.passphrase);
        keyClick(Qt.Key_Left);
        verify(!modal.passphrase);
    }

    SignalSpy {
        id: acceptedSpy
        target: modal
        signalName: "accepted"
    }

    // Copying leaves the sheet open, so a password the clipboard has
    // already forgotten can still be read and copied again.
    function test_copy_keeps_the_sheet_open() {
        open();
        acceptedSpy.clear();
        const before = controller.copiedSecrets;
        keyClick(Qt.Key_Tab);
        tryVerify(function() { return focused() === modal.tabOrder[1]; }, 3000);

        keyClick(Qt.Key_Return);
        compare(controller.copiedSecrets, before + 1, "Enter copia");
        verify(modal.opened, "e o gerador continua aberto");
        verify(modal.copied, "avisando que copiou");
        compare(acceptedSpy.count, 0);
        compare(modal.cancelText, i18n.t("common.close"));
    }

    // From the entry form the sheet still hands the password over and closes.
    function test_fill_mode_hands_the_password_over() {
        modal.fillMode = true;
        open();
        acceptedSpy.clear();
        const before = controller.copiedSecrets;
        keyClick(Qt.Key_Tab);
        tryVerify(function() { return focused() === modal.tabOrder[1]; }, 3000);

        keyClick(Qt.Key_Return);
        compare(acceptedSpy.count, 1);
        compare(acceptedSpy.signalArguments[0][0], "senha-de-teste");
        compare(controller.copiedSecrets, before, "sem copiar");
        modal.fillMode = false;
    }

    // Ctrl+C copies the password wherever the keyboard is in the sheet,
    // and leaves it open.
    function test_ctrl_c_copies_the_password() {
        open();
        acceptedSpy.clear();
        const before = controller.copiedSecrets;
        keyClick(Qt.Key_C, Qt.ControlModifier);
        compare(controller.copiedSecrets, before + 1, "Ctrl+C sem campo focado");
        verify(modal.opened);
        verify(modal.copied);

        keyClick(Qt.Key_Tab);
        tryVerify(function() { return focused() === modal.tabOrder[1]; }, 3000);
        keyClick(Qt.Key_C, Qt.ControlModifier);
        compare(controller.copiedSecrets, before + 2, "Ctrl+C num campo sem seleção");
        compare(acceptedSpy.count, 0);
    }

    // Text selected in a field is what Ctrl+C copies there, as anywhere.
    function test_ctrl_c_leaves_selected_text_alone() {
        open();
        const before = controller.copiedSecrets;
        keyClick(Qt.Key_Tab);
        tryVerify(function() { return focused() === modal.tabOrder[1]; }, 3000);
        modal.tabOrder[1].field.selectAll();
        verify(modal.tabOrder[1].field.selectedText.length > 0);
        keyClick(Qt.Key_C, Qt.ControlModifier);
        compare(controller.copiedSecrets, before, "a seleção do campo vence");
    }

    // From the entry form Ctrl+C copies too, without handing it over.
    function test_ctrl_c_copies_in_fill_mode() {
        modal.fillMode = true;
        open();
        acceptedSpy.clear();
        const before = controller.copiedSecrets;
        keyClick(Qt.Key_C, Qt.ControlModifier);
        compare(controller.copiedSecrets, before + 1);
        compare(acceptedSpy.count, 0);
        verify(modal.opened);
        modal.fillMode = false;
    }
}
