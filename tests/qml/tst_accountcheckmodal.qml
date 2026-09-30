import QtQuick
import QtTest
import "qrc:/"

// The sheet that stands between picking an account and being asked for its
// master password. It has to name the account it is waiting on — the whole
// point is telling the user why nothing is happening — and ESC has to get
// out, since the check behind it can take seconds.
TestCase {
    id: testCase
    name: "AccountCheckModal"
    when: windowShown
    visible: true
    width: 600
    height: 400

    property int cancelledCount: 0

    AccountCheckModal {
        id: sheet
        visible: true
        accountName: "pessoa@exemplo.com"

        onCancelled: testCase.cancelledCount += 1
    }

    function test_says_which_account_it_is_waiting_on() {
        const body = findChild(sheet, "accountCheckText");
        verify(body !== null, "a folha desenhou o texto");
        verify(body.text.indexOf("pessoa@exemplo.com") !== -1,
               "o texto nomeia a conta: " + body.text);
    }

    function test_escape_gives_up_on_the_wait() {
        testCase.cancelledCount = 0;
        keyClick(Qt.Key_Escape);
        compare(testCase.cancelledCount, 1);
    }
}
