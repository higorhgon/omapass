import QtQuick
import QtTest
import "qrc:/"

// Logging into Bitwarden. The server comes filled in with where bw points
// now (bitwarden.com unless it was set to a Vaultwarden or another server),
// so the keyboard starts on the e-mail, and what is typed in the server
// field goes out with the credentials.
TestCase {
    id: testCase
    name: "LoginModal"
    when: windowShown
    visible: true
    width: 700
    height: 500

    LoginModal {
        id: modal
        visible: false
        busy: false
        server: "https://vault.example.com"
    }

    SignalSpy {
        id: submitted
        target: modal
        signalName: "credentialsSubmitted"
    }

    function cleanup() {
        modal.visible = false;
        tryVerify(function() { return !modal.opened; }, 3000);
        submitted.clear();
    }

    function test_server_comes_filled_in() {
        modal.step = "credentials";
        modal.visible = true;
        tryVerify(function() { return modal.opened; }, 3000);

        const server = findChild(modal, "serverField");
        compare(server.text, "https://vault.example.com");

        const email = findChild(modal, "emailField");
        tryVerify(function() { return email.field.focus; }, 3000,
                  "com o servidor preenchido, o teclado começa no e-mail");
    }

    function test_server_goes_out_with_the_credentials() {
        modal.step = "credentials";
        modal.visible = true;
        tryVerify(function() { return modal.opened; }, 3000);

        findChild(modal, "serverField").text = "vw.lan";
        findChild(modal, "emailField").text = "a@b.com";
        findChild(modal, "passwordField").text = "segredo";
        modal.submitCredentials();

        compare(submitted.count, 1);
        compare(submitted.signalArguments[0][0], "vw.lan");
        compare(submitted.signalArguments[0][1], "a@b.com");
        compare(submitted.signalArguments[0][2], "segredo");
    }

    function test_empty_server_is_asked_for() {
        modal.step = "credentials";
        modal.visible = true;
        tryVerify(function() { return modal.opened; }, 3000);

        const server = findChild(modal, "serverField");
        server.text = "";
        findChild(modal, "emailField").text = "a@b.com";
        findChild(modal, "passwordField").text = "segredo";
        modal.submitCredentials();

        compare(submitted.count, 0);
        tryVerify(function() { return server.field.focus; }, 3000);
    }
}
