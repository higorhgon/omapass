// The 1Password CLI: sign-in, index and edits.

#include "support.h"

#include "onepasswordlogin.h"
#include "onepasswordvault.h"
#include "opjson.h"
#include "i18n.h"

class TestOnePassword : public QObject {
    Q_OBJECT

private slots:
    void onePasswordAccountsFallBackToTheUserId() {
        const QVector<OpAccount> accounts = parseOpAccounts(opFixture("accounts.json"));
        QCOMPARE(accounts.size(), 2);
        QCOMPARE(accounts.at(0).key(), QStringLiteral("minha"));
        QCOMPARE(accounts.at(0).email, QStringLiteral("pessoa@exemplo.com"));
        QCOMPARE(accounts.at(1).key(), accounts.at(1).userUuid);
    }

    void onePasswordSignInAnswersTheTwoStepPrompt() {
        FakeOp op;

        OnePasswordLogin login;
        QString variable;
        QString token;
        QString error;
        bool finished = false;
        connect(&login, &OnePasswordLogin::promptShown, &login, [&login](OpPrompt prompt) {
            if (prompt == OpPrompt::TwoFactorCode)
                login.sendCode(QStringLiteral("123456"));
        });
        connect(&login, &OnePasswordLogin::succeeded, &login,
                [&](const QString &, const QString &sessionVariable, const Secret &session) {
            variable = sessionVariable;
            token = session.toString();
            finished = true;
        });
        connect(&login, &OnePasswordLogin::failed, &login, [&](const QString &message, OpError) {
            error = message;
            finished = true;
        });

        login.startSignIn(QStringLiteral("teste"), Secret(QStringLiteral("senha-certa")));

        QTRY_VERIFY_WITH_TIMEOUT(finished, 20000);
        QVERIFY2(error.isEmpty(), qPrintable(error));
        // The name comes from what op printed, not from the account: naming
        // it here is how a session ends up unused.
        QCOMPARE(variable, QStringLiteral("OP_SESSION_qwertyuiopasdfgh"));
        QCOMPARE(token, QStringLiteral("TOKEN-DE-SESSAO"));
    }

    void onePasswordAddKeepsGoingWhenOpComplainsAboutAnAccountItAdded() {
        FakeOp op;
        op.setAccounts({});

        OnePasswordLogin login;
        QString token;
        QString error;
        bool finished = false;
        connect(&login, &OnePasswordLogin::promptShown, &login, [&login](OpPrompt prompt) {
            if (prompt == OpPrompt::TwoFactorCode)
                login.sendCode(QStringLiteral("123456"));
        });
        connect(&login, &OnePasswordLogin::succeeded, &login,
                [&](const QString &, const QString &, const Secret &session) {
            token = session.toString();
            finished = true;
        });
        connect(&login, &OnePasswordLogin::failed, &login, [&](const QString &message, OpError) {
            error = message;
            finished = true;
        });

        login.start(QStringLiteral("my.1password.com"), QStringLiteral("teste@exemplo.com"),
                    Secret(QStringLiteral("A3-CHAVE")), Secret(QStringLiteral("senha-certa")),
                    QStringLiteral("teste"));

        QTRY_VERIFY_WITH_TIMEOUT(finished, 20000);
        // `op account add` ends with something to say over an account it did
        // add; what settles it is op listing the account, and the session
        // follows.
        QVERIFY2(error.isEmpty(), qPrintable(error));
        QCOMPARE(token, QStringLiteral("TOKEN-DE-SESSAO"));
    }

    void onePasswordLogoutRemovesTheAccountEitherWay() {
        FakeOp op;

        // With no session, `op account forget` is the one that removes it.
        QString error;
        QVERIFY2(OnePasswordVault::logout(QStringLiteral("teste"), &error), qPrintable(error));
        QVERIFY(!OnePasswordVault::hasAccount(QStringLiteral("teste")));

        // With one, op refuses that and points at the sign-out instead.
        op.setAccounts({QStringLiteral("teste")});
        op.setSignedIn(true);
        QVERIFY2(OnePasswordVault::logout(QStringLiteral("teste"), &error), qPrintable(error));
        QVERIFY(!OnePasswordVault::hasAccount(QStringLiteral("teste")));
    }

    void onePasswordLogoutSaysSoWhenOpWillNotLetGo() {
        FakeOp op;
        // op believes a session is live and no sign-out can end it without
        // the token: the state omapass cannot talk its way out of.
        op.setSignedIn(true);
        qputenv("OP_FAKE_STUCK", "1");

        QString error;
        QVERIFY(!OnePasswordVault::logout(QStringLiteral("teste"), &error));
        QVERIFY(!error.isEmpty());
        QVERIFY(OnePasswordVault::hasAccount(QStringLiteral("teste")));
        qunsetenv("OP_FAKE_STUCK");
    }

    void onePasswordShellCommandQuotesItsArguments() {
        QCOMPARE(opShellCommand({QStringLiteral("signin"), QStringLiteral("--account"),
                                 QStringLiteral("minha")}),
                 QStringLiteral("op 'signin' '--account' 'minha'"));
        // A shorthand with a quote in it would otherwise end the string and
        // let the rest be read as more shell.
        QCOMPARE(opShellCommand({QStringLiteral("account"), QStringLiteral("forget"),
                                 QStringLiteral("a'b")}),
                 QStringLiteral("op 'account' 'forget' 'a'\\''b'"));
    }

    void onePasswordSignInNamesItsOwnSessionVariable() {
        // What `op signin` prints without --raw, comments and all.
        const OpSession named = parseOpSignIn(QStringLiteral(
            "export OP_SESSION_abcdefghij=\"token-de-sessao\"\n"
            "# This command is meant to be used with your shell's eval function.\n"
            "# Run 'eval $(op signin --account minha)' to sign in.\n"));
        QCOMPARE(named.variable, QStringLiteral("OP_SESSION_abcdefghij"));
        QCOMPARE(named.token, QStringLiteral("token-de-sessao"));

        // With --raw, or under a terminal that echoed the prompts back, only
        // the token is there and the caller names the variable itself.
        const OpSession raw = parseOpSignIn(QStringLiteral(
            "Enter the password for pessoa@exemplo.com at my.1password.com: \r\n"
            "token-de-sessao\r\n"));
        QVERIFY(raw.variable.isEmpty());
        QCOMPARE(raw.token, QStringLiteral("token-de-sessao"));

        QVERIFY(parseOpSignIn(QString()).token.isEmpty());
    }

    void onePasswordShorthandComesFromTheEmail() {
        // `op` would name the account after the address; the e-mail says
        // whose it is.
        QCOMPARE(opShorthandFor(QStringLiteral("Pessoa.Sobrenome@exemplo.com"),
                                QStringLiteral("my.1password.com")),
                 QStringLiteral("pessoa_sobrenome"));
        QCOMPARE(opShorthandFor(QStringLiteral("pessoa+trabalho@exemplo.com"),
                                QStringLiteral("my.1password.com")),
                 QStringLiteral("pessoa_trabalho"));
        // Nothing usable in the e-mail: back to what op itself would do.
        QCOMPARE(opShorthandFor(QString(), QStringLiteral("Empresa.1password.com")),
                 QStringLiteral("empresa"));

        // The same person on two domains would collide, and op refuses the
        // second account.
        const QStringList taken{QStringLiteral("pessoa"), QStringLiteral("pessoa2")};
        QCOMPARE(opUniqueShorthand(QStringLiteral("outra"), taken), QStringLiteral("outra"));
        QCOMPARE(opUniqueShorthand(QStringLiteral("pessoa"), taken), QStringLiteral("pessoa3"));
    }

    void onePasswordIndexNestsTagsUnderTheVault() {
        const OpIndex index = buildOpIndex(opFixture("items.json"), opFixture("vaults.json"));

        QCOMPARE(index.groups, QStringList({QStringLiteral("Pessoal"),
                                            QStringLiteral("Pessoal/Streaming"),
                                            QStringLiteral("Trabalho"),
                                            QStringLiteral("Trabalho/Assinaturas"),
                                            QStringLiteral("Trabalho/Trabalho"),
                                            QStringLiteral("Trabalho/Trabalho/Deploy"),
                                            QStringLiteral("Vazio")}));

        // A password item sits at its vault's root; a credit card is not
        // shown at all; a tag with stray spaces and empty segments is the
        // same group as the tidy one.
        QVERIFY(index.items.contains(QStringLiteral("Pessoal/Cofre do roteador")));
        QVERIFY(index.items.contains(QStringLiteral("Trabalho/Trabalho/Deploy/Servidor")));
        for (const QString &entry : std::as_const(index.entries))
            QVERIFY(!entry.contains(QStringLiteral("Cartao")));

        QCOMPARE(index.vaults.value(QStringLiteral("Pessoal")), QStringLiteral("v1"));
        QCOMPARE(index.vaults.value(QStringLiteral("Vazio")), QStringLiteral("v3"));
    }

    void onePasswordIndexFilesAnItemUnderItsFirstTag() {
        const OpIndex index = buildOpIndex(opFixture("items.json"), opFixture("vaults.json"));

        // "GitLab / CI" carries both "Trabalho/Deploy" and "Assinaturas";
        // the first in alphabetical order is the one that places it, and the
        // slash in the title is shown as a look-alike.
        const QString path = QStringLiteral("Trabalho/Assinaturas/GitLab ") + QChar(0x2215)
            + QStringLiteral(" CI");
        QVERIFY(index.items.contains(path));
        const OpItemRef ref = index.items.value(path);
        QCOMPARE(ref.title, QStringLiteral("GitLab / CI"));
        QCOMPARE(ref.vaultId, QStringLiteral("v2"));
        QCOMPARE(ref.tagPath, QStringLiteral("Assinaturas"));
    }

    void onePasswordIndexDisambiguatesDuplicateTitles() {
        const OpIndex index = buildOpIndex(opFixture("items.json"), opFixture("vaults.json"));
        QVERIFY(index.items.contains(QStringLiteral("Pessoal/Streaming/Netflix [i1]")));
        QVERIFY(index.items.contains(QStringLiteral("Pessoal/Streaming/Netflix [i2]")));
        QVERIFY(!index.items.contains(QStringLiteral("Pessoal/Streaming/Netflix")));
    }

    void onePasswordEntryDataReadsThePrimaryUrl() {
        const QJsonObject item = QJsonDocument::fromJson(opFixture("item.json")).object();
        const EntryData data = opEntryData(item);
        QCOMPARE(data.username, QStringLiteral("pessoa@empresa.com"));
        QCOMPARE(data.password.toString(), QStringLiteral("senha-antiga"));
        QCOMPARE(data.url, QStringLiteral("https://gitlab.exemplo.com"));
        QCOMPARE(data.notes, QStringLiteral("nota antiga"));
        QVERIFY(!opHasPasskey(item));
    }

    void onePasswordEditKeepsFieldsItDoesNotModel() {
        EntryData data;
        data.username = QStringLiteral("nova-pessoa");
        data.password = Secret(QStringLiteral("nova-senha"));
        data.url = QStringLiteral("https://novo.exemplo.com");
        data.notes = QStringLiteral("nota nova");

        const QJsonObject item = QJsonDocument::fromJson(
            applyOpEntryData(opFixture("item.json"), QStringLiteral("GitLab"),
                             QStringLiteral("Producao"), data)).object();

        QCOMPARE(item.value(QStringLiteral("title")).toString(), QStringLiteral("GitLab"));
        // The tag that placed the item gives way to the new group; the other
        // one is the user's own filing and stays.
        QCOMPARE(item.value(QStringLiteral("tags")).toVariant().toStringList(),
                 QStringList({QStringLiteral("Producao"), QStringLiteral("Trabalho/Deploy")}));
        QCOMPARE(item.value(QStringLiteral("sections")).toArray().size(), 1);

        const QJsonArray fields = item.value(QStringLiteral("fields")).toArray();
        QCOMPARE(fields.size(), 5);
        QCOMPARE(fields.at(0).toObject().value(QStringLiteral("value")).toString(),
                 QStringLiteral("nova-pessoa"));
        QCOMPARE(fields.at(1).toObject().value(QStringLiteral("value")).toString(),
                 QStringLiteral("nova-senha"));
        QVERIFY(fields.at(1).toObject().contains(QStringLiteral("password_details")));
        QCOMPARE(fields.at(3).toObject().value(QStringLiteral("type")).toString(),
                 QStringLiteral("OTP"));
        QCOMPARE(fields.at(4).toObject().value(QStringLiteral("value")).toString(),
                 QStringLiteral("producao"));

        const QJsonArray urls = item.value(QStringLiteral("urls")).toArray();
        QCOMPARE(urls.size(), 2);
        QCOMPARE(urls.at(0).toObject().value(QStringLiteral("href")).toString(),
                 QStringLiteral("https://novo.exemplo.com"));
        QCOMPARE(urls.at(1).toObject().value(QStringLiteral("href")).toString(),
                 QStringLiteral("https://espelho.exemplo.com"));
    }

    void onePasswordNewItemCarriesTheVaultAndTheTag() {
        EntryData data;
        data.password = Secret(QStringLiteral("p"));

        const QJsonObject item = QJsonDocument::fromJson(
            opNewItemJson(QStringLiteral("Site"), QStringLiteral("v1"),
                          QStringLiteral(" Casa / Rede "), data)).object();

        QCOMPARE(item.value(QStringLiteral("category")).toString(), QStringLiteral("LOGIN"));
        QCOMPARE(item.value(QStringLiteral("vault")).toObject().value(QStringLiteral("id")).toString(),
                 QStringLiteral("v1"));
        QCOMPARE(item.value(QStringLiteral("tags")).toVariant().toStringList(),
                 QStringList({QStringLiteral("Casa/Rede")}));
        // Only the password was filled in, so no empty username or notes
        // field is invented.
        const QJsonArray fields = item.value(QStringLiteral("fields")).toArray();
        QCOMPARE(fields.size(), 1);
        QCOMPARE(fields.at(0).toObject().value(QStringLiteral("purpose")).toString(),
                 QStringLiteral("PASSWORD"));
        QVERIFY(item.value(QStringLiteral("urls")).toArray().isEmpty());
    }

    void onePasswordErrorsAreClassified() {
        QCOMPARE(classifyOpError(QStringLiteral(
                     "[ERROR] 2026/09/17 12:00:00 session expired, sign in to create a new session")),
                 OpError::SessionExpired);
        QCOMPARE(classifyOpError(QStringLiteral(
                     "You are not currently signed in. Please run `op signin --help` for instructions")),
                 OpError::NotSignedIn);
        QCOMPARE(classifyOpError(QStringLiteral("No accounts configured for use with 1Password CLI.")),
                 OpError::NoAccount);
        QCOMPARE(classifyOpError(QStringLiteral("[ERROR] Incorrect Secret Key")), OpError::WrongSecretKey);
        QCOMPARE(classifyOpError(QStringLiteral("[ERROR] username/password authentication failed")),
                 OpError::WrongPassword);
        QCOMPARE(classifyOpError(QStringLiteral("[ERROR] rate limit exceeded")), OpError::RateLimited);
        QCOMPARE(classifyOpError(QStringLiteral("outra coisa qualquer")), OpError::Other);
        QCOMPARE(classifyOpError(QString()), OpError::None);
    }

    void onePasswordPromptsAreDetected() {
        QCOMPARE(detectOpPrompt(QStringLiteral("Enter your sign-in address (example.1password.com): ")),
                 OpPrompt::SignInAddress);
        QCOMPARE(detectOpPrompt(QStringLiteral(
                     "Enter the email address for your account on minha.1password.com: ")),
                 OpPrompt::Email);
        QCOMPARE(detectOpPrompt(QStringLiteral(
                     "Enter the Secret Key for pessoa@exemplo.com on minha.1password.com: ")),
                 OpPrompt::SecretKey);
        QCOMPARE(detectOpPrompt(QStringLiteral(
                     "Enter the Secret Key for pessoa@exemplo.com on minha.1password.com: \n"
                     "Enter the password for pessoa@exemplo.com at minha.1password.com: ")),
                 OpPrompt::Password);
        QCOMPARE(detectOpPrompt(QStringLiteral(
                     "Enter the password for pessoa@exemplo.com at minha.1password.com: \n"
                     "Enter your 6-digit authentication code: ")),
                 OpPrompt::TwoFactorCode);
        // What `op signin` actually prints for an account with two-step
        // verification, spelled out rather than in digits.
        QCOMPARE(detectOpPrompt(QStringLiteral(
                     "Enter the password for pessoa@exemplo.com at my.1password.com:\r\n"
                     "Enter your six-digit authentication code:")),
                 OpPrompt::TwoFactorCode);
        // Other wordings the code has been asked for: a prompt that goes
        // unrecognised is a prompt nobody answers, and the run hangs.
        QCOMPARE(detectOpPrompt(QStringLiteral("Enter your one-time password: ")),
                 OpPrompt::TwoFactorCode);
        QCOMPARE(detectOpPrompt(QStringLiteral("Enter the verification code we sent you: ")),
                 OpPrompt::TwoFactorCode);
        QCOMPARE(detectOpPrompt(QStringLiteral("carregando")), OpPrompt::None);
    }
};

OMAPASS_TEST(TestOnePassword)
#include "tst_onepassword.moc"
