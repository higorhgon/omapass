#pragma once

#include <QObject>
#include <QProcess>
#include <QSet>

#include "opjson.h"
#include "secret.h"

// One run of `op account add` or `op signin`, driven asynchronously, with
// the two-step code asked of the user while the process waits.
//
// Both run under a pseudo terminal (`script`, from util-linux), because with
// stdin on a pipe `op` refuses to ask anything — and the two-step code is
// something only the user has. With a terminal it prompts just as it does
// for a person, and each prompt is answered as it appears. Without `script`
// on the machine the answers still go in on stdin, which is enough for an
// account that does not ask for a code.
class OnePasswordLogin : public QObject {
    Q_OBJECT

public:
    explicit OnePasswordLogin(QObject *parent = nullptr);
    ~OnePasswordLogin() override;

    // `shorthand` is what `op` will know the account by, and what the list
    // shows; the caller picks it (see opShorthandFor).
    void start(const QString &address, const QString &email, const Secret &secretKey,
               const Secret &password, const QString &shorthand);
    // Opens a session for an account that is already on this device.
    void startSignIn(const QString &account, const Secret &password);
    void sendCode(const QString &code);
    void cancel();

signals:
    // Waiting on the user; the only prompt that reaches here is the
    // two-step code, since the rest is answered from what was typed in the
    // login sheet.
    void promptShown(OpPrompt prompt);
    // `sessionVariable` is the name op printed with the token, empty when
    // it did not say.
    void succeeded(const QString &shorthand, const QString &sessionVariable, const Secret &session);
    void failed(const QString &error, OpError kind);

private:
    void onOutput();
    void onFinished(int exitCode, QProcess::ExitStatus status);
    void answer(const Secret &secret);
    void runOp(const QStringList &args, const QProcessEnvironment &env);
    void begin(const QString &program, const QStringList &args, const QProcessEnvironment &env);
    void wipeBuffers();

    QProcess *m_process = nullptr;
    QString m_stdout;
    QString m_stderr;
    QString m_shorthand;
    Secret m_secretKey;
    Secret m_password;
    // Set while op is expected to ask for the password itself, rather than
    // read it from stdin without asking.
    bool m_awaitingPasswordPrompt = false;
    QSet<int> m_promptsSeen;
    bool m_stopping = false;
};
