#pragma once

#include <QObject>
#include <QProcess>
#include <QSet>

#include "opjson.h"
#include "secret.h"

// One run of `op account add`, driven asynchronously. Unlike every other op
// call this one is interactive: the Secret Key, the password and, when the
// account has two-step verification, the code are asked for on a prompt. The
// answers omapass already has are written as each prompt appears; the code
// is asked of the user while the process waits.
class OnePasswordLogin : public QObject {
    Q_OBJECT

public:
    explicit OnePasswordLogin(QObject *parent = nullptr);
    ~OnePasswordLogin() override;

    void start(const QString &address, const QString &email, const Secret &secretKey,
               const Secret &password);
    void sendCode(const QString &code);
    void cancel();

    // The shorthand `op` will know this account by, derived from the address
    // (`minha.1password.com` → `minha`). Exposed so the caller can remember
    // the account under the same name.
    static QString shorthandFor(const QString &address);

signals:
    // Waiting on the user; the only prompt that reaches here is the
    // two-step code, since the rest is answered from what was typed in the
    // login sheet.
    void promptShown(OpPrompt prompt);
    void succeeded(const QString &shorthand, const Secret &session);
    void failed(const QString &error, OpError kind);

private:
    void onOutput();
    void onFinished(int exitCode, QProcess::ExitStatus status);
    void answer(const Secret &secret);

    QProcess *m_process = nullptr;
    QString m_stdout;
    QString m_stderr;
    QString m_shorthand;
    Secret m_secretKey;
    Secret m_password;
    QSet<int> m_promptsSeen;
    bool m_stopping = false;
};
