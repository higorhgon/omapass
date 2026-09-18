#pragma once

#include <QObject>
#include <QProcess>
#include <QSet>

#include "opjson.h"
#include "secret.h"

// One run of `op account add`, driven asynchronously. With stdin on a pipe
// `op` never prompts: the address and the e-mail are flags, the Secret Key
// comes from OP_SECRET_KEY and the password is read from stdin. What cannot
// be known up front is the two-step code, so the process is kept alive while
// the interface asks the user for it and the answer is written to its stdin.
class OnePasswordLogin : public QObject {
    Q_OBJECT

public:
    explicit OnePasswordLogin(QObject *parent = nullptr);
    ~OnePasswordLogin() override;

    // `shorthand` is what `op` will know the account by; empty lets op make
    // one out of the address.
    void start(const QString &address, const QString &email, const Secret &secretKey,
               const Secret &password, const QString &shorthand = QString());
    void sendCode(const QString &code);
    void cancel();

    // The shorthand `op` derives from an address when none is given
    // (`my.1password.com` → `my`). Exposed so the caller can guess the name
    // the account will answer to.
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
    Secret m_password;
    QSet<int> m_promptsSeen;
    bool m_stopping = false;
};
