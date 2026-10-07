#pragma once

#include <QByteArray>
#include <QProcessEnvironment>
#include <QString>
#include <QStringList>

// Outcome of an external command. `started` separates "the binary is not
// installed" from "the command ran and failed", which callers report
// differently.
struct ProcResult {
    bool started = false;
    bool success = false;
    QString out;
    QString err;
};

// How long a command may take before it is given up on. The CLIs omapass
// drives answer in seconds at worst (`op` is the slow one), and a run that
// never ends would otherwise keep a background task — and with it the whole
// interface — waiting for good.
constexpr int processTimeoutMs = 120000;

ProcResult runProcess(const QString &program, const QStringList &args,
                      const QByteArray &stdinData = QByteArray(),
                      const QProcessEnvironment &env = QProcessEnvironment(),
                      int timeoutMs = processTimeoutMs);

// Whether the `script` in PATH is the util-linux one, which is the only
// version that takes `-c`. The name alone does not answer it: macOS and the
// BSDs ship a `script` of their own, same name, different command line — so
// a PATH lookup says yes and the call then dies with a usage error. Where
// this is asked, that reads to the user as "1Password refused the login".
//
// Answered by running the very form the callers use, since that is the
// capability in question; the result is worked out once and kept.
bool utilLinuxScriptAvailable();
