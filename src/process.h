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
// drives answer in seconds at worst (`bw` is the slow one), and a run that
// never ends would otherwise keep a background task — and with it the whole
// interface — waiting for good.
constexpr int processTimeoutMs = 120000;

ProcResult runProcess(const QString &program, const QStringList &args,
                      const QByteArray &stdinData = QByteArray(),
                      const QProcessEnvironment &env = QProcessEnvironment(),
                      int timeoutMs = processTimeoutMs);
