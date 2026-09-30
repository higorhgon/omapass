#include "process.h"

#include <QObject>
#include <QProcess>
#include <QStandardPaths>

namespace {

// The probe is a `true` under a pseudo terminal: it answers at once, and a
// `script` that does not understand the arguments fails on them before
// running anything at all.
constexpr int scriptProbeTimeoutMs = 5000;

}

ProcResult runProcess(const QString &program, const QStringList &args,
                      const QByteArray &stdinData, const QProcessEnvironment &env, int timeoutMs) {
    ProcResult result;

    QProcess process;
    if (!env.isEmpty())
        process.setProcessEnvironment(env);
    process.start(program, args);

    if (!process.waitForStarted(-1)) {
        result.err = process.errorString();
        return result;
    }
    result.started = true;

    if (!stdinData.isEmpty())
        process.write(stdinData);
    process.closeWriteChannel();

    if (!process.waitForFinished(timeoutMs)) {
        // Killed rather than left behind: it is holding the vault's turn.
        process.kill();
        process.waitForFinished(1000);
        result.out = QString::fromUtf8(process.readAllStandardOutput());
        result.err = QObject::tr("%1 did not answer in %2 s")
                         .arg(program, QString::number(timeoutMs / 1000));
        return result;
    }

    result.success = process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
    result.out = QString::fromUtf8(process.readAllStandardOutput());
    result.err = QString::fromUtf8(process.readAllStandardError());
    return result;
}

bool utilLinuxScriptAvailable() {
    static const bool available = []() {
        if (QStandardPaths::findExecutable(QStringLiteral("script")).isEmpty())
            return false;

        // Deliberately the same shape the real calls use. Asking for
        // `--version` instead would be worse than useless: the BSD script
        // reads it as a bundle of single letters, none of which is a
        // request for the version, and goes on to open an interactive
        // shell that sits there until the timeout.
        const ProcResult probe = runProcess(QStringLiteral("script"),
                                            {QStringLiteral("-qec"), QStringLiteral("true"),
                                             QStringLiteral("/dev/null")},
                                            QByteArray(), QProcessEnvironment(),
                                            scriptProbeTimeoutMs);
        return probe.started && probe.success;
    }();
    return available;
}
