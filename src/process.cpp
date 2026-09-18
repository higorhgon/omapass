#include "process.h"

#include <QObject>
#include <QProcess>

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
