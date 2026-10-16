#include "kdbx2pass.h"

#include "i18n.h"
#include "kdbx.h"
#include "keepassvault.h"
#include "process.h"
#include "secret.h"

#include <QTextStream>

#include <cstdio>

#if defined(Q_OS_UNIX)
#include <termios.h>
#include <unistd.h>
#endif

namespace {

QTextStream &stdOut() {
    static QTextStream stream(stdout);
    return stream;
}

Secret promptPassword(const QString &prompt) {
    stdOut() << prompt;
    stdOut().flush();

#if defined(Q_OS_UNIX)
    termios original;
    const bool isTerminal = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &original) == 0;
    if (isTerminal) {
        termios quiet = original;
        quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
    }
#endif

    QTextStream in(stdin);
    const QString line = in.readLine();

#if defined(Q_OS_UNIX)
    if (isTerminal) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
        stdOut() << '\n';
        stdOut().flush();
    }
#endif

    return Secret(line);
}

QString runPassCommand(const QStringList &args, const QByteArray &stdinData) {
    const ProcResult result = runProcess(QStringLiteral("pass"), args, stdinData);
    if (!result.started)
        return I18n::t(QStringLiteral("pass.spawn_error"), QStringLiteral("err"), result.err);
    if (!result.success) {
        const QString reported = result.err.trimmed();
        return reported.isEmpty()
            ? I18n::t(QStringLiteral("kdbx2pass.pass_cmd_failed"), QStringLiteral("cmd"),
                      args.join(QLatin1Char(' ')))
            : reported;
    }
    return QString();
}

}

namespace Kdbx2Pass {

// Replaces anything outside [unicode letters/digits, `_-. `] with `_`,
// mirroring the `re.sub(r'[^\w\-. ]', '_', title)` of the original script.
QString sanitizeTitle(const QString &title) {
    QString safe;
    safe.reserve(title.size());
    for (const QChar c : title) {
        const bool keep = c.isLetterOrNumber() || c == QLatin1Char('_') || c == QLatin1Char('-')
            || c == QLatin1Char('.') || c == QLatin1Char(' ');
        safe.append(keep ? c : QLatin1Char('_'));
    }

    const QString trimmed = safe.trimmed();
    return trimmed.isEmpty() ? I18n::t(QStringLiteral("kdbx2pass.no_title")) : trimmed;
}

QString run(const QString &dbPath, const QStringList &recipients) {
    if (recipients.isEmpty())
        return I18n::t(QStringLiteral("cli.kdbx2pass_usage"));

    // 1. Point the password store at the right recipients.
    QString error = runPassCommand(QStringList{QStringLiteral("init"), QStringLiteral("--")} + recipients, QByteArray());
    if (!error.isEmpty())
        return error;

    // 2. Open the database, asking for the master password once.
    const Secret password = promptPassword(
        I18n::t(QStringLiteral("kdbx2pass.master_password_prompt"), QStringLiteral("db"), dbPath));

    KdbxStatus status = KdbxStatus::Corrupt;
    QString detail;
    const std::unique_ptr<KdbxDatabase> db = KdbxDatabase::open(dbPath, password, &status, &detail);
    if (!db)
        return KeepassVault::openError(status, detail);

    // 3. Import each entry; the recycle bin stays behind.
    const auto entries = db->allEntries(false);
    if (entries.isEmpty())
        return I18n::t(QStringLiteral("kdbx2pass.empty_csv"));

    for (const auto &item : entries) {
        const QString &path = item.first;
        const KdbxEntry &entry = item.second;

        const int slash = path.lastIndexOf(QLatin1Char('/'));
        const QString group = slash < 0 ? QString() : path.left(slash);

        QString title = entry.title.trimmed();
        if (title.isEmpty())
            title = I18n::t(QStringLiteral("kdbx2pass.no_title"));

        const QString username = entry.username;
        const Secret &entryPassword = entry.password;
        const QString url = entry.url;
        const QString notes = entry.notes;

        const QString safeTitle = sanitizeTitle(title);
        const QString entryPath = group.isEmpty() ? safeTitle
                                                  : group + QLatin1Char('/') + safeTitle;

        // The multi-line shape pass expects: line 1 the password, the rest
        // metadata.
        QByteArray content = entryPassword.bytes();
        if (!username.isEmpty())
            content.append(QStringLiteral("\nusername: %1").arg(username).toUtf8());
        if (!url.isEmpty())
            content.append(QStringLiteral("\nurl: %1").arg(url).toUtf8());
        if (!notes.isEmpty())
            content.append(QStringLiteral("\nnotes: %1").arg(notes).toUtf8());

        stdOut() << I18n::t(QStringLiteral("kdbx2pass.importing"), QStringLiteral("entry"), entryPath)
                 << '\n';
        stdOut().flush();

        const QString error = runPassCommand({QStringLiteral("insert"), QStringLiteral("-m"),
                                QStringLiteral("-f"), QStringLiteral("--"), entryPath},
                               content);
        content.fill('\0');
        if (!error.isEmpty())
            return error;
    }

    stdOut() << I18n::t(QStringLiteral("kdbx2pass.done")) << '\n';
    stdOut().flush();
    return QString();
}

}
