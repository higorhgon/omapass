#include "onepasswordvault.h"

#include "i18n.h"
#include "process.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QSettings>
#include <QStandardPaths>
#include <QThread>

#include <atomic>

namespace {

const auto refPrefix = QStringLiteral("1password:");

// What the last `op account list` said, so a row can be labelled without
// spawning op again for each one. Written by accounts(), read by
// displayName().
QMutex accountsMutex;
QHash<QString, OpAccount> knownAccounts;

// The `op signout` started by the last close(), which runs detached.
std::atomic<qint64> pendingSignoutPid{0};

// A sign-out that finishes after a new sign-in would end the session that
// sign-in just created, so signing in first lets any pending one end.
void waitForPendingSignout() {
    const qint64 pid = pendingSignoutPid.exchange(0);
    if (pid <= 0)
        return;
    const QString procEntry = QStringLiteral("/proc/%1").arg(pid);
    for (int waited = 0; waited < 10000 && QFile::exists(procEntry); waited += 100)
        QThread::msleep(100);
}

// op's messages come after whatever it drew on stderr; the last line is the
// one that explains the failure.
QString lastMessage(const ProcResult &result) {
    static const QRegularExpression ansi(QStringLiteral("\\x1b\\[[0-9;?]*[A-Za-z]"));
    for (const QString &text : {result.err, result.out}) {
        QString clean = text;
        clean.remove(ansi);
        const QStringList lines = clean.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        for (auto it = lines.crbegin(); it != lines.crend(); ++it) {
            if (!it->trimmed().isEmpty())
                return it->trimmed();
        }
    }
    return QString();
}

// The name `op` printed alongside the token. Only if it did not say (an
// older shape, or --raw) is one guessed from the account, the way `op` names
// it — an account shorthand can carry characters a variable name cannot.
QString sessionVariableFor(const QString &account, const QString &stated) {
    if (!stated.isEmpty())
        return stated;

    static const QRegularExpression invalid(QStringLiteral("[^A-Za-z0-9_]"));
    QString name = account;
    name.replace(invalid, QStringLiteral("_"));
    return QStringLiteral("OP_SESSION_") + name;
}

// Some `op` commands answer differently with nothing but a pipe on the
// other side — signing out is one — so they get a terminal borrowed from
// `script`, exactly as the sign-in does.
ProcResult runOpUnderTerminal(const QStringList &args) {
    if (QStandardPaths::findExecutable(QStringLiteral("script")).isEmpty())
        return runProcess(QStringLiteral("op"), args);

    ProcResult result = runProcess(QStringLiteral("script"),
                                   {QStringLiteral("-qec"), opShellCommand(args),
                                    QStringLiteral("/dev/null")});
    // Under the terminal there is no separate stderr; what op said is in the
    // output either way.
    if (result.err.trimmed().isEmpty())
        result.err = result.out;
    return result;
}

QProcessEnvironment opEnvironment(const QString &account, const Secret &session,
                                  const QString &sessionVariable) {
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    if (!session.isEmpty())
        env.insert(sessionVariableFor(account, sessionVariable), session.toString());
    return env;
}

// Every call names its account: `op` otherwise falls back to the last one
// signed in, which is whatever the user did in their own terminal.
QStringList withAccount(const QString &account, const QStringList &args) {
    QStringList full = args;
    if (!account.isEmpty())
        full << QStringLiteral("--account") << account;
    return full;
}

ProcResult runOp(const QString &account, const QStringList &args, const Secret &session,
                 const QString &sessionVariable, const QByteArray &stdinData = QByteArray()) {
    ProcResult result = runProcess(QStringLiteral("op"), withAccount(account, args), stdinData,
                                   opEnvironment(account, session, sessionVariable));
    if (!result.started)
        result.err = I18n::t(QStringLiteral("onepassword.spawn_error"), QStringLiteral("err"), result.err);
    else if (!result.success)
        result.err = lastMessage(result);
    return result;
}

// Runs several read-only commands at once: each pays its own round trip to
// the server, so side by side they take about as long as one.
QVector<ProcResult> runOpParallel(const QString &account, const QVector<QStringList> &commands,
                                  const Secret &session, const QString &sessionVariable) {
    const QProcessEnvironment env = opEnvironment(account, session, sessionVariable);

    QVector<QProcess *> processes;
    for (const QStringList &args : commands) {
        auto *process = new QProcess;
        process->setProcessEnvironment(env);
        process->start(QStringLiteral("op"), withAccount(account, args));
        process->closeWriteChannel();
        processes.append(process);
    }

    QVector<ProcResult> results;
    for (QProcess *process : std::as_const(processes)) {
        ProcResult result;
        result.started = process->waitForStarted(-1);
        if (result.started) {
            process->waitForFinished(-1);
            result.success = process->exitStatus() == QProcess::NormalExit && process->exitCode() == 0;
            result.out = QString::fromUtf8(process->readAllStandardOutput());
            result.err = QString::fromUtf8(process->readAllStandardError());
            if (!result.success)
                result.err = lastMessage(result);
        } else {
            result.err = I18n::t(QStringLiteral("onepassword.spawn_error"), QStringLiteral("err"),
                                 process->errorString());
        }
        results.append(result);
        delete process;
    }
    return results;
}

// op's own wording is in English and often mentions flags omapass never
// used, so the cases worth explaining get a translated message; the rest is
// passed through as it came.
QString translateError(const ProcResult &result) {
    switch (classifyOpError(result.err)) {
    case OpError::WrongPassword:
        return I18n::t(QStringLiteral("backend.wrong_password"));
    case OpError::WrongSecretKey:
        return I18n::t(QStringLiteral("onepassword.wrong_secret_key"));
    case OpError::WrongCode:
        return I18n::t(QStringLiteral("onepassword.invalid_code"));
    case OpError::SessionExpired:
        return I18n::t(QStringLiteral("onepassword.session_expired"));
    case OpError::NotSignedIn:
        return I18n::t(QStringLiteral("onepassword.not_signed_in"));
    case OpError::NoAccount:
        return I18n::t(QStringLiteral("onepassword.not_logged_in"));
    case OpError::RateLimited:
        return I18n::t(QStringLiteral("onepassword.rate_limited"));
    case OpError::None:
    case OpError::Other:
        break;
    }
    return result.err;
}

void wipe(QString *text) {
    text->fill(QChar(0));
    text->clear();
}

QString lastSegment(const QString &path) {
    return path.section(QLatin1Char('/'), -1);
}

}

bool OnePasswordVault::isAvailable() {
    return !QStandardPaths::findExecutable(QStringLiteral("op")).isEmpty();
}

QString OnePasswordVault::refPath(const QString &account) {
    return refPrefix + account;
}

QString OnePasswordVault::accountOf(const QString &path) {
    return path.startsWith(refPrefix) ? path.mid(refPrefix.size()) : path;
}

QVector<OpAccount> OnePasswordVault::accounts() {
    // Reads op's own configuration; no account is signed in for this, and it
    // answers in milliseconds.
    const ProcResult result = runProcess(QStringLiteral("op"),
                                         {QStringLiteral("account"), QStringLiteral("list"),
                                          QStringLiteral("--format=json")});
    if (!result.success)
        return QVector<OpAccount>();

    const QVector<OpAccount> accounts = parseOpAccounts(result.out.toUtf8());
    const QMutexLocker locker(&accountsMutex);
    knownAccounts.clear();
    for (const OpAccount &account : accounts)
        knownAccounts.insert(account.key(), account);
    return accounts;
}

QString OnePasswordVault::displayName(const QString &account) {
    OpAccount known;
    {
        const QMutexLocker locker(&accountsMutex);
        known = knownAccounts.value(account);
    }
    if (known.email.isEmpty())
        return account;

    // `op` makes a shorthand out of the address when none is given
    // (`my.1password.com` becomes `my`), which would tell two accounts apart
    // by nothing useful. One the user chose is worth showing.
    const QString derived = known.url.section(QLatin1Char('.'), 0, 0);
    return known.shorthand.isEmpty() || known.shorthand == derived ? known.email : known.shorthand;
}

bool OnePasswordVault::hasAccount(const QString &account) {
    const QVector<OpAccount> known = accounts();
    for (const OpAccount &candidate : known) {
        if (candidate.key() == account || candidate.email == account)
            return true;
    }
    return false;
}

bool OnePasswordVault::logout(const QString &account, QString *error) {
    // A sign-out started by the last close() may still be running, and two
    // of them at once is how op ends up unsure of what is signed in.
    waitForPendingSignout();

    // With the session already ended when the vault was locked, `op account
    // forget` is the one that removes the account, so it goes first. The
    // sign-out forms are for the state where op still believes a session is
    // live: it then refuses to forget ("You are currently logged in… Use 'op
    // signout --forget' instead") — and that sign-out, with no token left to
    // end, exits 0 without removing anything. So every form is tried, and
    // what settles it is whether op still lists the account, never the exit
    // code.
    QVector<QStringList> attempts{
        {QStringLiteral("account"), QStringLiteral("forget"), account},
        {QStringLiteral("signout"), QStringLiteral("--account"), account, QStringLiteral("--forget")},
    };

    // Without --account, op signs out of the account it used last. That is
    // only unambiguous when it knows one.
    if (accounts().size() == 1)
        attempts.append({QStringLiteral("signout"), QStringLiteral("--forget")});

    // `op account forget` may also want the id op gave the account rather
    // than the shorthand omapass refers to it by.
    OpAccount known;
    {
        const QMutexLocker locker(&accountsMutex);
        known = knownAccounts.value(account);
    }
    for (const QString &id : {known.userUuid, known.accountUuid}) {
        if (!id.isEmpty())
            attempts.append({QStringLiteral("account"), QStringLiteral("forget"), id});
    }

    // Kept rather than logged as they happen: a form that does not apply to
    // the state op is in fails as a matter of course, and saying so on the
    // way to a removal that worked is just noise.
    QStringList refusals;
    ProcResult result;
    for (const QStringList &args : std::as_const(attempts)) {
        result = runOpUnderTerminal(args);
        if (!hasAccount(account))
            return true;
        refusals << QStringLiteral("op ") + args.join(QLatin1Char(' ')) + QStringLiteral(": ")
                + lastMessage(result);
    }

    for (const QString &refusal : std::as_const(refusals))
        qWarning().noquote() << "omapass:" << refusal;

    // op is holding on to a session omapass cannot end, because ending one
    // takes the token it was given — and that is gone with the vault. Saying
    // so, with the two commands that do work in a terminal, beats a message
    // that only says no.
    const QString said = lastMessage(result);
    if (refusals.join(QLatin1Char(' ')).contains(QLatin1String("currently logged in"),
                                                 Qt::CaseInsensitive)) {
        *error = I18n::t(QStringLiteral("onepassword.logout_session_stuck"),
                         QStringLiteral("account"), account);
        return false;
    }

    *error = said.isEmpty() ? I18n::t(QStringLiteral("onepassword.logout_ignored"),
                                      QStringLiteral("account"), account)
                            : said;
    return false;
}

bool OnePasswordVault::signIn(const QString &account, const Secret &password, Secret *session,
                              QString *sessionVariable, QString *error) {
    waitForPendingSignout();

    // The password goes in on stdin, never in argv. No --raw: the shell line
    // op prints instead carries the name of the variable it expects the
    // token back in, which is not something to guess. With the 1Password
    // desktop app integration turned on, `op` authenticates through the app
    // and prints no token: an empty session is a working one, and the calls
    // that follow simply carry no session variable.
    QByteArray input = password.bytes();
    input.append('\n');
    // --force so op prints the session line instead of telling us to run it
    // in a shell, the same reason the interactive path passes it.
    ProcResult result = runOp(account, {QStringLiteral("signin"), QStringLiteral("--force")},
                              Secret(), QString(), input);
    input.fill('\0');

    if (!result.success) {
        *error = translateError(result);
        return false;
    }

    const OpSession parsed = parseOpSignIn(result.out);
    wipe(&result.out);
    *session = Secret(parsed.token);
    *sessionVariable = parsed.variable;
    return true;
}

OnePasswordVault *OnePasswordVault::unlock(const QString &account, const Secret &password,
                                           QString *error) {
    if (!hasAccount(account)) {
        *error = I18n::t(QStringLiteral("onepassword.not_logged_in"));
        return nullptr;
    }

    Secret session;
    QString sessionVariable;
    if (!signIn(account, password, &session, &sessionVariable, error))
        return nullptr;
    return openWithSession(account, session, sessionVariable, error);
}

OnePasswordVault *OnePasswordVault::openWithSession(const QString &account, const Secret &session,
                                                    const QString &sessionVariable, QString *error) {
    auto *vault = new OnePasswordVault(account, session, sessionVariable);
    if (!vault->reload(error)) {
        delete vault;
        return nullptr;
    }
    return vault;
}

bool OnePasswordVault::reload(QString *error) const {
    QVector<ProcResult> results = runOpParallel(
        m_account,
        {{QStringLiteral("vault"), QStringLiteral("list"), QStringLiteral("--format=json")},
         {QStringLiteral("item"), QStringLiteral("list"), QStringLiteral("--format=json")}},
        m_session, m_sessionVariable);
    const ProcResult &vaults = results[0];
    ProcResult &items = results[1];

    if (!vaults.success || !items.success) {
        *error = translateError(!vaults.success ? vaults : items);
        wipe(&items.out);
        return false;
    }

    QHash<QString, QString> parsedVaults = parseOpVaults(vaults.out.toUtf8());
    QByteArray itemsJson = items.out.toUtf8();
    wipe(&items.out);
    QHash<QString, QJsonObject> parsedItems = parseOpItems(itemsJson);
    itemsJson.fill('\0');
    OpIndex index = buildOpIndex(parsedItems, parsedVaults);

    const QMutexLocker locker(&m_mutex);
    m_items = std::move(parsedItems);
    m_vaults = std::move(parsedVaults);
    m_index = std::move(index);
    return true;
}

void OnePasswordVault::storeItem(const QByteArray &itemJson) const {
    const QJsonObject item = QJsonDocument::fromJson(itemJson).object();
    const QString id = item.value(QStringLiteral("id")).toString();
    if (id.isEmpty())
        return;

    const QMutexLocker locker(&m_mutex);
    m_items.insert(id, item);
    m_index = buildOpIndex(m_items, m_vaults);
}

void OnePasswordVault::forgetItem(const QString &itemId) const {
    const QMutexLocker locker(&m_mutex);
    m_items.remove(itemId);
    m_index = buildOpIndex(m_items, m_vaults);
}

bool OnePasswordVault::lookup(const QString &entryPath, OpItemRef *ref, QString *error) const {
    const QMutexLocker locker(&m_mutex);
    if (!m_index.items.contains(entryPath)) {
        *error = I18n::t(QStringLiteral("onepassword.entry_not_found"), QStringLiteral("entry"), entryPath);
        return false;
    }
    *ref = m_index.items.value(entryPath);
    return true;
}

bool OnePasswordVault::fullItem(const OpItemRef &ref, QJsonObject *item, QString *error) const {
    {
        const QMutexLocker locker(&m_mutex);
        const QJsonObject cached = m_items.value(ref.id);
        // A listing has no fields at all, so that key is what tells a whole
        // item from the summary the list gave us.
        if (cached.contains(QStringLiteral("fields"))) {
            *item = cached;
            return true;
        }
    }

    // --reveal so the values that come back are the real ones: what is
    // stored here is what an edit will send back.
    ProcResult result = runOp(m_account,
                              {QStringLiteral("item"), QStringLiteral("get"), ref.id,
                               QStringLiteral("--vault"), ref.vaultId,
                               QStringLiteral("--format=json"), QStringLiteral("--reveal")},
                              m_session, m_sessionVariable);
    if (!result.success) {
        *error = translateError(result);
        return false;
    }

    QByteArray json = result.out.toUtf8();
    wipe(&result.out);
    *item = QJsonDocument::fromJson(json).object();
    storeItem(json);
    json.fill('\0');
    return true;
}

bool OnePasswordVault::vaultOfGroup(const QString &group, QString *vaultId, QString *error) const {
    const QString vaultName = opVaultOf(group);
    if (vaultName.isEmpty()) {
        // Every 1Password item lives in a vault, so the root of the list is
        // not a place an entry can go.
        *error = I18n::t(QStringLiteral("onepassword.vault_required"));
        return false;
    }

    const QMutexLocker locker(&m_mutex);
    const QString id = m_index.vaults.value(vaultName);
    if (id.isEmpty()) {
        *error = I18n::t(QStringLiteral("onepassword.unknown_vault"), QStringLiteral("vault"), vaultName);
        return false;
    }
    *vaultId = id;
    return true;
}

bool OnePasswordVault::setTags(const QString &itemId, const QString &vaultId,
                               const QStringList &tags, QString *error) const {
    // --tags replaces the whole list and touches nothing else. A JSON
    // template would do it too, but it would first need the whole item, and
    // that is one round trip per item on top of the edit.
    ProcResult result = runOp(m_account,
                              {QStringLiteral("item"), QStringLiteral("edit"), itemId,
                               QStringLiteral("--vault"), vaultId, QStringLiteral("--tags"),
                               tags.join(QLatin1Char(',')), QStringLiteral("--format=json"),
                               QStringLiteral("--reveal")},
                              m_session, m_sessionVariable);
    if (!result.success) {
        *error = translateError(result);
        return false;
    }

    QByteArray edited = result.out.toUtf8();
    wipe(&result.out);
    storeItem(edited);
    edited.fill('\0');
    return true;
}

void OnePasswordVault::list(QStringList *entries, QStringList *groups) const {
    {
        const QMutexLocker locker(&m_mutex);
        *entries = m_index.entries;
        *groups = m_index.groups;
    }
    appendEmptyGroups(*groups, entries);
}

QString OnePasswordVault::titleFor(const QString &entryPath, const QString &fallback) const {
    const QMutexLocker locker(&m_mutex);
    const QString title = m_index.items.value(entryPath).title;
    return title.isEmpty() ? fallback : title;
}

bool OnePasswordVault::fetchPassword(const QString &entryPath, Secret *password, QString *error) const {
    EntryData data;
    if (!fetchEntry(entryPath, &data, error))
        return false;
    *password = data.password;
    return true;
}

bool OnePasswordVault::fetchEntry(const QString &entryPath, EntryData *data, QString *error) const {
    OpItemRef ref;
    QJsonObject item;
    if (!lookup(entryPath, &ref, error) || !fullItem(ref, &item, error))
        return false;
    *data = opEntryData(item);
    return true;
}

bool OnePasswordVault::addEntry(const QString &entryPath, const QString &group, const EntryData &data,
                                QString *error) const {
    QString vaultId;
    if (!vaultOfGroup(group, &vaultId, error))
        return false;

    QByteArray json = opNewItemJson(lastSegment(entryPath), vaultId, opTagPathOf(group), data);
    ProcResult result = runOp(m_account,
                              {QStringLiteral("item"), QStringLiteral("create"), QStringLiteral("-"),
                               QStringLiteral("--format=json"), QStringLiteral("--reveal")},
                              m_session, m_sessionVariable, json);
    json.fill('\0');
    if (!result.success) {
        *error = translateError(result);
        return false;
    }

    QByteArray created = result.out.toUtf8();
    wipe(&result.out);
    storeItem(created);
    created.fill('\0');
    return true;
}

bool OnePasswordVault::editEntry(const QString &oldPath, const QString &newPath, const QString &group,
                                 const EntryData &data, QString *error) const {
    OpItemRef ref;
    QJsonObject item;
    if (!lookup(oldPath, &ref, error) || !fullItem(ref, &item, error))
        return false;

    // A template edit replaces the whole item, and `op` cannot express a
    // passkey in one: editing would silently destroy it.
    if (opHasPasskey(item)) {
        *error = I18n::t(QStringLiteral("onepassword.passkey_readonly"));
        return false;
    }

    QString vaultId;
    if (!vaultOfGroup(group, &vaultId, error))
        return false;

    QString itemId = ref.id;
    if (vaultId != ref.vaultId) {
        // Moving between vaults gives the item a new id, so what comes back
        // is what the edit has to talk to.
        ProcResult moved = runOp(m_account,
                                 {QStringLiteral("item"), QStringLiteral("move"), ref.id,
                                  QStringLiteral("--current-vault"), ref.vaultId,
                                  QStringLiteral("--destination-vault"), vaultId,
                                  QStringLiteral("--format=json"), QStringLiteral("--reveal")},
                                 m_session, m_sessionVariable);
        if (!moved.success) {
            *error = translateError(moved);
            return false;
        }

        QByteArray movedJson = moved.out.toUtf8();
        wipe(&moved.out);
        const QString newId = QJsonDocument::fromJson(movedJson).object()
                                  .value(QStringLiteral("id")).toString();
        if (!newId.isEmpty())
            itemId = newId;
        forgetItem(ref.id);
        storeItem(movedJson);
        movedJson.fill('\0');
    }

    // An untouched title keeps the real one: the path segment may carry a
    // look-alike slash or the id suffix that told duplicates apart.
    const QString segment = lastSegment(newPath);
    const QString title = segment == lastSegment(oldPath) ? ref.title : segment;

    QByteArray updated = applyOpEntryData(QJsonDocument(item).toJson(QJsonDocument::Compact), title,
                                          opTagPathOf(group), data);
    ProcResult result = runOp(m_account,
                              {QStringLiteral("item"), QStringLiteral("edit"), itemId,
                               QStringLiteral("--vault"), vaultId, QStringLiteral("--format=json"),
                               QStringLiteral("--reveal")},
                              m_session, m_sessionVariable, updated);
    updated.fill('\0');
    if (!result.success) {
        *error = translateError(result);
        return false;
    }

    QByteArray edited = result.out.toUtf8();
    wipe(&result.out);
    storeItem(edited);
    edited.fill('\0');
    return true;
}

bool OnePasswordVault::removeEntry(const QString &entryPath, QString *error) const {
    OpItemRef ref;
    if (!lookup(entryPath, &ref, error))
        return false;

    // Without --archive the item goes to Recently Deleted, recoverable from
    // the 1Password apps for 30 days.
    const ProcResult result = runOp(m_account,
                                    {QStringLiteral("item"), QStringLiteral("delete"), ref.id,
                                     QStringLiteral("--vault"), ref.vaultId},
                                    m_session, m_sessionVariable);
    if (!result.success) {
        *error = translateError(result);
        return false;
    }

    forgetItem(ref.id);
    return true;
}

bool OnePasswordVault::renameGroup(const QString &oldGroup, const QString &newName,
                                   QString *error) const {
    QString vaultId;
    if (!vaultOfGroup(oldGroup, &vaultId, error))
        return false;

    const QString oldTag = opTagPathOf(oldGroup);
    if (oldTag.isEmpty()) {
        // A first-level group is the vault itself.
        const ProcResult result = runOp(m_account,
                                        {QStringLiteral("vault"), QStringLiteral("edit"), vaultId,
                                         QStringLiteral("--name"), newName},
                                        m_session, m_sessionVariable);
        if (!result.success) {
            *error = translateError(result);
            return false;
        }

        const QMutexLocker locker(&m_mutex);
        m_vaults.insert(vaultId, newName);
        m_index = buildOpIndex(m_items, m_vaults);
        return true;
    }

    const QString parent = parentGroup(oldTag);
    const QString newTag = parent.isEmpty() ? newName : parent + QLatin1Char('/') + newName;
    const QString oldPrefix = oldTag + QLatin1Char('/');

    QHash<QString, QJsonObject> items;
    {
        const QMutexLocker locker(&m_mutex);
        items = m_items;
    }

    // Tags nest by name alone, so renaming a group rewrites that part of the
    // tag on every item at or below it, in this vault only. Each item is
    // stored as it goes, so a failure midway still leaves the list showing
    // what actually changed.
    for (const QJsonObject &item : items) {
        if (item.value(QStringLiteral("vault")).toObject().value(QStringLiteral("id")).toString()
            != vaultId)
            continue;

        const QStringList tags = opItemTags(item);
        QStringList renamed;
        bool touched = false;
        for (const QString &tag : tags) {
            if (tag == oldTag || tag.startsWith(oldPrefix)) {
                renamed.append(newTag + tag.mid(oldTag.size()));
                touched = true;
            } else {
                renamed.append(tag);
            }
        }
        if (!touched)
            continue;

        renamed.removeDuplicates();
        renamed.sort();
        if (!setTags(item.value(QStringLiteral("id")).toString(), vaultId, renamed, error))
            return false;
    }
    return true;
}

bool OnePasswordVault::removeGroup(const QString &group, QString *error) const {
    QString vaultId;
    if (!vaultOfGroup(group, &vaultId, error))
        return false;

    const QString tag = opTagPathOf(group);
    if (tag.isEmpty()) {
        const ProcResult result = runOp(m_account,
                                        {QStringLiteral("vault"), QStringLiteral("delete"), vaultId},
                                        m_session, m_sessionVariable);
        if (!result.success) {
            *error = translateError(result);
            return false;
        }

        const QMutexLocker locker(&m_mutex);
        m_vaults.remove(vaultId);
        for (const QString &id : m_items.keys()) {
            if (m_items.value(id).value(QStringLiteral("vault")).toObject()
                    .value(QStringLiteral("id")).toString() == vaultId)
                m_items.remove(id);
        }
        m_index = buildOpIndex(m_items, m_vaults);
        return true;
    }

    const QString prefix = tag + QLatin1Char('/');
    QHash<QString, QJsonObject> items;
    {
        const QMutexLocker locker(&m_mutex);
        items = m_items;
    }

    // Removing a tag group leaves the items where they are — in their vault,
    // one level up — which is what deleting a folder does elsewhere.
    for (const QJsonObject &item : items) {
        if (item.value(QStringLiteral("vault")).toObject().value(QStringLiteral("id")).toString()
            != vaultId)
            continue;

        const QStringList tags = opItemTags(item);
        QStringList kept;
        for (const QString &candidate : tags) {
            if (candidate != tag && !candidate.startsWith(prefix))
                kept.append(candidate);
        }
        if (kept.size() == tags.size())
            continue;

        if (!setTags(item.value(QStringLiteral("id")).toString(), vaultId, kept, error))
            return false;
    }
    return true;
}

void OnePasswordVault::close() {
    // Detached: the round trip to the server is not something either locking
    // back to the database list or quitting the app should wait for. The
    // account stays configured; only the session ends — and ending it here
    // is what keeps `op` from believing, later, that it is still signed in
    // and refusing to forget the account.
    //
    // Under the borrowed terminal, like every other op call that has turned
    // out to answer differently without one.
    const QStringList args{QStringLiteral("signout"), QStringLiteral("--account"), m_account};
    const bool underTerminal = !QStandardPaths::findExecutable(QStringLiteral("script")).isEmpty();

    QProcess process;
    process.setProcessEnvironment(opEnvironment(m_account, m_session, m_sessionVariable));
    process.setProgram(underTerminal ? QStringLiteral("script") : QStringLiteral("op"));
    process.setArguments(underTerminal
        ? QStringList{QStringLiteral("-qec"), opShellCommand(args), QStringLiteral("/dev/null")}
        : args);
    process.setStandardOutputFile(QProcess::nullDevice());
    process.setStandardErrorFile(QProcess::nullDevice());
    // Without this the detached process inherits the terminal omapass was
    // started from, and `op` asks questions on it ("Do you want to add an
    // account manually now?") that nobody is there to answer.
    process.setStandardInputFile(QProcess::nullDevice());
    qint64 pid = 0;
    if (process.startDetached(&pid))
        pendingSignoutPid = pid;

    m_session.clear();
    const QMutexLocker locker(&m_mutex);
    m_items.clear();
    m_vaults.clear();
    m_index = OpIndex();
}
