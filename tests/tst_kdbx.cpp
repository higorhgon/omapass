// The .kdbx reader and writer.

#include "support.h"

#include "appcontroller.h"
#include "config.h"
#include "i18n.h"
#include "kdbx.h"
#include "kdbx2pass.h"
#include "keepassvault.h"
#include "process.h"

#include <QElapsedTimer>
#include <QScopeGuard>

#include <memory>

namespace {

// A small KDBX 4 database written to `path`, opened with "senha".
QByteArray writeSample(const QString &path) {
    auto db = KdbxDatabase::create(Secret(QStringLiteral("senha")), QStringLiteral("Amostra"));
    if (!db)
        return QByteArray();
    KdbxEntry entry;
    entry.title = QStringLiteral("Gmail");
    entry.username = QStringLiteral("ana");
    entry.password = Secret(QStringLiteral("antiga"));
    entry.notes = QString(4000, QLatin1Char('n'));   // enough for a real block
    if (!db->addEntry(QStringLiteral("Email"), entry).isEmpty() || !db->save(path).isEmpty())
        return QByteArray();
    QFile file(path);
    return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

bool writeBytes(const QString &path, const QByteArray &bytes) {
    QFile file(path);
    return file.open(QIODevice::WriteOnly | QIODevice::Truncate) && file.write(bytes) == bytes.size();
}

}

class TestKdbx : public QObject {
    Q_OBJECT

private slots:
    // The sidebar deletes a group only once nothing is left in it: no entry,
    // at any depth, and no subgroup.
    void sidebarDeletesOnlyEmptyGroups() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.filePath(QStringLiteral("grupos.kdbx"));
        {
            auto db = KdbxDatabase::create(Secret(QStringLiteral("senha")), QStringLiteral("Grupos"));
            KdbxEntry entry;
            entry.title = QStringLiteral("Mail");
            QVERIFY(db->addEntry(QStringLiteral("Cheio"), entry).isEmpty());
            QVERIFY(db->createGroup(QStringLiteral("Vazio")).isEmpty());
            QVERIFY(db->createGroup(QStringLiteral("Pai/Filho")).isEmpty());
            QVERIFY(db->save(path).isEmpty());
        }

        AppConfig config;
        config.autoSearch = true;
        config.searchPath = dir.path();
        config.recencyEnabled = false;
        AppController app(config);
        QTRY_VERIFY(!app.scanning());
        app.setDatabaseQuery(QStringLiteral("grupos.kdbx"));
        QCOMPARE(app.databases().size(), 1);
        app.selectDatabase(0);
        app.unlock(QStringLiteral("senha"));
        QTRY_VERIFY(!app.busy());

        const auto sidebarIds = [&]() {
            QStringList ids;
            for (const QVariant &v : app.sidebarItems())
                ids.append(v.toMap().value(QStringLiteral("id")).toString());
            return ids;
        };
        QVERIFY(sidebarIds().contains(QStringLiteral("group:Vazio")));

        QCOMPARE(app.sidebarDeleteBlocker(QStringLiteral("group:Cheio")),
                 I18n::t(QStringLiteral("app.group_not_empty")));
        QCOMPARE(app.sidebarDeleteBlocker(QStringLiteral("group:Pai")),
                 I18n::t(QStringLiteral("app.group_has_subgroups")));
        QCOMPARE(app.sidebarDeleteBlocker(QStringLiteral("all")),
                 I18n::t(QStringLiteral("app.sidebar_not_deletable")));
        QVERIFY(app.sidebarDeleteBlocker(QStringLiteral("group:Vazio")).isEmpty());

        // Refused even when asked directly, past the question.
        app.deleteSidebarItem(QStringLiteral("group:Cheio"));
        QTRY_VERIFY(!app.busy());
        QVERIFY(sidebarIds().contains(QStringLiteral("group:Cheio")));
        QCOMPARE(app.message(), I18n::t(QStringLiteral("app.group_not_empty")));

        app.selectSection(QStringLiteral("group:Vazio"));
        app.deleteSidebarItem(QStringLiteral("group:Vazio"));
        QTRY_VERIFY(!sidebarIds().contains(QStringLiteral("group:Vazio")));
        QCOMPARE(app.activeSection(), QStringLiteral("all"));
        QCOMPARE(app.message(), I18n::t(QStringLiteral("app.group_deleted")));
    }

#ifdef Q_OS_UNIX
    void findsMiseFdWithARestrictedPath() {
        const QTemporaryDir home;
        QVERIFY(home.isValid());
        QVERIFY(QDir(home.path()).mkpath(QStringLiteral(".local/bin")));
        QVERIFY(QDir(home.path()).mkdir(QStringLiteral("search")));
        const QString mise = home.filePath(QStringLiteral(".local/bin/mise"));
        const QString fd = home.filePath(QStringLiteral("fd"));
        const auto executable = QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner;
        QVERIFY(writeBytes(mise, "#!/bin/sh\n[ \"$3:$4\" = which:fd ] && printf '%s\\n' \"$HOME/fd\"\n"));
        QVERIFY(writeBytes(fd, "#!/bin/sh\n"
                               "if [ \"$2\" = \"$HOME/search\" ]; then\n"
                               "    printf '%s\\n' \"$2/test.kdbx\"\n"
                               "fi\n"));
        QVERIFY(QFile::setPermissions(mise, executable));
        QVERIFY(QFile::setPermissions(fd, executable));

        const QByteArray previousHome = qgetenv("HOME");
        const auto restoreHome = qScopeGuard([&] {
            if (previousHome.isNull())
                qunsetenv("HOME");
            else
                qputenv("HOME", previousHome);
        });
        qputenv("HOME", QFile::encodeName(home.path()));
        const PathOverride cleanPath(QFile::encodeName(home.filePath(QStringLiteral(".local"))));
        QCOMPARE(findFdExecutable(), fd);
        const auto databases = Vault::findLocalDatabases(home.filePath(QStringLiteral("search")));
        QCOMPARE(databases.size(), 1);
        QCOMPARE(databases.first().path, home.filePath(QStringLiteral("search/test.kdbx")));
    }
#endif

    void kdbxTruncatedFilesAreRefusedNotCrashedOn() {
        QTemporaryDir dir;
        const QString path = dir.filePath(QStringLiteral("t.kdbx"));
        const QByteArray original = writeSample(path);
        QVERIFY(!original.isEmpty());

        for (const qsizetype size : {qsizetype(0), qsizetype(4), qsizetype(12), qsizetype(100),
                                     original.size() / 2, original.size() - 1}) {
            QVERIFY(writeBytes(path, original.left(size)));
            KdbxStatus status = KdbxStatus::Ok;
            QVERIFY2(!KdbxDatabase::open(path, Secret(QStringLiteral("senha")), &status),
                     qPrintable(QStringLiteral("opened at %1 bytes").arg(size)));
            QVERIFY(status != KdbxStatus::Ok);
        }
    }

    void kdbxTamperedPayloadIsCorruptNotAWrongPassword() {
        QTemporaryDir dir;
        const QString path = dir.filePath(QStringLiteral("t.kdbx"));
        QByteArray bytes = writeSample(path);
        QVERIFY(!bytes.isEmpty());

        // A bit flipped in the encrypted data, past the header: the right
        // password still opens the header, and the block MAC catches it.
        bytes[bytes.size() - 40] = char(bytes[bytes.size() - 40] ^ 0x01);
        QVERIFY(writeBytes(path, bytes));
        KdbxStatus status = KdbxStatus::Ok;
        QVERIFY(!KdbxDatabase::open(path, Secret(QStringLiteral("senha")), &status));
        QCOMPARE(status, KdbxStatus::Corrupt);
    }

    void kdbxArgon2AboveTheCostCapIsRefusedBeforeDeriving() {
        QTemporaryDir dir;
        const QString path = dir.filePath(QStringLiteral("t.kdbx"));
        QByteArray bytes = writeSample(path);
        QVERIFY(!bytes.isEmpty());

        // The "I" (iterations) entry of the KDF parameters: type 0x05
        // (UInt64), a one-byte name, eight bytes of value.
        const QByteArray marker = QByteArray::fromHex("0501000000") + "I" + QByteArray::fromHex("08000000");
        const qsizetype at = bytes.indexOf(marker);
        QVERIFY(at > 0);
        const quint64 iterations = 100000;   // × 64 MiB: hours of Argon2
        for (int i = 0; i < 8; ++i)
            bytes[at + marker.size() + i] = char((iterations >> (8 * i)) & 0xFF);
        QVERIFY(writeBytes(path, bytes));

        QElapsedTimer timer;
        timer.start();
        KdbxStatus status = KdbxStatus::Ok;
        QString detail;
        QVERIFY(!KdbxDatabase::open(path, Secret(QStringLiteral("senha")), &status, &detail));
        QCOMPARE(status, KdbxStatus::Unsupported);
        QCOMPARE(detail, QStringLiteral("Argon2 parameters"));
        QVERIFY(timer.elapsed() < 5000);
    }

    void kdbxFailedSaveLeavesMemoryAsTheFileIs() {
        QTemporaryDir dir;
        const QString path = dir.filePath(QStringLiteral("t.kdbx"));
        QVERIFY(!writeSample(path).isEmpty());

        QString error;
        const std::unique_ptr<KeepassVault> vault(KeepassVault::unlock(path, Secret(QStringLiteral("senha")), &error));
        QVERIFY2(vault, qPrintable(error));

        // A directory nobody can write to: QSaveFile cannot even start.
        QFile::setPermissions(dir.path(), QFileDevice::ReadOwner | QFileDevice::ExeOwner);
        if (QFileInfo(dir.path()).isWritable()) {
            QFile::setPermissions(dir.path(), QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
            QSKIP("running with permissions that ignore the directory mode");
        }
        EntryData changed;
        changed.username = QStringLiteral("ana");
        changed.password = Secret(QStringLiteral("nova"));
        QVERIFY(!vault->editEntry(QStringLiteral("Email/Gmail"), QStringLiteral("Email/Gmail"),
                                  QStringLiteral("Email"), changed, &error));
        QFile::setPermissions(dir.path(), QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);

        // The edit that did not reach the file is not in memory either...
        EntryData data;
        QVERIFY(vault->fetchEntry(QStringLiteral("Email/Gmail"), &data, &error));
        QCOMPARE(data.password.toString(), QStringLiteral("antiga"));

        // ...so the next save that works does not carry it along.
        EntryData other;
        other.password = Secret(QStringLiteral("x"));
        QVERIFY2(vault->addEntry(QStringLiteral("Email/Outro"), QStringLiteral("Email"), other, &error),
                 qPrintable(error));
        KdbxStatus status = KdbxStatus::Corrupt;
        const auto reread = KdbxDatabase::open(path, Secret(QStringLiteral("senha")), &status);
        QVERIFY(reread);
        KdbxEntry entry;
        QVERIFY(reread->entry(QStringLiteral("Email/Gmail"), &entry));
        QCOMPARE(entry.password.toString(), QStringLiteral("antiga"));
    }

    void kdbxRoundTripsEntriesGroupsAndHistory() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.filePath(QStringLiteral("t.kdbx"));
        const Secret password(QStringLiteral("correct horse"));

        auto db = KdbxDatabase::create(password, QStringLiteral("Teste"));
        QVERIFY(db);
        KdbxEntry entry;
        entry.title = QStringLiteral("Gmail");
        entry.username = QStringLiteral("ana@example.com");
        entry.password = Secret(QStringLiteral("s3cr&t <pw>"));
        entry.url = QStringLiteral("https://mail.example");
        entry.notes = QStringLiteral("linha 1\nlinha 2 ção");
        QVERIFY(db->addEntry(QStringLiteral("Trabalho/Email"), entry).isEmpty());
        entry.title = QStringLiteral("Raiz");
        QVERIFY(db->addEntry(QString(), entry).isEmpty());
        QVERIFY(db->save(path).isEmpty());

        KdbxStatus status = KdbxStatus::Corrupt;
        QVERIFY(!KdbxDatabase::open(path, Secret(QStringLiteral("wrong")), &status));
        QCOMPARE(status, KdbxStatus::WrongPassword);

        QString detail;
        auto reopened = KdbxDatabase::open(path, password, &status, &detail);
        QVERIFY2(reopened, qPrintable(QStringLiteral("status %1: %2").arg(int(status)).arg(detail)));
        QStringList entries, groups;
        reopened->list(&entries, &groups);
        QCOMPARE(entries, QStringList({QStringLiteral("Raiz"), QStringLiteral("Trabalho/Email/Gmail")}));
        QCOMPARE(groups, QStringList({QStringLiteral("Trabalho"), QStringLiteral("Trabalho/Email")}));

        KdbxEntry read;
        QVERIFY(reopened->entry(QStringLiteral("Trabalho/Email/Gmail"), &read));
        QCOMPARE(read.password.toString(), QStringLiteral("s3cr&t <pw>"));
        QCOMPARE(read.notes, QStringLiteral("linha 1\nlinha 2 ção"));
        QCOMPARE(read.url, QStringLiteral("https://mail.example"));

        // Edit: moves, changes the password, renames the group, recycles.
        read.password = Secret(QStringLiteral("novo"));
        read.title = QStringLiteral("Gmail 2");
        QVERIFY(reopened->editEntry(QStringLiteral("Trabalho/Email/Gmail"), QStringLiteral("Pessoal"), read).isEmpty());
        QVERIFY(reopened->renameGroup(QStringLiteral("Pessoal"), QStringLiteral("Casa")).isEmpty());
        QVERIFY(reopened->removeEntry(QStringLiteral("Raiz")).isEmpty());
        QVERIFY(reopened->save(path).isEmpty());

        auto again = KdbxDatabase::open(path, password, &status);
        QVERIFY(again);
        again->list(&entries, &groups);
        QVERIFY(entries.contains(QStringLiteral("Casa/Gmail 2")));
        QVERIFY(entries.contains(QStringLiteral("Recycle Bin/Raiz")));
        QVERIFY(!entries.contains(QStringLiteral("Raiz")));
        QVERIFY(again->entry(QStringLiteral("Casa/Gmail 2"), &read));
        QCOMPARE(read.password.toString(), QStringLiteral("novo"));
    }

    void kdbxKeepsTheOneTimePassword() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.filePath(QStringLiteral("t.kdbx"));
        const Secret password(QStringLiteral("senha"));
        const QString uri = QStringLiteral("otpauth://totp/Gmail?secret=JBSWY3DPEHPK3PXP&period=30&digits=6");

        auto db = KdbxDatabase::create(password, QStringLiteral("Teste"));
        QVERIFY(db);
        KdbxEntry entry;
        entry.title = QStringLiteral("Gmail");
        entry.password = Secret(QStringLiteral("p"));
        entry.otp = Secret(uri);
        QVERIFY(db->addEntry(QString(), entry).isEmpty());
        QVERIFY(db->save(path).isEmpty());

        KdbxStatus status = KdbxStatus::Corrupt;
        auto reopened = KdbxDatabase::open(path, password, &status);
        QVERIFY(reopened);
        KdbxEntry read;
        QVERIFY(reopened->entry(QStringLiteral("Gmail"), &read));
        QCOMPARE(read.otp.toString(), uri);

        // Changed, then removed.
        read.otp = Secret(QStringLiteral("otpauth://totp/Gmail?secret=MZXW6YTBOI"));
        QVERIFY(reopened->editEntry(QStringLiteral("Gmail"), QString(), read).isEmpty());
        QVERIFY(reopened->entry(QStringLiteral("Gmail"), &read));
        QCOMPARE(read.otp.toString(), QStringLiteral("otpauth://totp/Gmail?secret=MZXW6YTBOI"));

        read.otp = Secret();
        QVERIFY(reopened->editEntry(QStringLiteral("Gmail"), QString(), read).isEmpty());
        QVERIFY(reopened->save(path).isEmpty());
        auto again = KdbxDatabase::open(path, password, &status);
        QVERIFY(again);
        QVERIFY(again->entry(QStringLiteral("Gmail"), &read));
        QVERIFY(read.otp.isEmpty());
    }

    // Custom icons as KeePassXC keeps them: a pool in Meta, entries pointing
    // into it by UUID.
    void kdbxKeepsCustomIcons() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.filePath(QStringLiteral("t.kdbx"));
        const Secret password(QStringLiteral("senha"));

        auto db = KdbxDatabase::create(password, QStringLiteral("Teste"));
        QVERIFY(db);
        KdbxEntry entry;
        entry.password = Secret(QStringLiteral("p"));
        entry.title = QStringLiteral("A");
        QVERIFY(db->addEntry(QString(), entry).isEmpty());
        entry.title = QStringLiteral("B");
        QVERIFY(db->addEntry(QStringLiteral("G"), entry).isEmpty());
        QVERIFY(db->entryIcons().isEmpty());

        const QByteArray red("png-vermelho"), blue("png-azul");
        QVERIFY(db->setEntryIcon(QStringLiteral("A"), red).isEmpty());
        QVERIFY(db->setEntryIcon(QStringLiteral("G/B"), red).isEmpty());
        QVERIFY(db->save(path).isEmpty());

        KdbxStatus status = KdbxStatus::Corrupt;
        auto reopened = KdbxDatabase::open(path, password, &status);
        QVERIFY(reopened);
        QHash<QString, QByteArray> icons = reopened->entryIcons();
        QCOMPARE(icons.value(QStringLiteral("A")), red);
        QCOMPARE(icons.value(QStringLiteral("G/B")), red);

        // The icon is still B's, and the entry's other fields are untouched.
        QVERIFY(reopened->setEntryIcon(QStringLiteral("A"), blue).isEmpty());
        icons = reopened->entryIcons();
        QCOMPARE(icons.value(QStringLiteral("A")), blue);
        QCOMPARE(icons.value(QStringLiteral("G/B")), red);
        KdbxEntry read;
        QVERIFY(reopened->entry(QStringLiteral("A"), &read));
        QCOMPARE(read.password.toString(), QStringLiteral("p"));

        QVERIFY(reopened->setEntryIcon(QStringLiteral("G/B"), QByteArray()).isEmpty());
        QVERIFY(!reopened->entryIcons().contains(QStringLiteral("G/B")));
        QVERIFY(!reopened->setEntryIcon(QStringLiteral("nao-existe"), red).isEmpty());
    }

    // Where KeePassXC keeps the browser integration's data: the database's
    // custom data and the entries'. Both survive a save, and an edit.
    // KeePassXC's additional URLs: KP2A_URL, KP2A_URL_1, … read in order,
    // written back renumbered only when the list changed.
    void kdbxKeepsAdditionalUrls() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.filePath(QStringLiteral("t.kdbx"));
        const Secret password(QStringLiteral("senha"));

        auto db = KdbxDatabase::create(password, QStringLiteral("Teste"));
        KdbxEntry entry;
        entry.title = QStringLiteral("Sistema");
        entry.password = Secret(QStringLiteral("p"));
        entry.url = QStringLiteral("https://sistema.exemplo.com");
        entry.extraUrls = {QStringLiteral("http://localhost:8080"), QStringLiteral("http://192.168.0.10"),
                           QStringLiteral("https://homolog.exemplo.com")};
        QVERIFY(db->addEntry(QString(), entry).isEmpty());
        QVERIFY(db->save(path).isEmpty());

        KdbxStatus status = KdbxStatus::Corrupt;
        auto reopened = KdbxDatabase::open(path, password, &status);
        QVERIFY(reopened);
        KdbxEntry read;
        QVERIFY(reopened->entry(QStringLiteral("Sistema"), &read));
        QCOMPARE(read.extraUrls, entry.extraUrls);

        // Unchanged: no edit goes to the history.
        QVERIFY(reopened->editEntry(QStringLiteral("Sistema"), QString(), read).isEmpty());
        QVERIFY(reopened->save(path).isEmpty());

        // One out of the middle: the rest close up, in order.
        read.extraUrls.removeAt(1);
        QVERIFY(reopened->editEntry(QStringLiteral("Sistema"), QString(), read).isEmpty());
        KdbxEntry after;
        QVERIFY(reopened->entry(QStringLiteral("Sistema"), &after));
        QCOMPARE(after.extraUrls, (QStringList{QStringLiteral("http://localhost:8080"),
                                               QStringLiteral("https://homolog.exemplo.com")}));
        QCOMPARE(after.url, QStringLiteral("https://sistema.exemplo.com"));

        after.extraUrls.clear();
        QVERIFY(reopened->editEntry(QStringLiteral("Sistema"), QString(), after).isEmpty());
        QVERIFY(reopened->entry(QStringLiteral("Sistema"), &read));
        QVERIFY(read.extraUrls.isEmpty());
    }

    void kdbxKeepsCustomData() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.filePath(QStringLiteral("t.kdbx"));
        const Secret password(QStringLiteral("senha"));

        auto db = KdbxDatabase::create(password, QStringLiteral("Teste"));
        QVERIFY(db);
        QVERIFY(db->hasEntryCustomData());
        KdbxEntry entry;
        entry.password = Secret(QStringLiteral("p"));
        entry.title = QStringLiteral("A");
        QVERIFY(db->addEntry(QStringLiteral("Web"), entry).isEmpty());
        // The recycle bin's contents are no one's business.
        entry.title = QStringLiteral("Lixo");
        QVERIFY(db->addEntry(QString(), entry).isEmpty());
        QVERIFY(db->removeEntry(QStringLiteral("Lixo")).isEmpty());

        QVERIFY(db->setCustomData(QStringLiteral("KPXC_BROWSER_laptop"), QStringLiteral("chave")).isEmpty());
        QVERIFY(db->setEntryCustomData(QStringLiteral("Web/A"), QStringLiteral("KeePassXC-Browser Settings"),
                                       QStringLiteral("{\"Allow\":[\"a.com\"]}")).isEmpty());
        // An edit puts the entry in its history: the data stays on the entry.
        entry.title = QStringLiteral("A");
        entry.username = QStringLiteral("ana");
        QVERIFY(db->editEntry(QStringLiteral("Web/A"), QStringLiteral("Web"), entry).isEmpty());
        QVERIFY(!db->setEntryCustomData(QStringLiteral("nada"), QStringLiteral("k"), QStringLiteral("v")).isEmpty());
        QVERIFY(db->save(path).isEmpty());

        KdbxStatus status = KdbxStatus::Corrupt;
        auto reopened = KdbxDatabase::open(path, password, &status);
        QVERIFY(reopened);
        QCOMPARE(reopened->customData().value(QStringLiteral("KPXC_BROWSER_laptop")), QStringLiteral("chave"));
        QCOMPARE(reopened->entryCustomData(QStringLiteral("KeePassXC-Browser Settings")),
                 (QHash<QString, QString>{{QStringLiteral("Web/A"), QStringLiteral("{\"Allow\":[\"a.com\"]}")}}));

        QCOMPARE(reopened->rootUuid().size(), 32);
        const QHash<QString, QString> entries = reopened->entryUuids();
        QCOMPARE(entries.keys(), QStringList{QStringLiteral("Web/A")});
        QCOMPARE(entries.value(QStringLiteral("Web/A")).size(), 32);
        QVERIFY(reopened->groupUuids().contains(QStringLiteral("Web")));
        QVERIFY(!reopened->groupUuids().contains(reopened->rootUuid()));

        // Removing the last item leaves no empty <CustomData> behind.
        QVERIFY(reopened->setEntryCustomData(QStringLiteral("Web/A"), QStringLiteral("KeePassXC-Browser Settings"),
                                             QString()).isEmpty());
        QVERIFY(reopened->setCustomData(QStringLiteral("KPXC_BROWSER_laptop"), QString()).isEmpty());
        QVERIFY(reopened->entryCustomData(QStringLiteral("KeePassXC-Browser Settings")).isEmpty());
        QVERIFY(!reopened->customData().contains(QStringLiteral("KPXC_BROWSER_laptop")));

        // KDBX 3.1 has no custom data on entries.
        auto legacy = KdbxDatabase::create(password, QStringLiteral("Velho"), true);
        QVERIFY(!legacy->hasEntryCustomData());
        QVERIFY(legacy->addEntry(QString(), entry).isEmpty());
        QVERIFY(!legacy->setEntryCustomData(QStringLiteral("A"), QStringLiteral("k"), QStringLiteral("v")).isEmpty());
    }

    void kdbxLegacyFormatRoundTrips() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.filePath(QStringLiteral("v3.kdbx"));
        const Secret password(QStringLiteral("antigo"));

        auto db = KdbxDatabase::create(password, QStringLiteral("V3"), true);
        QVERIFY(db);
        KdbxEntry entry;
        entry.title = QStringLiteral("Velho");
        entry.password = Secret(QStringLiteral("p4ss"));
        QVERIFY(db->addEntry(QStringLiteral("G"), entry).isEmpty());
        QVERIFY(db->save(path).isEmpty());

        KdbxStatus status = KdbxStatus::Corrupt;
        QVERIFY(!KdbxDatabase::open(path, Secret(QStringLiteral("x")), &status));
        QCOMPARE(status, KdbxStatus::WrongPassword);

        auto reopened = KdbxDatabase::open(path, password, &status);
        QVERIFY(reopened);
        KdbxEntry read;
        QVERIFY(reopened->entry(QStringLiteral("G/Velho"), &read));
        QCOMPARE(read.password.toString(), QStringLiteral("p4ss"));
        // Saved again it is still a 3.1 file, and still opens.
        QVERIFY(reopened->save(path).isEmpty());
        QVERIFY(KdbxDatabase::open(path, password, &status));

        // KeePassXC reads it too, when it is around.
        const QString cli = QStandardPaths::findExecutable(QStringLiteral("keepassxc-cli"));
        if (!cli.isEmpty()) {
            QProcess process;
            process.start(cli, {QStringLiteral("ls"), QStringLiteral("-Rfq"), path});
            process.write("antigo\n");
            process.closeWriteChannel();
            QVERIFY(process.waitForFinished(60000));
            QVERIFY(process.readAllStandardOutput().contains("G/Velho"));
        }
    }

    void kdbxInteroperatesWithKeepassxcCli() {
        QString cli = QStandardPaths::findExecutable(QStringLiteral("keepassxc-cli"));
        if (cli.isEmpty())
            cli = QStringLiteral(OMAPASS_SRC_ROOT "/build/keepassxc-cli");
        if (!QFileInfo::exists(cli))
            QSKIP("keepassxc-cli is not available");

        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.filePath(QStringLiteral("cli.kdbx"));
        const auto run = [&cli](const QStringList &args, const QByteArray &input, QByteArray *out = nullptr) {
            QProcess process;
            process.start(cli, args);
            process.write(input);
            process.closeWriteChannel();
            process.waitForFinished(60000);
            if (out)
                *out = process.readAllStandardOutput();
            return process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
        };

        // A database made by KeePassXC opens here.
        QVERIFY(run({QStringLiteral("db-create"), QStringLiteral("-p"), path}, "pw\npw\n"));
        QVERIFY(run({QStringLiteral("mkdir"), QStringLiteral("-q"), path, QStringLiteral("Site")}, "pw\n"));
        QVERIFY(run({QStringLiteral("add"), QStringLiteral("-q"), QStringLiteral("-p"), QStringLiteral("-u"),
                     QStringLiteral("bob"), path, QStringLiteral("Site/Login")},
                    "pw\nsegredo-cli\nsegredo-cli\n"));

        KdbxStatus status = KdbxStatus::Corrupt;
        auto db = KdbxDatabase::open(path, Secret(QStringLiteral("pw")), &status);
        QVERIFY2(db, "KeePassXC's database did not open");
        KdbxEntry entry;
        QVERIFY(db->entry(QStringLiteral("Site/Login"), &entry));
        QCOMPARE(entry.username, QStringLiteral("bob"));
        QCOMPARE(entry.password.toString(), QStringLiteral("segredo-cli"));

        // And what this writes, KeePassXC reads.
        KdbxEntry added;
        added.title = QStringLiteral("Novo");
        added.username = QStringLiteral("eva");
        added.password = Secret(QStringLiteral("segredo-omapass"));
        QVERIFY(db->addEntry(QStringLiteral("Site"), added).isEmpty());
        QVERIFY(db->save(path).isEmpty());

        QByteArray out;
        QVERIFY(run({QStringLiteral("ls"), QStringLiteral("-Rfq"), path}, "pw\n", &out));
        QVERIFY(out.contains("Site/Novo"));
        QVERIFY(run({QStringLiteral("show"), QStringLiteral("-q"), QStringLiteral("-s"), path,
                     QStringLiteral("Site/Novo"), QStringLiteral("-a"), QStringLiteral("Password")},
                    "pw\n", &out));
        QCOMPARE(QString::fromUtf8(out).trimmed(), QStringLiteral("segredo-omapass"));
    }

    void createsSshAttachments() {
        QTemporaryDir dir;
        for (bool legacy : {false, true}) {
            auto db = KdbxDatabase::create(Secret(QStringLiteral("pw")), QStringLiteral("SSH"), legacy);
            KdbxEntry entry;
            entry.title = QStringLiteral("Deploy");
            entry.sshAttachment = Secret(QByteArray("private key content\n"));
            entry.sshPublicKey = QStringLiteral("ssh-ed25519 YWJj deploy");
            QVERIFY(db->addEntry({}, entry).isEmpty());
            const QString path = dir.filePath(legacy ? QStringLiteral("3.kdbx") : QStringLiteral("4.kdbx"));
            QVERIFY(db->save(path).isEmpty());
            KdbxStatus status;
            db = KdbxDatabase::open(path, Secret(QStringLiteral("pw")), &status);
            QVERIFY(db);
            Secret key;
            QVERIFY(db->sshKey(entry.title, &key));
            QCOMPARE(key.bytes(), entry.sshAttachment.bytes());
            KdbxEntry edited;
            QVERIFY(db->entry(entry.title, &edited));
            QCOMPARE(edited.sshPublicKey, entry.sshPublicKey);
            edited.sshPublicKey += QStringLiteral("-updated");
            QVERIFY(db->editEntry(entry.title, {}, edited).isEmpty());
            QVERIFY(db->entry(entry.title, &entry));
            QCOMPARE(entry.sshPublicKey, edited.sshPublicKey);
            QVERIFY(db->sshKey(entry.title, &key));
            QCOMPARE(key.bytes(), QByteArray("private key content\n"));
        }
    }

    void kdbxReadsKeeAgentAttachments_data() {
        QTest::addColumn<bool>("legacy");
        QTest::newRow("KDBX 3.1") << true;
        QTest::newRow("KDBX 4") << false;
    }

    void kdbxReadsKeeAgentAttachments() {
        QFETCH(bool, legacy);
        const QString cli = QStandardPaths::findExecutable(QStringLiteral("keepassxc-cli"));
        if (cli.isEmpty())
            QSKIP("keepassxc-cli is not available");

        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.filePath(QStringLiteral("agent.kdbx"));
        const Secret password(QStringLiteral("pw"));
        auto db = KdbxDatabase::create(password, QStringLiteral("Agent"), legacy);
        QVERIFY(db);
        KdbxEntry entry;
        entry.title = QStringLiteral("SSH");
        QVERIFY(db->addEntry(QString(), entry).isEmpty());
        QVERIFY(db->save(path).isEmpty());

        const auto attach = [&](const QString &name, const QByteArray &bytes) {
            QFile file(dir.filePath(name));
            if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size())
                return false;
            file.close();
            return runProcess(cli, {QStringLiteral("attachment-import"), QStringLiteral("-q"),
                                    path, entry.title, name, file.fileName()}, "pw\n").success;
        };
        QVERIFY(attach(QStringLiteral("id_ed25519"), "key content\n"));
        QVERIFY(attach(QStringLiteral("KeeAgent.settings"), R"xml(
<EntrySettings>
  <AllowUseOfSshKey>true</AllowUseOfSshKey>
  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
  <UseConfirmConstraintWhenAdding>true</UseConfirmConstraintWhenAdding>
  <UseLifetimeConstraintWhenAdding>true</UseLifetimeConstraintWhenAdding>
  <LifetimeConstraintDuration>47</LifetimeConstraintDuration>
  <Location>
    <SelectedType>attachment</SelectedType>
    <AttachmentName>id_ed25519</AttachmentName>
  </Location>
</EntrySettings>)xml"));

        QString error;
        std::unique_ptr<KeepassVault> vault(KeepassVault::unlock(path, password, &error));
        QVERIFY2(vault, qPrintable(error));
        const auto config = vault->entryMeta().value(entry.title).ssh;
        QVERIFY(config);
        QVERIFY(config->defaults.addOnUnlock);
        QVERIFY(config->defaults.confirm);
        QCOMPARE(config->defaults.lifetimeSeconds, 47);

        Secret key;
        QVERIFY(vault->fetchSshKey(entry.title, config->id, &key, &error));
        QCOMPARE(key.bytes(), QByteArray("key content\n"));
        QVERIFY(vault->removeEntry(entry.title, &error));
        const auto after = vault->entryMeta();
        for (const EntryMeta &meta : after)
            QVERIFY(!meta.ssh);
    }
};

OMAPASS_TEST(TestKdbx)
#include "tst_kdbx.moc"
