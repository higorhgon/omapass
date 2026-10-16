// The .kdbx reader and writer.

#include "support.h"

#include "kdbx.h"
#include "kdbx2pass.h"
#include "process.h"

class TestKdbx : public QObject {
    Q_OBJECT

private slots:
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
};

OMAPASS_TEST(TestKdbx)
#include "tst_kdbx.moc"
