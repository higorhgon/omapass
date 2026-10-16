// The .kdbx reader and writer.

#include "support.h"

#include "kdbx.h"
#include "kdbx2pass.h"
#include "keepassvault.h"
#include "process.h"

#include <QElapsedTimer>

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
