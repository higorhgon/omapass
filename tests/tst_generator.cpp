// The password and passphrase generator.

#include "support.h"

#include "generator.h"
#include "config.h"

class TestGenerator : public QObject {
    Q_OBJECT

private slots:
    void generatorHonoursClassesLengthAndExclusions() {
        GeneratorOptions options;
        options.length = 40;
        options.special = false;
        options.excludeSimilar = true;
        options.exclude = QStringLiteral("aeiou");

        for (int round = 0; round < 20; ++round) {
            Secret generated;
            QString error;
            QVERIFY(Generator::generate(options, &generated, &error));
            const QString text = generated.toString();
            QCOMPARE(text.size(), 40);
            bool lower = false, upper = false, number = false;
            for (const QChar c : text) {
                QVERIFY2(c.isLetterOrNumber(), "no special characters were asked for");
                QVERIFY(!QStringLiteral("aeiouiIl1|Lo0O").contains(c));
                lower |= c.isLower();
                upper |= c.isUpper();
                number |= c.isDigit();
            }
            QVERIFY(lower && upper && number);
        }
    }

    void generatorCustomSetReplacesTheClasses() {
        GeneratorOptions options;
        options.custom = QStringLiteral("ab");
        options.length = 30;

        Secret generated;
        QString error;
        QVERIFY(Generator::generate(options, &generated, &error));
        for (const QChar c : generated.toString())
            QVERIFY(c == QLatin1Char('a') || c == QLatin1Char('b'));
    }

    void generatorPassphraseDrawsWordsFromTheList() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString list = dir.filePath(QStringLiteral("w.wordlist"));
        QFile file(list);
        QVERIFY(file.open(QIODevice::WriteOnly));
        for (int i = 0; i < Generator::minimumWordlistSize; ++i)
            file.write(QByteArray("palavra") + QByteArray::number(i) + "\n");
        file.close();

        Generator::configure(list, QStringLiteral("en"));
        GeneratorOptions options;
        options.passphrase = true;
        options.words = 5;
        options.separator = QStringLiteral("-");

        Secret generated;
        QString error;
        QVERIFY(Generator::generate(options, &generated, &error));
        const QStringList words = generated.toString().split(QLatin1Char('-'));
        QCOMPARE(words.size(), 5);
        for (const QString &word : words)
            QVERIFY(word.startsWith(QStringLiteral("palavra")));
        Generator::configure(QStringLiteral("auto"), QStringLiteral("en"));
    }

    void generatorWordlistFollowsConfigAndLanguage() {
        const QString english = QStringLiteral("eff_large.wordlist");

        // "auto": the interface language first, English behind it.
        QCOMPARE(Generator::wordlistNames(QStringLiteral("auto"), QStringLiteral("pt-BR")),
                 QStringList({QStringLiteral("pt-BR.wordlist"), english}));
        QCOMPARE(Generator::wordlistNames(QStringLiteral("auto"), QStringLiteral("en")),
                 QStringList({english}));

        // A named list still falls back to English; "en" is the English one.
        QCOMPARE(Generator::wordlistNames(QStringLiteral("pt-BR"), QStringLiteral("en")),
                 QStringList({QStringLiteral("pt-BR.wordlist"), english}));
        QCOMPARE(Generator::wordlistNames(QStringLiteral("en"), QStringLiteral("pt-BR")),
                 QStringList({english}));

        // A path is taken as it is, with nothing behind it.
        QCOMPARE(Generator::wordlistNames(QStringLiteral("/tmp/minha.txt"), QStringLiteral("pt-BR")),
                 QStringList({QStringLiteral("/tmp/minha.txt")}));

        QVERIFY(!Generator::wordlistDirectories().isEmpty());
    }

    void generatorOptionsAreBounded() {
        GeneratorOptions options;
        options.length = 2;
        options.words = 99;
        options.lower = options.upper = options.numbers = options.special = false;

        const GeneratorOptions bounded = Generator::normalize(options);
        QCOMPARE(bounded.length, 4);
        QCOMPARE(bounded.words, 16);
        // Nothing selected would leave no characters to draw from.
        QVERIFY(bounded.lower);

        GeneratorOptions custom;
        custom.custom = QStringLiteral("xyz");
        custom.lower = custom.upper = custom.numbers = custom.special = false;
        QVERIFY(!Generator::normalize(custom).lower);
    }
};

OMAPASS_TEST(TestGenerator)
#include "tst_generator.moc"
