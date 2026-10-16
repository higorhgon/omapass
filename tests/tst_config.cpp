// config.toml, the interface language and the translations.

#include "support.h"

#include "config.h"
#include "i18n.h"

class TestConfig : public QObject {
    Q_OBJECT

private slots:
    void languageFromConfigBeatsEnvironment() {
        QCOMPARE(Config::resolveLanguage(QStringLiteral("en"), QStringLiteral("pt_BR.UTF-8"), QString()),
                 QStringLiteral("en"));
        QCOMPARE(Config::resolveLanguage(QStringLiteral("pt-BR"), QStringLiteral("en_US.UTF-8"), QString()),
                 QStringLiteral("pt-BR"));
    }

    void languageIsDetectedFromEnvironment() {
        QCOMPARE(Config::resolveLanguage(QString(), QStringLiteral("en_US.UTF-8"), QString()),
                 QStringLiteral("en"));
        QCOMPARE(Config::resolveLanguage(QStringLiteral("auto"), QStringLiteral("pt_PT.UTF-8"), QString()),
                 QStringLiteral("pt-BR"));
    }

    void languageFallsBackToLcAllThenEnglish() {
        QCOMPARE(Config::resolveLanguage(QString(), QString(), QStringLiteral("pt_BR.UTF-8")),
                 QStringLiteral("pt-BR"));
        QCOMPARE(Config::resolveLanguage(QString(), QString(), QString()), QStringLiteral("en"));
        QCOMPARE(Config::resolveLanguage(QString(), QStringLiteral("fr_FR.UTF-8"), QString()),
                 QStringLiteral("en"));
    }

    void tomlEditsKeepEverythingElseInPlace() {
        const QString original = QStringLiteral(
            "[general]\n"
            "# quanto tempo até travar\n"
            "path = \"~/\"  # comentário do valor\n"
            "lock_minutes = 10\n"
            "algo_que_nao_conheco = 1\n"
            "\n"
            "[generator]\n"
            "wordlist = \"auto\"\n");

        QMap<QString, QString> values;
        values.insert(QStringLiteral("general.path"), Config::tomlString(QStringLiteral("~/docs")));
        values.insert(QStringLiteral("general.recency"), QStringLiteral("false"));
        values.insert(QStringLiteral("generator.wordlist"), Config::tomlString(QStringLiteral("pt-BR")));

        const QString edited = Config::applyTomlEdits(original, values);

        // Changed values, with the comment after the value kept.
        QVERIFY(edited.contains(QStringLiteral("path = \"~/docs\"  # comentário do valor")));
        QVERIFY(edited.contains(QStringLiteral("wordlist = \"pt-BR\"")));
        // A key that did not exist lands in its own section, not at the end.
        QVERIFY(edited.indexOf(QStringLiteral("recency = false")) > edited.indexOf(QStringLiteral("[general]")));
        QVERIFY(edited.indexOf(QStringLiteral("recency = false")) < edited.indexOf(QStringLiteral("[generator]")));
        // Comments, untouched keys and the rest stay as they were.
        QVERIFY(edited.contains(QStringLiteral("# quanto tempo até travar")));
        QVERIFY(edited.contains(QStringLiteral("algo_que_nao_conheco = 1")));
        QVERIFY(edited.contains(QStringLiteral("lock_minutes = 10")));

        const QHash<QString, QString> reread = [&edited]() {
            QTemporaryDir dir;
            const QString path = dir.filePath(QStringLiteral("config.toml"));
            QFile file(path);
            if (!file.open(QIODevice::WriteOnly))
                return QHash<QString, QString>();   // and the comparisons below fail
            file.write(edited.toUtf8());
            file.close();
            return Config::readFlatToml(path);
        }();
        QCOMPARE(reread.value(QStringLiteral("general.path")), QStringLiteral("~/docs"));
        QCOMPARE(reread.value(QStringLiteral("general.recency")), QStringLiteral("false"));
        QCOMPARE(reread.value(QStringLiteral("generator.wordlist")), QStringLiteral("pt-BR"));
    }

    void tomlEditsCreateAMissingSection() {
        const QString edited = Config::applyTomlEdits(
            QStringLiteral("[general]\npath = \"~/\"\n"),
            {{QStringLiteral("generator.wordlist"), Config::tomlString(QStringLiteral("en"))}});

        QVERIFY(edited.contains(QStringLiteral("[generator]")));
        QVERIFY(edited.indexOf(QStringLiteral("wordlist = \"en\"")) > edited.indexOf(QStringLiteral("[generator]")));

        // An empty file still comes out readable.
        const QString fromEmpty = Config::applyTomlEdits(
            QString(), {{QStringLiteral("general.recency"), QStringLiteral("true")}});
        QVERIFY(fromEmpty.contains(QStringLiteral("[general]")));
        QVERIFY(fromEmpty.endsWith(QLatin1Char('\n')));
    }

    void flatTomlReadsSectionsAndStripsQuotes() {
        QTemporaryFile file;
        QVERIFY(file.open());
        file.write("# a comment\n[general]\npath = \"~/docs\"\nrecency = true\n\n"
                   "[colors]\nTitle = '#00AAAA'  \n");
        file.close();

        const QHash<QString, QString> values = Config::readFlatToml(file.fileName());
        QCOMPARE(values.value(QStringLiteral("general.path")), QStringLiteral("~/docs"));
        QCOMPARE(values.value(QStringLiteral("general.recency")), QStringLiteral("true"));
        QCOMPARE(values.value(QStringLiteral("colors.Title")), QStringLiteral("#00AAAA"));

        // A quoted value keeps a '#' of its own and drops a comment after it.
        QTemporaryFile withComments;
        QVERIFY(withComments.open());
        withComments.write("[general]\npath = \"~/a#b\"  # comentário\nrecency = true # outro\n");
        withComments.close();

        const QHash<QString, QString> parsed = Config::readFlatToml(withComments.fileName());
        QCOMPARE(parsed.value(QStringLiteral("general.path")), QStringLiteral("~/a#b"));
        QCOMPARE(parsed.value(QStringLiteral("general.recency")), QStringLiteral("true"));
    }

    void lockMinutesDefaultsToTenWhenAbsent() {
        QCOMPARE(Config::parseLockMinutes(QString()), std::optional<int>(10));
    }

    void lockMinutesFalseDisablesAutoLock() {
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("false")), std::optional<int>());
    }

    void lockMinutesAcceptsAPositiveInteger() {
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("30")), std::optional<int>(30));
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("1")), std::optional<int>(1));
    }

    void lockMinutesFallsBackToDefaultOnInvalidValues() {
        const std::optional<int> tenMinutes(10);
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("0")), tenMinutes);
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("-5")), tenMinutes);
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("true")), tenMinutes);
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("nunca")), tenMinutes);
    }

    void translationsInterpolateArguments() {
        const QString text = I18n::t(QStringLiteral("cli.version"), QStringLiteral("version"),
                                     QStringLiteral("9.9.9"));
        QVERIFY(text.contains(QStringLiteral("9.9.9")));
        QVERIFY(!text.contains(QStringLiteral("%{")));
    }

    void unknownTranslationKeyFallsBackToItself() {
        QCOMPARE(I18n::t(QStringLiteral("no.such.key")), QStringLiteral("no.such.key"));
    }
};

OMAPASS_TEST(TestConfig)
#include "tst_config.moc"
