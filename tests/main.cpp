// The one test binary: every class registered with OMAPASS_TEST, run in
// turn, in name order so the output reads the same every time. The exit code
// is the number of failed tests, as QTEST_MAIN's would be for a single class.

#include "support.h"

#include "i18n.h"

#include <algorithm>
#include <memory>

QList<std::pair<QByteArray, TestFactory>> &testRegistry() {
    static QList<std::pair<QByteArray, TestFactory>> registry;
    return registry;
}

int main(int argc, char **argv) {
#ifdef QT_GUI_LIB
    QGuiApplication app(argc, argv);
#else
    QCoreApplication app(argc, argv);
#endif

    // The strings the tests compare against are the Portuguese ones.
    I18n::load(QStringLiteral("pt-BR"));

    auto tests = testRegistry();
    std::sort(tests.begin(), tests.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });

    int failed = 0;
    for (const auto &[name, make] : std::as_const(tests)) {
        const std::unique_ptr<QObject> test(make());
        failed += QTest::qExec(test.get(), argc, argv);
    }
    return failed;
}
