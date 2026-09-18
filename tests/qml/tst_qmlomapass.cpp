// The interface tests. The components under test are the ones from the
// application's own resources, drawn in a real window (offscreen in CI), so
// what is exercised is what ships — the seams where the recent defects lived
// (a row showing the wrong field, a field that never took the keyboard) are
// not reachable any other way.
#include <QQmlContext>
#include <QQmlEngine>
#include <QtQuickTest>

#include "i18n.h"
#include "palette.h"
#include "systemtheme.h"

class Setup : public QObject {
    Q_OBJECT

public:
    Setup() { I18n::load(QStringLiteral("pt-BR")); }

public slots:
    void qmlEngineAvailable(QQmlEngine *engine) {
        // The same names main.cpp gives them, so the components need no
        // changes to be testable.
        engine->rootContext()->setContextProperty(QStringLiteral("theme"), &m_palette);
        engine->rootContext()->setContextProperty(QStringLiteral("systemTheme"), &m_systemTheme);
        engine->rootContext()->setContextProperty(QStringLiteral("i18n"), &m_strings);
    }

private:
    Palette m_palette{{}};
    SystemTheme m_systemTheme;
    Strings m_strings;
};

QUICK_TEST_MAIN_WITH_SETUP(qmlomapass, Setup)

#include "tst_qmlomapass.moc"
