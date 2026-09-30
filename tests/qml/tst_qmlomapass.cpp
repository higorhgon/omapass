// The interface tests. The components under test are the ones from the
// application's own resources, drawn in a real window (offscreen in CI), so
// what is exercised is what ships — the seams where the recent defects lived
// (a row showing the wrong field, a field that never took the keyboard) are
// not reachable any other way.
#include <QQmlContext>
#include <QQmlEngine>
#include <QtQuickTest>

#include "fakecontroller.h"
#include "fakewindow.h"
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
        // DatabasePage reads both of these the way it does in the running
        // application: `controller` for what to show, `window` for the text
        // scale and the Ctrl+C binding.
        engine->rootContext()->setContextProperty(QStringLiteral("controller"), &m_controller);
        engine->rootContext()->setContextProperty(QStringLiteral("window"), &m_window);
    }

private:
    Palette m_palette{{}};
    SystemTheme m_systemTheme;
    Strings m_strings;
    FakeController m_controller;
    FakeWindow m_window;
};

QUICK_TEST_MAIN_WITH_SETUP(qmlomapass, Setup)

#include "tst_qmlomapass.moc"
