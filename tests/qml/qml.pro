QT += core gui qml quick qmltest dbus
# No crypto here: these tests draw components, and the sources they need
# (theme, text scale, translations) do not touch Botan.
CONFIG += c++20
TEMPLATE = app
TARGET = tst_qmlomapass

INCLUDEPATH += ../../src

SOURCES += \
    tst_qmlomapass.cpp \
    ../../src/config.cpp \
    ../../src/i18n.cpp \
    ../../src/palette.cpp \
    ../../src/systemtheme.cpp

HEADERS += \
    ../../src/config.h \
    ../../src/i18n.h \
    ../../src/palette.h \
    ../../src/systemtheme.h

RESOURCES += ../../src/resources.qrc
