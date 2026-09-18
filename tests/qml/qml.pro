QT += core gui qml quick qmltest dbus
CONFIG += c++20 link_pkgconfig
PKGCONFIG += botan-3
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
