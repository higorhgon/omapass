QT += core gui qml quick qmltest dbus
CONFIG += c++20 link_pkgconfig
# Botan 3 where the distribution has it (Arch), Botan 2 where it does not
# (Ubuntu 24.04 LTS ships 2.19). Everything omapass asks of Botan exists in
# both; the two calls whose spelling changed are handled in bwcrypto.cpp.
packagesExist(botan-3) {
    PKGCONFIG += botan-3
} else {
    PKGCONFIG += botan-2
}
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
