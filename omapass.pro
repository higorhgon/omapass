QT += core gui qml quick quickcontrols2 dbus

CONFIG += c++17 release
TARGET = omapass
TEMPLATE = app

HEADERS += \
    src/appcontroller.h \
    src/clipboard.h \
    src/config.h \
    src/filter.h \
    src/history.h \
    src/i18n.h \
    src/keepassvault.h \
    src/kdbx2pass.h \
    src/palette.h \
    src/passstore.h \
    src/passvault.h \
    src/process.h \
    src/secret.h \
    src/sessionlock.h \
    src/systemtheme.h \
    src/vault.h

SOURCES += \
    src/main.cpp \
    src/appcontroller.cpp \
    src/clipboard.cpp \
    src/config.cpp \
    src/filter.cpp \
    src/history.cpp \
    src/i18n.cpp \
    src/keepassvault.cpp \
    src/kdbx2pass.cpp \
    src/palette.cpp \
    src/passstore.cpp \
    src/passvault.cpp \
    src/process.cpp \
    src/secret.cpp \
    src/sessionlock.cpp \
    src/systemtheme.cpp \
    src/vault.cpp

RESOURCES += src/resources.qrc
