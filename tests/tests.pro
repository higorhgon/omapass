QT += core testlib
CONFIG += testcase c++20 link_pkgconfig
PKGCONFIG += botan-3
DEFINES += OMAPASS_BW_FIXTURES=\\\"$$PWD/fixtures/bitwarden\\\"
DEFINES += OMAPASS_OP_FIXTURES=\\\"$$PWD/fixtures/onepassword\\\"
DEFINES += OMAPASS_FAKE_CLIS=\\\"$$PWD/fakes\\\"
TEMPLATE = app
TARGET = tst_omapass

INCLUDEPATH += ../src

SOURCES += \
    tst_omapass.cpp \
    ../src/bitwardenjson.cpp \
    ../src/bitwardenvault.cpp \
    ../src/bwcrypto.cpp \
    ../src/bwcache.cpp \
    ../src/config.cpp \
    ../src/filter.cpp \
    ../src/generator.cpp \
    ../src/history.cpp \
    ../src/i18n.cpp \
    ../src/kdbx2pass.cpp \
    ../src/keepassvault.cpp \
    ../src/onepasswordlogin.cpp \
    ../src/onepasswordvault.cpp \
    ../src/opjson.cpp \
    ../src/passstore.cpp \
    ../src/passvault.cpp \
    ../src/pin.cpp \
    ../src/process.cpp \
    ../src/secret.cpp \
    ../src/vault.cpp

HEADERS += \
    ../src/bitwardenjson.h \
    ../src/bitwardenvault.h \
    ../src/bwcache.h \
    ../src/bwcrypto.h \
    ../src/config.h \
    ../src/filter.h \
    ../src/generator.h \
    ../src/history.h \
    ../src/i18n.h \
    ../src/kdbx2pass.h \
    ../src/keepassvault.h \
    ../src/onepasswordlogin.h \
    ../src/onepasswordvault.h \
    ../src/opjson.h \
    ../src/passstore.h \
    ../src/passvault.h \
    ../src/pin.h \
    ../src/process.h \
    ../src/secret.h \
    ../src/vault.h

RESOURCES += ../src/resources.qrc
