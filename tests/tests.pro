QT += core testlib
CONFIG += testcase c++20 link_pkgconfig
PKGCONFIG += botan-3
DEFINES += OMAPASS_BW_FIXTURES=\\\"$$PWD/fixtures/bitwarden\\\"
DEFINES += OMAPASS_OP_FIXTURES=\\\"$$PWD/fixtures/onepassword\\\"
TEMPLATE = app
TARGET = tst_omapass

INCLUDEPATH += ../src

SOURCES += \
    tst_omapass.cpp \
    ../src/bitwardenjson.cpp \
    ../src/bwcrypto.cpp \
    ../src/bwpin.cpp \
    ../src/bwcache.cpp \
    ../src/config.cpp \
    ../src/filter.cpp \
    ../src/generator.cpp \
    ../src/history.cpp \
    ../src/i18n.cpp \
    ../src/kdbx2pass.cpp \
    ../src/opjson.cpp \
    ../src/passstore.cpp \
    ../src/process.cpp \
    ../src/secret.cpp

HEADERS += \
    ../src/bitwardenjson.h \
    ../src/bwcache.h \
    ../src/bwcrypto.h \
    ../src/bwpin.h \
    ../src/config.h \
    ../src/filter.h \
    ../src/generator.h \
    ../src/history.h \
    ../src/i18n.h \
    ../src/kdbx2pass.h \
    ../src/opjson.h \
    ../src/passstore.h \
    ../src/process.h \
    ../src/secret.h

RESOURCES += ../src/resources.qrc
