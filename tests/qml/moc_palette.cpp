/****************************************************************************
** Meta object code from reading C++ file 'palette.h'
**
** Created by: The Qt Meta Object Compiler version 69 (Qt 6.11.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../src/palette.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'palette.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 69
#error "This file was generated using the moc from 6.11.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {
struct qt_meta_tag_ZN7PaletteE_t {};
} // unnamed namespace

template <> constexpr inline auto Palette::qt_create_metaobjectdata<qt_meta_tag_ZN7PaletteE_t>()
{
    namespace QMC = QtMocConstants;
    QtMocHelpers::StringRefStorage qt_stringData {
        "Palette",
        "changed",
        "",
        "darkModeChanged",
        "setSystemDarkMode",
        "darkMode",
        "background",
        "QColor",
        "surface",
        "selection",
        "base",
        "title",
        "guidance",
        "annotation",
        "important",
        "alertInfo",
        "alertWarn",
        "alertError"
    };

    QtMocHelpers::UintData qt_methods {
        // Signal 'changed'
        QtMocHelpers::SignalData<void()>(1, 2, QMC::AccessPublic, QMetaType::Void),
        // Signal 'darkModeChanged'
        QtMocHelpers::SignalData<void()>(3, 2, QMC::AccessPublic, QMetaType::Void),
        // Slot 'setSystemDarkMode'
        QtMocHelpers::SlotData<void(bool)>(4, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Bool, 5 },
        }}),
    };
    QtMocHelpers::UintData qt_properties {
        // property 'background'
        QtMocHelpers::PropertyData<QColor>(6, 0x80000000 | 7, QMC::DefaultPropertyFlags | QMC::EnumOrFlag, 0),
        // property 'surface'
        QtMocHelpers::PropertyData<QColor>(8, 0x80000000 | 7, QMC::DefaultPropertyFlags | QMC::EnumOrFlag, 0),
        // property 'selection'
        QtMocHelpers::PropertyData<QColor>(9, 0x80000000 | 7, QMC::DefaultPropertyFlags | QMC::EnumOrFlag, 0),
        // property 'base'
        QtMocHelpers::PropertyData<QColor>(10, 0x80000000 | 7, QMC::DefaultPropertyFlags | QMC::EnumOrFlag, 0),
        // property 'title'
        QtMocHelpers::PropertyData<QColor>(11, 0x80000000 | 7, QMC::DefaultPropertyFlags | QMC::EnumOrFlag, 0),
        // property 'guidance'
        QtMocHelpers::PropertyData<QColor>(12, 0x80000000 | 7, QMC::DefaultPropertyFlags | QMC::EnumOrFlag, 0),
        // property 'annotation'
        QtMocHelpers::PropertyData<QColor>(13, 0x80000000 | 7, QMC::DefaultPropertyFlags | QMC::EnumOrFlag, 0),
        // property 'important'
        QtMocHelpers::PropertyData<QColor>(14, 0x80000000 | 7, QMC::DefaultPropertyFlags | QMC::EnumOrFlag, 0),
        // property 'alertInfo'
        QtMocHelpers::PropertyData<QColor>(15, 0x80000000 | 7, QMC::DefaultPropertyFlags | QMC::EnumOrFlag, 0),
        // property 'alertWarn'
        QtMocHelpers::PropertyData<QColor>(16, 0x80000000 | 7, QMC::DefaultPropertyFlags | QMC::EnumOrFlag, 0),
        // property 'alertError'
        QtMocHelpers::PropertyData<QColor>(17, 0x80000000 | 7, QMC::DefaultPropertyFlags | QMC::EnumOrFlag, 0),
        // property 'darkMode'
        QtMocHelpers::PropertyData<bool>(5, QMetaType::Bool, QMC::DefaultPropertyFlags, 1),
    };
    QtMocHelpers::UintData qt_enums {
    };
    return QtMocHelpers::metaObjectData<Palette, qt_meta_tag_ZN7PaletteE_t>(QMC::MetaObjectFlag{}, qt_stringData,
            qt_methods, qt_properties, qt_enums);
}
Q_CONSTINIT const QMetaObject Palette::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN7PaletteE_t>.stringdata,
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN7PaletteE_t>.data,
    qt_static_metacall,
    nullptr,
    qt_staticMetaObjectRelocatingContent<qt_meta_tag_ZN7PaletteE_t>.metaTypes,
    nullptr
} };

void Palette::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<Palette *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->changed(); break;
        case 1: _t->darkModeChanged(); break;
        case 2: _t->setSystemDarkMode((*reinterpret_cast<std::add_pointer_t<bool>>(_a[1]))); break;
        default: ;
        }
    }
    if (_c == QMetaObject::IndexOfMethod) {
        if (QtMocHelpers::indexOfMethod<void (Palette::*)()>(_a, &Palette::changed, 0))
            return;
        if (QtMocHelpers::indexOfMethod<void (Palette::*)()>(_a, &Palette::darkModeChanged, 1))
            return;
    }
    if (_c == QMetaObject::ReadProperty) {
        void *_v = _a[0];
        switch (_id) {
        case 0: *reinterpret_cast<QColor*>(_v) = _t->background(); break;
        case 1: *reinterpret_cast<QColor*>(_v) = _t->surface(); break;
        case 2: *reinterpret_cast<QColor*>(_v) = _t->selection(); break;
        case 3: *reinterpret_cast<QColor*>(_v) = _t->base(); break;
        case 4: *reinterpret_cast<QColor*>(_v) = _t->title(); break;
        case 5: *reinterpret_cast<QColor*>(_v) = _t->guidance(); break;
        case 6: *reinterpret_cast<QColor*>(_v) = _t->annotation(); break;
        case 7: *reinterpret_cast<QColor*>(_v) = _t->important(); break;
        case 8: *reinterpret_cast<QColor*>(_v) = _t->alertInfo(); break;
        case 9: *reinterpret_cast<QColor*>(_v) = _t->alertWarn(); break;
        case 10: *reinterpret_cast<QColor*>(_v) = _t->alertError(); break;
        case 11: *reinterpret_cast<bool*>(_v) = _t->darkMode(); break;
        default: break;
        }
    }
}

const QMetaObject *Palette::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Palette::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_staticMetaObjectStaticContent<qt_meta_tag_ZN7PaletteE_t>.strings))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int Palette::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 3)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 3;
    }
    if (_c == QMetaObject::ReadProperty || _c == QMetaObject::WriteProperty
            || _c == QMetaObject::ResetProperty || _c == QMetaObject::BindableProperty
            || _c == QMetaObject::RegisterPropertyMetaType) {
        qt_static_metacall(this, _c, _id, _a);
        _id -= 12;
    }
    return _id;
}

// SIGNAL 0
void Palette::changed()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void Palette::darkModeChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}
QT_WARNING_POP
