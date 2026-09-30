#pragma once

#include <QObject>

// The handful of things DatabasePage asks of the application window: the
// text scale every size is written against, and the flag that tells the
// window whether Ctrl+C should copy or quit.
class FakeWindow : public QObject {
    Q_OBJECT

    Q_PROPERTY(qreal s MEMBER m_scale CONSTANT)
    Q_PROPERTY(bool editingText MEMBER m_editingText NOTIFY editingTextChanged)

public:
    using QObject::QObject;

signals:
    void editingTextChanged();

private:
    qreal m_scale = 1.0;
    bool m_editingText = false;
};
