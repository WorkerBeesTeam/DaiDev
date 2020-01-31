#ifndef PARAMCLASS_H
#define PARAMCLASS_H

#include <QtCore/QObject>
#include <QtScript/QScriptClass>
#include <QtScript/QScriptString>

#include "Das/device_item_group.h"

QT_BEGIN_NAMESPACE
class QScriptContext;
QT_END_NAMESPACE

namespace Das {

class ParamGroupClass : public QObject, public QScriptClass
{
    Q_OBJECT
public:
    ParamGroupClass(QScriptEngine *engine);

    QScriptValue newInstance(Param* param);
    static QScriptValue newInstance(ParamGroupClass *pgClass, Param* param);

    QScriptValue getValue(Param* param);
    static QScriptValue getValue(ParamGroupClass *pgClass, Param* param);

    QueryFlags queryProperty(const QScriptValue &object,
                             const QScriptString &name,
                             QueryFlags flags, uint *id) override;

    QScriptValue property(const QScriptValue &object,
                          const QScriptString &name, uint id) override;

    void setProperty(QScriptValue &object, const QScriptString &name,
                     uint id, const QScriptValue &value) override;

    QScriptValue::PropertyFlags propertyFlags(
        const QScriptValue &object, const QScriptString &name, uint id) override;

    QScriptClassPropertyIterator *newIterator(const QScriptValue &object) override;

    QString name() const override;
    QScriptValue prototype() const override;

    QScriptValue constructor();
private:
    static QScriptValue construct(QScriptContext *ctx, QScriptEngine *);

    static QScriptValue toScriptValue(QScriptEngine *eng, Param * const &param);
    static void fromScriptValue(const QScriptValue &obj, Param *&param);

    QScriptValue proto, f_ctor;

    friend class ParamGroupPrototype;
    friend class ParamGroupClassPropertyIterator;
};

} // namespace Das

#endif // PARAMCLASS_H
