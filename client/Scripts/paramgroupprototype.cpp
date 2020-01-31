#include <QtScript/QScriptEngine>
#include <QDateTime>
#include <QDebug>

#include <memory>

#include "paramgroupclass.h"
#include "paramgroupprototype.h"

namespace Das {

/*static*/ Param ParamGroupPrototype::empty_param;

ParamGroupPrototype::ParamGroupPrototype(ParamGroupClass *parent) :
    QObject(parent), pgClass(parent)
{
}

QString ParamGroupPrototype::title() const
{
    return thisParam()->type()->title();
}

uint32_t ParamGroupPrototype::type() const
{
    return thisParam()->type()->id();
}

QString ParamGroupPrototype::name() const
{
    return thisParam()->type()->name();
}

int ParamGroupPrototype::length() const
{
    return thisParam()->count();
}

QScriptValue ParamGroupPrototype::byTypeId(uint32_t DIG_param_type) const
{
    Param* param = thisParam()->get_by_type_id(DIG_param_type);
    if (!param)
        return QScriptValue();
    return ParamGroupClass::toScriptValue(engine(), param);
}

QString ParamGroupPrototype::toString() const
{
    Param* param = thisParam();
//    if (param->type().type == DIG_Param_Type::TimeType)
//        return QDateTime::fromMSecsSinceEpoch(param->value().toLongLong()).toString();
    return param->value().toString();
}

QScriptValue ParamGroupPrototype::valueOf() const
{
    Param* param = thisParam();
//    if (param->type().type == DIG_Param_Type::TimeType)
//        return engine()->newDate(QDateTime::fromMSecsSinceEpoch(param->value().toLongLong()));
    if (pgClass)
        return pgClass->getValue(param);
    return engine()->newVariant(param->value());
}

Param *ParamGroupPrototype::thisParam() const
{
    Param* param = thisObject().data().toVariant().value<Param*>();
    return param ? param : &empty_param;
}

} // namespace Das
