#include "base_type.h"

namespace Das {
namespace DB {

Base_Type::Base_Type(uint32_t id, const QString &name, uint32_t scheme_id) :
    Schemed_Model(scheme_id),
    id_(id), name_(name) {}

uint32_t Base_Type::id() const { return id_; }
void Base_Type::set_id(uint32_t id) { id_ = id; }

QString Base_Type::name() const { return name_; }
void Base_Type::set_name(const QString &name) { if (name_ != name) name_ = name; }

QDataStream &operator>>(QDataStream &ds, Base_Type &item)
{
    return ds >> item.id_ >> item.name_;
}

QDataStream &operator<<(QDataStream &ds, const Base_Type &item)
{
    return ds << item.id() << item.name();
}

Titled_Type::Titled_Type(uint id, const QString &name, const QString &title) :
    Base_Type{id, name}, title_(title) {}

QString Titled_Type::title() const { return title_; }
void Titled_Type::set_title(const QString &title) { if (title_ != title) title_ = title; }

QDataStream &operator>>(QDataStream &ds, Titled_Type &item)
{
    return ds >> static_cast<Base_Type&>(item) >> item.title_;
}

QDataStream &operator<<(QDataStream &ds, const Titled_Type &item)
{
    return ds << static_cast<const Base_Type&>(item) << item.title();
}

} // namespace DB
} // namespace Das
