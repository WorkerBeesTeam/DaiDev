#include "scheme_group.h"

namespace Das {
namespace DB {

Scheme_Group::Scheme_Group(uint32_t id, const QString &name) :
    ID_Type(id),
    _name(name) {}

QString Scheme_Group::name() const { return _name; }
void Scheme_Group::set_name(const QString &name) { _name = name; }

QDataStream &operator>>(QDataStream &ds, Scheme_Group &item)
{
    return ds >> item._id >> item._name;
}

QDataStream &operator<<(QDataStream &ds, const Scheme_Group &item)
{
    return ds << item.id() << item.name();
}

// Scheme_Group_Scheme ---------
Scheme_Group_Scheme::Scheme_Group_Scheme(uint32_t id, uint32_t scheme_group_id, uint32_t scheme_id) :
    Base_Type{id, scheme_id},
    _scheme_group_id{scheme_group_id} {}

uint32_t Scheme_Group_Scheme::scheme_group_id() const { return _scheme_group_id; }
void Scheme_Group_Scheme::set_scheme_group_id(uint32_t scheme_group_id) { _scheme_group_id = scheme_group_id; }

QDataStream &operator>>(QDataStream &ds, Scheme_Group_Scheme &item)
{
    ds >> static_cast<Base_Type&>(item) >> item._scheme_group_id;

    uint32_t scheme_id;
    ds >> scheme_id;
    item.set_scheme_id(scheme_id);

    return ds;
}

QDataStream &operator<<(QDataStream &ds, const Scheme_Group_Scheme &item)
{
    return ds << static_cast<const Base_Type&>(item) << item.scheme_group_id() << item.scheme_id();
}

// Scheme_Group_User ---------
Scheme_Group_User::Scheme_Group_User(uint32_t id, uint32_t group_id, uint32_t user_id) :
    ID_Type(id),
    _group_id(group_id), _user_id(user_id) {}

uint32_t Scheme_Group_User::group_id() const { return _group_id; }
void Scheme_Group_User::set_group_id(uint32_t group_id) { _group_id = group_id; }

uint32_t Scheme_Group_User::user_id() const { return _user_id; }
void Scheme_Group_User::set_user_id(uint32_t user_id) { _user_id = user_id; }

QDataStream &operator>>(QDataStream &ds, Scheme_Group_User &item)
{
    return ds >> item._id >> item._group_id >> item._user_id;
}

QDataStream &operator<<(QDataStream &ds, const Scheme_Group_User &item)
{
    return ds << item.id() << item.group_id() << item.user_id();
}

} // namespace DB
} // namespace Das
