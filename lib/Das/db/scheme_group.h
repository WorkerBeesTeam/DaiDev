#ifndef DAS_DB_SCHEME_GROUP_H
#define DAS_DB_SCHEME_GROUP_H

#include <Helpz/db_meta.h>

#include <Das/daslib_global.h>
#include <Das/db/base_type.h>

namespace Das {
namespace DB {

class DAS_LIBRARY_SHARED_EXPORT Scheme_Group : public ID_Type
{
    HELPZ_DB_META(Scheme_Group, "scheme_group", "sg", DB_A(id), DB_A(name))
public:
    explicit Scheme_Group(uint32_t id = 0, const QString &name = {});
    Scheme_Group(Scheme_Group&& other) = default;
    Scheme_Group(const Scheme_Group& other) = default;
    Scheme_Group& operator=(Scheme_Group&& other) = default;
    Scheme_Group& operator=(const Scheme_Group& other) = default;

    QString name() const;
    void set_name(const QString& name);

private:
    QString _name;

    friend QDataStream &operator>>(QDataStream &ds, Scheme_Group &item);
};

QDataStream &operator>>(QDataStream &ds, Scheme_Group &item);
QDataStream &operator<<(QDataStream &ds, const Scheme_Group &item);

class DAS_LIBRARY_SHARED_EXPORT Scheme_Group_Scheme : public Base_Type
{
    HELPZ_DB_META(Scheme_Group_Scheme, "scheme_groups", "sgs", DB_A(id), DB_A(scheme_group_id), DB_A(scheme_id))
public:
    explicit Scheme_Group_Scheme(uint32_t id = 0, uint32_t scheme_group_id = 0, uint32_t scheme_id = 0);
    Scheme_Group_Scheme(Scheme_Group_Scheme&& other) = default;
    Scheme_Group_Scheme(const Scheme_Group_Scheme& other) = default;
    Scheme_Group_Scheme& operator=(Scheme_Group_Scheme&& other) = default;
    Scheme_Group_Scheme& operator=(const Scheme_Group_Scheme& other) = default;

    uint32_t scheme_group_id() const;
    void set_scheme_group_id(uint32_t scheme_group_id);

private:
    uint32_t _scheme_group_id;

    friend QDataStream &operator>>(QDataStream &ds, Scheme_Group_Scheme &item);
};

QDataStream &operator>>(QDataStream &ds, Scheme_Group_Scheme &item);
QDataStream &operator<<(QDataStream &ds, const Scheme_Group_Scheme &item);

class DAS_LIBRARY_SHARED_EXPORT Scheme_Group_User : public ID_Type
{
    HELPZ_DB_META(Scheme_Group_User, "scheme_group_user", "sgu", DB_A(id), DB_A(group_id), DB_A(user_id))
public:
    explicit Scheme_Group_User(uint32_t id = 0, uint32_t group_id = 0, uint32_t user_id = 0);
    Scheme_Group_User(Scheme_Group_User&& other) = default;
    Scheme_Group_User(const Scheme_Group_User& other) = default;
    Scheme_Group_User& operator=(Scheme_Group_User&& other) = default;
    Scheme_Group_User& operator=(const Scheme_Group_User& other) = default;

    uint32_t group_id() const;
    void set_group_id(uint32_t group_id);

    uint32_t user_id() const;
    void set_user_id(uint32_t user_id);

private:
    uint32_t _group_id, _user_id;

    friend QDataStream &operator>>(QDataStream &ds, Scheme_Group_User &item);
};

QDataStream &operator>>(QDataStream &ds, Scheme_Group_User &item);
QDataStream &operator<<(QDataStream &ds, const Scheme_Group_User &item);

} // namespace DB
} // namespace Das

#endif // DAS_DB_SCHEME_GROUP_H
