#ifndef DAS_DATABASE_DELETE_INFO_H
#define DAS_DATABASE_DELETE_INFO_H

#include <exception>
#include <functional>
#include <cassert>

#include <QBitArray>

#include <Helpz/db_base.h>
#include <Helpz/db_builder.h>
#include <Helpz/db_delete_row.h>

#include <Das/section.h>
#include <Das/log/log_pack.h>

#include <Das/db/node.h>
#include <Das/db/disabled_param.h>
#include <Das/db/disabled_status.h>
#include <Das/db/chart.h>
#include <Das/db/dig_param.h>
#include <Das/db/dig_param_value.h>
#include <Das/db/dig_status.h>
#include <Das/db/device_item_value.h>
#include <Das/db/dig_mode.h>
#include <Das/db/value_view.h>
#include <Das/db/user.h>
#include <Das/db/auth_group.h>
#include <Das/db/scheme_group.h>
#include <Das/device.h>
#include <Das/type_managers.h>

#include "scheme_info.h"

namespace Das {
namespace DB {

using Delete_Info_List = Helpz::DB::Delete_Row_Info_List;

template<typename T>
Delete_Info_List db_delete_info(const QString&)
{
//    std::cout << "Have not db_delete_info for type " << typeid(T).name() << std::endl;
//    assert(false);
    return {};
}

template<>
inline Delete_Info_List db_delete_info< User >(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<User_Groups>(db_name), User_Groups::COL_user_id }
    };
}

template<>
inline Delete_Info_List db_delete_info< Auth_Group >(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<User_Groups>(db_name), User_Groups::COL_group_id },
        { Helpz::DB::db_table<Auth_Group_Permission>(db_name), Auth_Group_Permission::COL_group_id },
        { Helpz::DB::db_table<Disabled_Param>(db_name), Disabled_Param::COL_group_id },
        { Helpz::DB::db_table<Disabled_Status>(db_name), Disabled_Status::COL_group_id }
    };
}

template<>
inline Delete_Info_List db_delete_info< Node >(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<Node>(db_name), Node::COL_parent_id, {}, true }
    };
}

template<>
inline Delete_Info_List db_delete_info< Device_Item >(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<Log_Value_Item>(db_name), Log_Value_Item::COL_item_id },
        { Helpz::DB::db_table<Device_Item_Value>(db_name), Device_Item_Value::COL_item_id },
        { Helpz::DB::db_table<Device_Item>(db_name), Device_Item::COL_parent_id, {}, true },
        { Helpz::DB::db_table<Chart_Item>(db_name), Chart_Item::COL_item_id }
    };
}

template<>
inline Delete_Info_List db_delete_info<Device>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<Device_Item>(db_name), Device_Item::COL_device_id, db_delete_info<Device_Item>(db_name) }
    };
}

template<>
inline Delete_Info_List db_delete_info<Device_Item_Type>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<Device_Item>(db_name), Device_Item::COL_type_id, db_delete_info<Device_Item>(db_name) },
        { Helpz::DB::db_table<Value_View>(db_name), Value_View::COL_type_id }
    };
}

template<>
inline Delete_Info_List db_delete_info< Save_Timer >(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<Device_Item_Type>(db_name), Device_Item_Type::COL_save_timer_id, {}, true }
    };
}

template<>
inline Delete_Info_List db_delete_info< DIG_Param >(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<DIG_Param_Value>(db_name), DIG_Param_Value::COL_group_param_id },
        { Helpz::DB::db_table<Chart_Item>(db_name), Chart_Item::COL_param_id }
    };
}

template<>
inline Delete_Info_List db_delete_info<DIG_Status>(const QString& /*db_name*/) { return {}; }

template<>
inline Delete_Info_List db_delete_info<Device_Item_Group>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<DIG_Mode>(db_name), DIG_Mode::COL_group_id },
        { Helpz::DB::db_table<DIG_Param>(db_name), DIG_Param::COL_group_id, db_delete_info<DIG_Param>(db_name) },
        { Helpz::DB::db_table<DIG_Status>(db_name), DIG_Status::COL_group_id },
        { Helpz::DB::db_table<Device_Item>(db_name), Device_Item::COL_group_id, {}, true }
    };
}

template<>
inline Delete_Info_List db_delete_info<Section>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<Device_item_Group>(db_name), Device_item_Group::COL_section_id, db_delete_info<Device_item_Group>(db_name) }
    };
}

template<>
inline Delete_Info_List db_delete_info<DIG_Param_Type>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<DIG_Param>(db_name), DIG_Param::COL_param_id, db_delete_info<DIG_Param>(db_name) },
        { Helpz::DB::db_table<Disabled_Param>(db_name), Disabled_Param::COL_param_id }
    };
}

template<>
inline Delete_Info_List db_delete_info<DIG_Status_Type>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<DIG_Status>(db_name), DIG_Status::COL_status_id },
        { Helpz::DB::db_table<Disabled_Status>(db_name), Disabled_Status::COL_status_id }
    };
}

template<>
inline Delete_Info_List db_delete_info<DIG_Mode_Type>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<DIG_Mode>(db_name), DIG_Mode::COL_mode_id }
    };
}

template<>
inline Delete_Info_List db_delete_info<Sign_Type>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<Device_Item_Type>(db_name), Device_Item_Type::COL_sign_id, {}, true }
    };
}

template<>
inline Delete_Info_List db_delete_info<Plugin_Type>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<Device>(db_name), Device::COL_plugin_id, {}, true }
    };
}

template<>
inline Delete_Info_List db_delete_info<DIG_Status_Category>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<DIG_Status_Type>(db_name), DIG_Status_Type::COL_category_id, db_delete_info<DIG_Status_Type>(db_name) }
    };
}

template<>
inline Delete_Info_List db_delete_info<DIG_Type>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<Device_item_Group>(db_name), Device_item_Group::COL_type_id, db_delete_info<Device_item_Group>(db_name) },
        { Helpz::DB::db_table<DIG_Mode_Type>(db_name), DIG_Mode_Type::COL_group_type_id, {}, true },
        { Helpz::DB::db_table<Device_Item_Type>(db_name), Device_Item_Type::COL_group_type_id, db_delete_info<Device_Item_Type>(db_name) },
        { Helpz::DB::db_table<DIG_Param_Type>(db_name), DIG_Param_Type::COL_group_type_id, db_delete_info<DIG_Param_Type>(db_name) },
        { Helpz::DB::db_table<DIG_Status_Type>(db_name), DIG_Status_Type::COL_group_type_id, db_delete_info<DIG_Status_Type>(db_name) }
    };
}

template<>
inline Delete_Info_List db_delete_info<Chart>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<Chart_Item>(db_name), Chart_Item::COL_chart_id }
    };
}

template<>
inline Delete_Info_List db_delete_info<DB::Scheme_Group>(const QString& db_name)
{
    return {
        { Helpz::DB::db_table<DB::Scheme_Group_Scheme>(db_name), DB::Scheme_Group_Scheme::COL_scheme_group_id },
        { Helpz::DB::db_table<DB::Scheme_Group_User>(db_name), DB::Scheme_Group_User::COL_group_id }
    };
}

// has_scheme_id
template<typename T> constexpr bool has_scheme_id() { return true; }
template<> inline constexpr bool has_scheme_id<User>() { return false; }
template<> inline constexpr bool has_scheme_id<User_Groups>() { return false; }
template<> inline constexpr bool has_scheme_id<Auth_Group>() { return false; }
template<> inline constexpr bool has_scheme_id<Auth_Group_Permission>() { return false; }
template<> inline constexpr bool has_scheme_id<DB::Scheme_Group>() { return false; }
template<> inline constexpr bool has_scheme_id<DB::Scheme_Group_Scheme>() { return false; }
template<> inline constexpr bool has_scheme_id<DB::Scheme_Group_User>() { return false; }

template<typename T>
QString get_full_field_name(int index, bool add_short_name = false)
{
    QString res;
    if (add_short_name)
    {
        const QString short_name = T::table_short_name();
        if (!short_name.isEmpty())
        {
            res += short_name;
            res += '.';
        }
    }

    res += T::table_column_names().at(index);
    return res;
}

// Scheme_Table_Helper
template<typename T, auto pk_getter, int pk_num_value, int... extra_order_keys>
struct Scheme_Table_Helper_Impl
{
    using PK_Type = typename std::result_of<decltype(pk_getter)(T)>::type;
    static const int pk_num = pk_num_value;
    static PK_Type get_pk(const T& item) { return (item.*pk_getter)(); }
    static PK_Type get_query_pk(const QSqlQuery& q) { return q.value(pk_num).value<PK_Type>(); }

    static QString get_extra_orders(bool add_short_name = false)
    {
        if constexpr (!sizeof...(extra_order_keys))
            Q_UNUSED(add_short_name);

        QStringList orders {get_full_field_name<T>(extra_order_keys, add_short_name)...};
        return orders.join(',');
    }
};

template<typename T>
struct Scheme_Table_Helper : Scheme_Table_Helper_Impl<T, &T::id, 0> {};

template<>
struct Scheme_Table_Helper<Device_Item_Value> :
        Scheme_Table_Helper_Impl<Device_Item_Value, &Device_Item_Value::item_id, Device_Item_Value::COL_item_id> {};
template<>
struct Scheme_Table_Helper<DIG_Param_Value> :
        Scheme_Table_Helper_Impl<DIG_Param_Value, &DIG_Param_Value::group_param_id, DIG_Param_Value::COL_group_param_id> {};
template<>
struct Scheme_Table_Helper<DIG_Mode> :
        Scheme_Table_Helper_Impl<DIG_Mode, &DIG_Mode::group_id, DIG_Mode::COL_group_id> {};
template<>
struct Scheme_Table_Helper<User_Groups> :
        Scheme_Table_Helper_Impl<User_Groups, &User_Groups::id, User_Groups::COL_id, User_Groups::COL_user_id, User_Groups::COL_group_id> {};

// db_delete_rows
template<typename T, typename PK_Type = typename Scheme_Table_Helper<T>::PK_Type, template<typename> class Container = QVector>
bool db_delete_rows(Helpz::DB::Base& db, const Container<PK_Type>& delete_vect, const Scheme_Info& scheme,
                    const QString& db_name = QString())
{
    using namespace Helpz::DB;
    Table table = db_table<T>(db_name);
    if (table.field_names().isEmpty())
        return false;

    Delete_Row_Info_List delete_array = DB::db_delete_info<T>(db_name);

    Delete_Row_Helper::FILL_WHERE_FUNC_T fill_where_func;
    if (has_scheme_id<T>())
    {
        const QString where = scheme.ids_to_sql();
        fill_where_func = [where](const Delete_Row_Info& info, QString& where_str) -> void
        {
            Q_UNUSED(info)
            where_str += " AND " + where;
        };
    }

    const Delete_Row_Info row_info{table, Scheme_Table_Helper<T>::pk_num, delete_array, false, Scheme_Table_Helper<T>::pk_num};
    for (PK_Type id: delete_vect)
    {
        if (!Delete_Row_Helper(&db, QString::number(id), fill_where_func)
                .del(row_info))
        {
            return false;
        }
    }
    return true;
}

} // namespace DB
} // namespace Das

#endif // DAS_DATABASE_DELETE_INFO_H
