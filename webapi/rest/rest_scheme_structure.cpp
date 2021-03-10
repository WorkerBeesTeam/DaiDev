#include <exception>

#include <served/status.hpp>
#include <served/request_error.hpp>

#include <QSqlError>

#include <plus/das/database_delete_info.h>
#include <Das/db/translation.h>

#include "rest_helper.h"
#include "json_helper.h"
#include "auth_middleware.h"
#include "rest_scheme.h"
#include "rest_scheme_structure.h"

namespace Das {
namespace Rest {

using namespace Helpz::DB;

template<typename T>
picojson::array get_elements(const served::request &req, const std::string& struct_name, const QString& where = {})
{
    Auth_Middleware::check_permission("view_" + struct_name);
    const Scheme_Info scheme = Scheme::get_info(req);

    Base& db = Base::get_thread_local_instance();
    const Table table = db_table<T>();

    QString sql = "WHERE ";
    if (!where.isEmpty())
        sql += where + " AND ";
    sql += scheme.ids_to_sql();

    QSqlQuery q = db.select(table, sql);
    if (!q.isActive())
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());

    picojson::array json;
    while (q.next())
        json.emplace_back(gen_json_object<T>(q, table.field_names()));
    return json;
}

template<typename T>
void get_element_list(served::response &res, const served::request &req, const std::string& struct_name)
{
    picojson::array json = get_elements<T>(req, struct_name);
    res.set_header("Content-Type", "application/json");
    res << picojson::value{json}.serialize();
}

template<typename T>
int del_elements(const Scheme_Info& scheme, const std::vector<uint32_t>& id_vect)
{
    if (id_vect.empty())
        return 0;

    Base& db = Base::get_thread_local_instance();
    if (!DB::db_delete_rows<T>(db, id_vect, scheme))
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());
    return id_vect.size(); // TODO: Либо возвращать кол-во строк, либо JSON с удалёнными объектами
}

template<typename T>
picojson::value create_element_impl(const Table& table, T& elem)
{
    Base& db = Base::get_thread_local_instance();

    QVariant id;
    const QVariantList values = T::to_variantlist(elem);
    const QString sql = db.insert_query(table, values.size());
    const QSqlQuery q = db.exec(sql, values, &id);
    if (!q.isActive())
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());

    elem.set_id(id.toUInt());
    return picojson::value{obj_to_pico(elem, table.field_names())};
}

template<typename T>
bool update_element_impl(const Table& table, T& elem, const QString& where_suffix)
{
    QVariantList values = T::to_variantlist(elem);
    values.removeAt(T::COL_scheme_id);
    values.removeFirst(); // remove id

    Base& db = Base::get_thread_local_instance();
    const QSqlQuery q = db.update(table, values, "id = " + QString::number(elem.id()) + where_suffix);
    if (!q.isActive())
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());
    return q.numRowsAffected() > 0;
}

template<typename T>
void modify_element_list(served::response &res, const served::request &req, const std::string& struct_name)
{
    const picojson::array elem_arr = Helper::parse_array(req.body());

    QVector<T> ins_vect, upd_vect;
    std::vector<uint32_t> del_vect;

    const Scheme_Info scheme = Scheme::get_info(req);
    uint32_t scheme_id = scheme.extending_scheme_ids().empty() ? scheme.id() : *scheme.extending_scheme_ids().cbegin();

    for (const picojson::value& elem_val: elem_arr)
    {
        if (!elem_val.is<picojson::object>())
            throw std::runtime_error("Is not an object");
        const picojson::object& elem_obj = elem_val.get<picojson::object>();
        if (elem_obj.size() == 1)
        {
            uint32_t elem_id = elem_obj.at("id").get<int64_t>();
            if (!elem_id)
                throw std::runtime_error("Attempt to delete unknown element");
            del_vect.push_back(std::move(elem_id));
        }
        else
        {
            T elem = obj_from_pico<T>(elem_obj);
            elem.set_scheme_id(scheme_id);
            (elem.id() ? upd_vect : ins_vect).push_back(std::move(elem));
        }
    }

    if (!del_vect.empty())
        Auth_Middleware::check_permission("delete_" + struct_name);
    if (!upd_vect.empty())
        Auth_Middleware::check_permission("change_" + struct_name);
    if (!ins_vect.empty())
        Auth_Middleware::check_permission("add_" + struct_name);

    picojson::object json;
    picojson::array ins_json_list;

    Base& db = Base::get_thread_local_instance();
    const Table table = db_table<T>();

    db.database().transaction();

    try
    {
        int64_t deleted = del_elements<T>(scheme, del_vect);
        json.emplace("deleted", picojson::value{deleted});

        if (!ins_vect.empty())
            for (T& elem: ins_vect)
                ins_json_list.push_back(create_element_impl(table, elem));

        int64_t updated = 0;
        if (!upd_vect.empty())
        {
            QString where_suffix = " AND " + scheme.ids_to_sql();
            Table upd_table = table;
    //        if constexpr (DB::has_scheme_id<T>()) // has_scheme_id in plus/das/database_delete_info.h
            upd_table.field_names().removeAt(T::COL_scheme_id);
            upd_table.field_names().removeFirst(); // remove id

            for (const T& elem: upd_vect)
                if (update_element_impl(upd_table, elem, where_suffix))
                    ++updated;
        }
        json.emplace("updated", picojson::value{updated});
    }
    catch (...)
    {
        db.database().rollback();
        throw;
    }

    db.database().commit();

    json.emplace("result", true);
    json.emplace("inserted", std::move(ins_json_list));

    res.set_header("Content-Type", "application/json");
    res << picojson::value{json}.serialize();
}

QString get_element_id_sql(const served::request &req)
{
    return "id=" + QString::number(Helper::get_element_id(req));
}

template<typename T>
void get_element(served::response &res, const served::request &req, const std::string& struct_name)
{
    picojson::array json = get_elements<T>(req, struct_name, get_element_id_sql(req));
    if (json.empty())
        throw served::request_error(served::status_4XX::NOT_FOUND, "Unknown element id");

    res.set_header("Content-Type", "application/json");
    res << picojson::value{json.front()}.serialize();
}

template<typename T>
void del_element(served::response &res, const served::request &req, const std::string& struct_name)
{
    uint32_t elem_id = Helper::get_element_id(req);
    Auth_Middleware::check_permission("delete_" + struct_name);

    const Scheme_Info scheme = Scheme::get_info(req);

    int deleted = del_elements<T>(scheme, {elem_id});
    if (deleted == 0)
        throw served::request_error(served::status_4XX::NOT_FOUND, "Unknown element id");

    Q_UNUSED(res);
}

template<typename T>
void create_element(served::response &res, const served::request &req, const std::string& struct_name)
{
    const picojson::object elem_obj = Helper::parse_object(req.body());
    T elem = obj_from_pico<T>(elem_obj);

    Auth_Middleware::check_permission("add_" + struct_name);

    const Scheme_Info scheme = Scheme::get_info(req);
    uint32_t scheme_id = scheme.extending_scheme_ids().empty() ? scheme.id() : *scheme.extending_scheme_ids().cbegin();

    elem.set_id(0);
    elem.set_scheme_id(scheme_id);

    picojson::value elem_val = create_element_impl(db_table<T>(), elem);

    res.set_header("Content-Type", "application/json");
    res << elem_val.serialize();
}

template<typename T>
void update_element(served::response &res, const served::request &req, const std::string& struct_name)
{
    const picojson::object elem_obj = Helper::parse_object(req.body());
    T elem = obj_from_pico<T>(elem_obj);

    Auth_Middleware::check_permission("change_" + struct_name);

    const Scheme_Info scheme = Scheme::get_info(req);

    QString where_suffix = " AND " + scheme.ids_to_sql();
    Table table = db_table<T>();
//    if constexpr (DB::has_scheme_id<T>()) // has_scheme_id in plus/das/database_delete_info.h
    table.field_names().removeAt(T::COL_scheme_id);
    table.field_names().removeFirst(); // remove id

    update_element_impl(table, elem, where_suffix);
    Q_UNUSED(res);
}

template<typename T>
std::string get_struct_name()
{
    QString name = T::table_name();
    if (is_table_use_common_prefix<T>())
        name = name.right(name.size() - Table::common_prefix().size());
    return name.toStdString();
}

template<typename T>
void add_resource_handler(served::multiplexer &mux, const std::string& struct_url)
{
    using Handler = Resource_Handler<std::string>;
    const std::string name = get_struct_name<T>();
    mux.handle(struct_url + name + "/{elem_id:[0-9]+}/")
            .get(Handler{get_element<T>, name})
            .del(Handler{del_element<T>, name});
    mux.handle(struct_url + name + '/')
            .get(Handler{get_element_list<T>, name})
            .post(Handler{create_element<T>, name})
            .put(Handler{update_element<T>, name})
            .method(served::PATCH, Handler{modify_element_list<T>, name});
}

Scheme_Structure::Scheme_Structure(served::multiplexer &mux, const std::string &scheme_path)
{
    const std::string struct_url = scheme_path + "/structure/";

    add_resource_handler<Device>(mux, struct_url);
    add_resource_handler<DB::Plugin_Type>(mux, struct_url);
    add_resource_handler<DB::Device_Item>(mux, struct_url);
    add_resource_handler<DB::Device_Item_Type>(mux, struct_url);
    add_resource_handler<DB::Save_Timer>(mux, struct_url);
    add_resource_handler<Section>(mux, struct_url);
    add_resource_handler<DB::Device_Item_Group>(mux, struct_url);
    add_resource_handler<DB::DIG_Type>(mux, struct_url);
    add_resource_handler<DB::DIG_Mode_Type>(mux, struct_url);
    add_resource_handler<DB::DIG_Param_Type>(mux, struct_url);
    add_resource_handler<DB::DIG_Status_Type>(mux, struct_url);
    add_resource_handler<DB::DIG_Status_Category>(mux, struct_url);
    add_resource_handler<DB::DIG_Param>(mux, struct_url);
    add_resource_handler<DB::Sign_Type>(mux, struct_url);
    add_resource_handler<DB::Code_Item>(mux, struct_url);
    add_resource_handler<DB::Translation>(mux, struct_url);
    add_resource_handler<DB::Value_View>(mux, struct_url);
}

} // namespace Rest
} // namespace Das
