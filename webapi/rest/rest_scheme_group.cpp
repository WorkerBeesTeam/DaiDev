
#define PICOJSON_USE_INT64
#include <picojson/picojson.h>

#include <Helpz/db_base.h>

#include <Das/db/scheme_group.h>
#include <plus/das/database_delete_info.h>

#include "json_helper.h"
#include "rest_helper.h"
#include "auth_middleware.h"
#include "rest_scheme_group.h"

namespace Das {
namespace Rest {

using namespace Helpz::DB;

Scheme_Group::Scheme_Group(served::multiplexer &mux)
{
    const std::string scheme_group_path = "/scheme_group/";
    const std::string elem_path = scheme_group_path + "{elem_id:[0-9]+}/";
    mux.handle(elem_path + "scheme/{sg_scheme_id:[0-9]+}/")
            .post(Resource_Handler{add_scheme})
            .del(Resource_Handler{del_scheme});
    mux.handle(elem_path + "scheme/")
            .get(Resource_Handler{get_schemes});
    mux.handle(elem_path + "user/{sg_user_id:[0-9]+}/")
            .post(Resource_Handler{add_user})
            .del(Resource_Handler{del_user});
    mux.handle(elem_path + "user/")
            .get(Resource_Handler{get_users});
    mux.handle(elem_path)
            .get(Resource_Handler{get_element})
            .del(Resource_Handler{del_element});
    mux.handle(scheme_group_path)
            .get(Resource_Handler{get_element_list})
            .post(Resource_Handler{create_element})
            .put(Resource_Handler{update_element});
}

/*static*/ picojson::array Scheme_Group::get_list(uint32_t scheme_id, uint32_t user_id, uint32_t scheme_group_id)
{
    uint32_t req_user_id = Auth_Middleware::get_thread_local_user().id_;

    Auth_Middleware::check_permission("view_scheme_group");
    bool see_all = Auth_Middleware::has_permission("add_scheme_group");
    if (!see_all)
    {
        if (user_id && user_id != req_user_id)
            throw served::request_error(served::status_4XX::FORBIDDEN,
                                        "You hasn't permissions for see scheme groups of another user.");
        user_id = req_user_id;
    }

    QVariantList values;
    QString sql, where;

    if (user_id)
    {
        sql += "LEFT JOIN das_scheme_group_user sgu ON sgu.group_id = sg.id ";
        where += "sgu.user_id = ?";
        values.push_back(user_id);
    }

    if (scheme_id)
    {
        sql += "LEFT JOIN das_scheme_groups sgs ON sgs.scheme_group_id = sg.id ";
        if (user_id)
            where += " AND ";
        where += "sgs.scheme_id = ?";
        values.push_back(scheme_id);
    }

    if (scheme_group_id)
    {
        if (!where.isEmpty())
            where += " AND ";
        where += "sg.id = ?";
        values.push_back(scheme_group_id);
    }

    sql += "WHERE " + where;
    sql += " GROUP BY sg.id";
    return gen_json_array<DB::Scheme_Group>(sql, values);
}

/*static*/ void Scheme_Group::get_element_list(served::response &res, const served::request &req)
{
    uint32_t scheme_id = stoa_or(req.query["scheme_id"]);
    uint32_t user_id = stoa_or(req.query["user_id"]);

    picojson::array json = get_list(scheme_id, user_id);
    res.set_header("Content-Type", "application/json");
    res << picojson::value{std::move(json)}.serialize();
}

/*static*/ void Scheme_Group::create_element(served::response &res, const served::request &req)
{
    using T = DB::Scheme_Group;
    const picojson::object elem_obj = Helper::parse_object(req.body());
    T elem = obj_from_pico<T>(elem_obj);

    Auth_Middleware::check_permission("add_scheme_group");

    Table table = db_table<T>();

    Base& db = Base::get_thread_local_instance();

    QVariant id;
    const QVariantList values = T::to_variantlist(elem);
    const QString sql = db.insert_query(table, values.size());
    const QSqlQuery q = db.exec(sql, values, &id);
    if (!q.isActive())
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());

    elem.set_id(id.toUInt());
    picojson::value elem_val{obj_to_pico(elem, table.field_names())};

    res.set_header("Content-Type", "application/json");
    res << elem_val.serialize();
}

/*static*/ void Scheme_Group::update_element(served::response &res, const served::request &req)
{
    using T = DB::Scheme_Group;
    const picojson::object elem_obj = Helper::parse_object(req.body());
    T elem = obj_from_pico<T>(elem_obj);

    Auth_Middleware::check_permission("change_scheme_group");

    Table table = db_table<T>();
    table.field_names().removeFirst(); // remove id

    QVariantList values = T::to_variantlist(elem);
    values.removeFirst(); // remove id

    Base& db = Base::get_thread_local_instance();
    const QSqlQuery q = db.update(table, values, "id = " + QString::number(elem.id()));
    if (!q.isActive())
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());

    res.set_header("Content-Type", "application/json");
    res << req.body();
}

/*static*/ void Scheme_Group::get_element(served::response &res, const served::request &req)
{
    uint32_t elem_id = Helper::get_element_id(req);
    picojson::array json = get_list(0, 0, elem_id);
    if (json.empty())
        throw served::request_error(served::status_4XX::NOT_FOUND, "Unknown element id or you havn't permissions.");

    res.set_header("Content-Type", "application/json");
    res << json.front().serialize();
}

/*static*/ void Scheme_Group::del_element(served::response &res, const served::request &req)
{
    uint32_t elem_id = Helper::get_element_id(req);
    Auth_Middleware::check_permission("delete_scheme_group");

    Base& db = Base::get_thread_local_instance();
    if (!DB::db_delete_rows<DB::Scheme_Group>(db, {elem_id}, {}))
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());

    Q_UNUSED(res);
}

void Scheme_Group::add_scheme(served::response &res, const served::request &req)
{
    using T = DB::Scheme_Group_Scheme;
    T elem(0, Helper::get_element_id(req), Helper::get_element_id(req, "sg_scheme_id"));
    Auth_Middleware::check_permission("add_scheme_group");

    Table table = db_table<T>();
    Base& db = Base::get_thread_local_instance();

    QVariant id;
    const QVariantList values = T::to_variantlist(elem);
    const QString sql = db.insert_query(table, values.size());
    const QSqlQuery q = db.exec(sql, values, &id);
    if (!q.isActive())
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());

    elem.set_id(id.toUInt());

    picojson::value elem_val{obj_to_pico(elem, table.field_names())};

    res.set_header("Content-Type", "application/json");
    res << elem_val.serialize();
}

void Scheme_Group::del_scheme(served::response &res, const served::request &req)
{
    using T = DB::Scheme_Group_Scheme;
    uint32_t scheme_group_id = Helper::get_element_id(req);
    uint32_t scheme_id = Helper::get_element_id(req, "sg_scheme_id");
    Auth_Middleware::check_permission("delete_scheme_group");

    Base& db = Base::get_thread_local_instance();
    const QSqlQuery q = db.del(db_table_name<T>(), "scheme_group_id = ? AND scheme_id = ?", {scheme_group_id, scheme_id});
    if (!q.isActive())
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());
    Q_UNUSED(res);
}

void Scheme_Group::get_schemes(served::response &res, const served::request &req)
{
    using T = DB::Scheme_Group_Scheme;
    uint32_t scheme_group_id = Helper::get_element_id(req);
    Auth_Middleware::check_permission("view_scheme_group");

    const QString sql = "LEFT JOIN das_scheme_groups sgs ON sgs.scheme_id = s.id "
                        "WHERE sgs.scheme_group_id = ?";

    Table table{"das_scheme", "s", {"id", "name", "title"}};

    Base& db = Base::get_thread_local_instance();
    QSqlQuery q = db.select(table, sql, {scheme_group_id});
    if (!q.isActive())
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());

    picojson::array json;
    while (q.next())
    {
        picojson::object obj = gen_json_object<T>(q, table.field_names());
        json.emplace_back(std::move(obj));
    }

    res.set_header("Content-Type", "application/json");
    res << picojson::value{std::move(json)}.serialize();
}

void Scheme_Group::add_user(served::response &res, const served::request &req)
{
    using T = DB::Scheme_Group_User;
    T elem(0, Helper::get_element_id(req), Helper::get_element_id(req, "sg_user_id"));
    Auth_Middleware::check_permission("add_scheme_group_user");

    Table table = db_table<T>();
    Base& db = Base::get_thread_local_instance();

    QVariant id;
    const QVariantList values = T::to_variantlist(elem);
    const QString sql = db.insert_query(table, values.size());
    const QSqlQuery q = db.exec(sql, values, &id);
    if (!q.isActive())
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());

    elem.set_id(id.toUInt());

    picojson::value elem_val{obj_to_pico(elem, table.field_names())};

    res.set_header("Content-Type", "application/json");
    res << elem_val.serialize();
}

void Scheme_Group::del_user(served::response &res, const served::request &req)
{
    using T = DB::Scheme_Group_User;
    uint32_t scheme_group_id = Helper::get_element_id(req);
    uint32_t user_id = Helper::get_element_id(req, "sg_user_id");
    Auth_Middleware::check_permission("delete_scheme_group_user");

    Base& db = Base::get_thread_local_instance();
    const QSqlQuery q = db.del(db_table_name<T>(), "group_id = ? AND user_id = ?", {scheme_group_id, user_id});
    if (!q.isActive())
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());
    Q_UNUSED(res);
}

void Scheme_Group::get_users(served::response &res, const served::request &req)
{
    using T = DB::Scheme_Group_User;
    uint32_t scheme_group_id = Helper::get_element_id(req);
    Auth_Middleware::check_permission("view_scheme_group_user");

    const QString sql = R"sql(
SELECT u.id, u.first_name, u.last_name, u.username, IF(up.id IS NULL AND t1.user_id IS NULL, 'user', 'admin') as role
FROM das_user u
LEFT JOIN das_scheme_group_user sgu ON sgu.user_id = u.id
LEFT JOIN das_user_user_permissions up ON up.user_id = u.id AND up.permission_id IN (
    SELECT id FROM auth_permission WHERE codename = 'add_scheme_group'
)
LEFT JOIN (
    SELECT ug.user_id FROM das_user_groups ug
    LEFT JOIN auth_group_permissions gp ON gp.group_id = ug.group_id
    LEFT JOIN auth_permission p ON p.id = gp.permission_id
    WHERE p.codename = 'add_scheme_group'
    GROUP BY ug.user_id
) t1 ON t1.user_id = u.id
WHERE sgu.group_id = ?)sql";

    Base& db = Base::get_thread_local_instance();
    QSqlQuery q = db.exec(sql, {scheme_group_id});
    if (!q.isActive())
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, db.last_error().toStdString());

    picojson::array json;
    while (q.next())
    {
        picojson::object obj;
        obj.emplace("id", static_cast<int64_t>(q.value(0).toLongLong()));
        obj.emplace("first_name", q.value(1).toString().toStdString());
        obj.emplace("last_name", q.value(2).toString().toStdString());
        obj.emplace("username", q.value(3).toString().toStdString());
        obj.emplace("role", q.value(4).toString().toStdString());
        json.emplace_back(std::move(obj));
    }

    res.set_header("Content-Type", "application/json");
    res << picojson::value{std::move(json)}.serialize();
}

} // namespace Rest
} // namespace Das
