#include <served/status.hpp>
#include <served/request_error.hpp>

#include <QSqlError>
#include <QUuid>

#include <fmt/ranges.h>

#include <Helpz/db_base.h>
#include <Helpz/db_builder.h>

//#include <Das/section.h>
#include <Das/db/scheme.h>
#include <Das/db/dig_status_type.h>
#include <Das/db/disabled_status.h>
#include <Das/db/help.h>
//#include <Das/db/dig_status.h>
//#include <Das/db/device_item_value.h>
//#include <Das/db/chart.h>

#include <dbus/dbus_interface.h>

#include "rest_helper.h"
#include "json_helper.h"
#include "filter.h"
#include "csrf_middleware.h"
#include "auth_middleware.h"
#include "scheme_copier.h"
#include "rest_chart.h"
#include "rest_chart_data_controller.h"
#include "rest_scheme_structure.h"
#include "rest_scheme.h"

namespace Das {
namespace Rest {

using namespace Helpz::DB;

const char *get_scheme_base() { return "scheme"; }
std::string get_scheme_path_base() { return '/' + std::string(get_scheme_base()) + '/'; }

std::string get_scheme_path()
{
    return get_scheme_path_base() + '{' + get_scheme_base() + "_id:[0-9]+}";
}

Scheme::Scheme(served::multiplexer& mux, DBus::Interface* dbus_iface) :
    dbus_iface_(dbus_iface)
{
    const std::string scheme_path = get_scheme_path();
    structure_ = std::make_shared<Scheme_Structure>(mux, scheme_path);
    chart_ = std::make_shared<Chart>(mux, scheme_path);
    chart_data_ = std::make_shared<Chart_Data_Controller>(mux, scheme_path);

    mux.handle(scheme_path + "/dig_status").get([this](served::response& res, const served::request& req) { get_dig_status(res, req); });
    mux.handle(scheme_path + "/dig_status_type").get([this](served::response& res, const served::request& req) { get_dig_status_type(res, req); });
    mux.handle(scheme_path + "/device_item_value").get([this](served::response& res, const served::request& req) { get_device_item_value(res, req); });
    mux.handle(scheme_path + "/disabled_status")
            .get([this](served::response& res, const served::request& req) { get_disabled_status(res, req); })
            .method(served::method::PATCH, [this](served::response& res, const served::request& req) { del_disabled_status(res, req); })
            .post([this](served::response& res, const served::request& req) { add_disabled_status(res, req); });

    mux.handle(scheme_path + "/help").get([](served::response &res, const served::request &req)
    {
        Auth_Middleware::check_permission("view_help");

        const Scheme_Info scheme = get_info(req);

        const QString sql = "WHERE scheme_id IS NULL OR %1 ORDER BY parent_id";

        res.set_header("Content-Type", "application/json");
        res << gen_json_list<DB::Help>(sql.arg(scheme.ids_to_sql()));
    });

    mux.handle(scheme_path + "/set_name/").post([this](served::response& res, const served::request& req) { set_name(res, req); });
    mux.handle(scheme_path + "/copy/").post([this](served::response& res, const served::request& req) { copy(res, req); });
    mux.handle(scheme_path).get([this](served::response& res, const served::request& req) { get(res, req); });
    mux.handle(get_scheme_path_base())
            .get([this](served::response& res, const served::request& req) { get_list(res, req); })
            .post([this](served::response& res, const served::request& req) { create(res, req); });
    // throw served::request_error(served::status_4XX::NOT_FOUND, "Scheme not found");
}

/*static*/ Scheme_Info Scheme::get_info(const served::request& req)
{
    const std::string url_path = req.url().path();
    const std::string scheme_path = get_scheme_path_base();
    // Check url_path is starts with /scheme/ and is have more text like /scheme/10/
    if (url_path.size() > scheme_path.size()
        && strncmp(scheme_path.c_str(), url_path.c_str(), scheme_path.size()) == 0)
    {
        const std::string param_name = get_scheme_base() + std::string("_id");
        const std::string param_data = req.params[param_name];
        if (!param_data.empty())
        {
            uint32_t scheme_id = std::atoi(param_data.c_str());
            return get_info(scheme_id);
        }
    }

    throw served::request_error(served::status_4XX::NOT_FOUND, "Scheme not found");
    return {};
}

/*static*/ Scheme_Info Scheme::get_info(uint32_t scheme_id)
{
    uint32_t user_id = Auth_Middleware::get_thread_local_user().id_;
    if (user_id != 0 && scheme_id != 0)
    {
        const QString sql =
                "SELECT s.id, s.parent_id FROM das_scheme s "
                "LEFT JOIN das_scheme_groups sg ON sg.scheme_id = s.id "
                "LEFT JOIN das_scheme_group_user sgu ON sgu.group_id = sg.scheme_group_id "
                "WHERE s.id = %1 AND sgu.user_id = %2";

        Base& db = Base::get_thread_local_instance();
        QSqlQuery q = db.exec(sql.arg(scheme_id).arg(user_id));
        if (q.next())
        {
            std::set<uint32_t> extending_ids;
            if (!q.isNull(1))
                extending_ids.insert(q.value(1).toUInt());
            return Scheme_Info{q.value(0).toUInt(), std::move(extending_ids)}; // TODO: get array from specific table for extending ids
        }
    }

    return {};
}

void Scheme::get_dig_status(served::response &res, const served::request &req)
{
    const Scheme_Info scheme = get_info(req);

    Scheme_Status scheme_status;
    QMetaObject::invokeMethod(dbus_iface_, "get_scheme_status", Qt::BlockingQueuedConnection,
        Q_RETURN_ARG(Scheme_Status, scheme_status),
        Q_ARG(uint32_t, scheme.id()));

    picojson::array json_array;

    if (!scheme_status.status_set_.empty())
    {
        QStringList status_column_names = DIG_Status::table_column_names();
        QString group_title;
        QString sql = "SELECT g.id, s.name, g.title, gt.title "
              "FROM das_device_item_group g "
              "LEFT JOIN das_section s ON s.id = g.section_id "
              "LEFT JOIN das_dig_type gt ON gt.id = g.type_id "
              "WHERE g." + scheme.ids_to_sql() + " AND g.id IN (";

        for (const DIG_Status& status: scheme_status.status_set_)
            sql += QString::number(status.group_id()) + ',';
        sql.replace(sql.size() - 1, 1, QChar(')'));

        std::map<uint32_t, QString> group_title_map;

        Base& db = Base::get_thread_local_instance();
        QSqlQuery q = db.exec(sql);
        while(q.next())
        {
            group_title = q.value(2).toString();
            if (group_title.isEmpty())
                group_title = q.value(3).toString();
            group_title.insert(0, q.value(1).toString() + ' ');
            group_title_map.emplace(q.value(0).toUInt(), group_title);
        }

        for (const DIG_Status& status: scheme_status.status_set_)
        {
            picojson::array args;
            QStringList args_list = status.args();
            for (const QString& arg: args_list)
                args.push_back(picojson::value{arg.toStdString()});

            picojson::object json_obj = obj_to_pico(status, status_column_names);
            json_obj.emplace("args", std::move(args));
            json_obj.emplace("title", group_title_map[status.group_id()].toStdString());
            json_array.push_back(picojson::value{std::move(json_obj)});
        }
    }

    picojson::object json;
    json.emplace("items", std::move(json_array));
    json.emplace("connection", static_cast<int64_t>(scheme_status.connection_state_));

    res.set_header("Content-Type", "application/json");
    res << picojson::value{std::move(json)}.serialize();
}

void Scheme::get_dig_status_type(served::response &res, const served::request &req)
{
    const Scheme_Info scheme = get_info(req);

    res.set_header("Content-Type", "application/json");
    res << gen_json_list<DIG_Status_Type>("WHERE " + scheme.ids_to_sql());
}

void Scheme::get_device_item_value(served::response &res, const served::request &req)
{
    const Scheme_Info scheme = get_info(req);

    QVector<Device_Item_Value> values;

    QMetaObject::invokeMethod(dbus_iface_, "get_device_item_values", Qt::BlockingQueuedConnection,
        Q_RETURN_ARG(QVector<Device_Item_Value>, values),
        Q_ARG(uint32_t, scheme.id()));

    picojson::array j_array;

    using T = Device_Item_Value;
    QStringList names = T::table_column_names();
    names[T::COL_item_id] = "id";
    names[T::COL_timestamp_msecs] = "ts";
    names[T::COL_raw_value] = "raw";

    for (const Device_Item_Value& value: values)
    {
        picojson::object obj = obj_to_pico(value, names);
        obj.emplace("id", static_cast<int64_t>(value.item_id()));
        obj.emplace("ts", static_cast<int64_t>(value.timestamp_msecs()));
        obj.emplace("user_id", static_cast<int64_t>(value.user_id()));
        obj.emplace("raw", pico_from_qvariant(value.raw_value()));
        obj.emplace("value", pico_from_qvariant(value.value()));

        if (value.is_big_value())
        {
            obj.emplace("raw_value", value.raw_value().toString().left(16).toStdString());
            obj.emplace("display", value.value().toString().left(16).toStdString());
        }
        else
        {
            obj.emplace("raw_value", pico_from_qvariant(value.raw_value()));
            obj.emplace("display", pico_from_qvariant(value.value()));
        }

        j_array.emplace_back(std::move(obj));
    }

    res.set_header("Content-Type", "application/json");
    res << picojson::value{std::move(j_array)}.serialize();
}

void Scheme::get_disabled_status(served::response &res, const served::request &req)
{
    Auth_Middleware::check_permission("view_disabled_status");

    const Scheme_Info scheme = get_info(req);

    uint32_t dig_id = stoa_or(req.query["dig_id"]);

    const QString sql = "WHERE %1 AND (dig_id IS NULL OR dig_id = %2)";

    res.set_header("Content-Type", "application/json");
    res << gen_json_list<DB::Disabled_Status>(sql.arg(scheme.ids_to_sql()).arg(dig_id));
}

void Scheme::del_disabled_status(served::response &res, const served::request &req)
{
    const picojson::array arr = Helper::parse_array(req.body());

    std::set<uint32_t> id_set;
    uint32_t id;
    auto checkAdd = [&id_set, &id](const picojson::value& value)
    {
        if (value.is<double>())
        {
            id = static_cast<uint32_t>(value.get<double>());
            if (id)
            {
                id_set.insert(id);
                return true;
            }
        }
        return false;
    };

    for (const picojson::value& value: arr)
    {
        if (!checkAdd(value) && value.is<picojson::object>())
        {
            const picojson::object& obj = value.get<picojson::object>();
            auto it = obj.find("id");
            if (it != obj.cend())
                checkAdd(it->second);
        }
    }

    if (id_set.empty())
        throw served::request_error(served::status_4XX::BAD_REQUEST, "Failed find item for delete");

    Auth_Middleware::check_permission("delete_disabled_status");
    const Scheme_Info scheme = get_info(req);

    QString where = "scheme_id=";
    where += QString::number(scheme.id());
    where += " AND ";
    where += get_db_field_in_sql("id", id_set);

    Base& db = Base::get_thread_local_instance();
    db.del(db_table_name<DB::Disabled_Status>(), where);

    res.set_status(204);
}

void Scheme::add_disabled_status(served::response &res, const served::request &req)
{
    const picojson::array arr = Helper::parse_array(req.body());

    Auth_Middleware::check_permission("add_disabled_status");
    const Scheme_Info scheme = get_info(req);

    QVariantList values, tmp_values;

    Table table = db_table<DB::Disabled_Status>();

    for (const picojson::value& value: arr)
    {
        DB::Disabled_Status item = obj_from_pico<DB::Disabled_Status>(value, table);
        item.set_scheme_id(scheme.id());

        tmp_values = DB::Disabled_Status::to_variantlist(item);
        tmp_values.removeFirst();
        values += tmp_values;
    }

    if (values.empty())
        throw served::request_error(served::status_4XX::BAD_REQUEST, "Failed find item for insert");

    table.field_names().removeFirst();
    QString sql = "INSERT INTO " + table.name() + '(' + table.field_names().join(',') + ") VALUES" +
            Base::get_q_array(table.field_names().size(), values.size() / table.field_names().size());

    Base& db = Base::get_thread_local_instance();
    db.exec(sql, values);

    res.set_status(204);
}

void Scheme::get(served::response &res, const served::request &req)
{
    res.set_header("Content-Type", "application/json");
    res << "{ \"content\": \"Hello, " << req.params["scheme_id"] << "!\" }\n";

    std::cerr << "get scheme" << std::endl;
}

void Scheme::get_list(served::response &res, const served::request &req)
{
    Filter::Result filter = get_filter_result<DB::Scheme>(req.query, false);

    const uint32_t user_id = Auth_Middleware::get_thread_local_user().id_;

    QString suffix =
            "LEFT JOIN das_scheme_groups sg ON sg.scheme_id = s.id "
            "LEFT JOIN das_scheme_group_user sgu ON sgu.group_id = sg.scheme_group_id "
            "WHERE sgu.user_id = ";

    suffix += QString::number(user_id);
    suffix += filter.suffix_;
    suffix += " GROUP BY s.id";

    res.set_header("Content-Type", "application/json");
    res << gen_json_list<DB::Scheme>(suffix, filter.values_);
}

void Scheme::create(served::response &res, const served::request &req)
{
    picojson::object obj = Helper::parse_object(req.body());

    auto s_groups_it = obj.find("scheme_groups");
    if (s_groups_it == obj.cend() || !s_groups_it->second.is<picojson::array>())
        throw served::request_error(served::status_4XX::BAD_REQUEST, "scheme_groups is required");

    const picojson::array& scheme_groups = s_groups_it->second.get<picojson::array>();
    if (scheme_groups.empty())
        throw served::request_error(served::status_4XX::BAD_REQUEST, "scheme_groups can't be empty");

    Auth_Middleware::check_permission("add_scheme");

    DB::Scheme scheme = from_json<DB::Scheme>(obj);
    scheme.set_last_usage(QDateTime::currentDateTimeUtc());
    scheme.set_version("");
    scheme.set_using_key(QUuid().toString(QUuid::Id128));

    const uint32_t user_id = Auth_Middleware::get_thread_local_user().id_;

    Base& db = Base::get_thread_local_instance();

    QString sql =
            "SELECT * FROM das_scheme_groups sg "
            "LEFT JOIN das_scheme_group_user sgu ON sgu.group_id = sg.scheme_group_id "
            "WHERE sgu.user_id = %1 AND sg.scheme_id = %2 "
            "LIMIT 1";

    if (scheme.parent_id())
    {
        auto q = db.exec(sql.arg(user_id).arg(scheme.parent_id()));
        if (!q.isActive() || !q.next())
            throw served::request_error(served::status_4XX::BAD_REQUEST, "Can't find scheme id: " + std::to_string(scheme.parent_id()));
    }
    else
    {
        // TODO: check can create scheme controller (parent scheme)
    }

    sql = "SELECT COUNT(*) FROM das_scheme_group_user sgu WHERE sgu.user_id = ";
    sql += QString::number(user_id);
    sql += " AND sgu.group_id IN (";

    for (const picojson::value& s_group: scheme_groups)
    {
        sql += QString::number(s_group.get<int64_t>());
        sql += ',';
    }
    sql.replace(sql.size()-1, 1, ')');

    QSqlQuery q = db.exec(sql);
    if (!q.isActive() || !q.next() || q.value(0).toUInt() == 0)
        throw served::request_error(served::status_4XX::BAD_REQUEST, "Can't find some scheme group");

    QVariant new_id;
    if (!db.insert(db_table<DB::Scheme>(), DB::Scheme::to_variantlist(scheme), &new_id))
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, "Can't create new scheme: " + scheme.name().toStdString());

    const QString new_id_str = new_id.toString();
    sql = "INSERT INTO das_scheme_groups(scheme_id, scheme_group_id) VALUES";
    for (const picojson::value& s_group: scheme_groups)
    {
        sql += '(';
        sql += new_id_str;
        sql += ',';
        sql += QString::number(s_group.get<int64_t>());
        sql += "),";
    }
    sql.replace(sql.size()-1, 1, ';');
    q = db.exec(sql);
    if (!q.isActive())
    {
        db.exec("DELETE FROM das_scheme_groups WHERE scheme_id = " + new_id_str);
        db.exec("DELETE FROM das_scheme WHERE id = " + new_id_str);
        throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, "Can't create new scheme: " + scheme.name().toStdString() + " failed add to groups");
    }

    obj["id"] = picojson::value(new_id.value<int64_t>());
    const picojson::value val{std::move(obj)};
    res << val.serialize();
    std::cerr << "Scheme::create: " << val.serialize() << std::endl;
}

void Scheme::set_name(served::response &res, const served::request &req)
{
    const picojson::object obj = Helper::parse_object(req.body());
    const Scheme_Info scheme = get_info(req);

    const std::string& scheme_name = obj.at("name").get<std::string>();
    std::cerr << "set_name: " << scheme_name << std::endl;

    const uint32_t user_id = Auth_Middleware::get_thread_local_user().id_;

    QMetaObject::invokeMethod(dbus_iface_, "set_scheme_name", Qt::QueuedConnection,
        Q_ARG(uint32_t, scheme.id()), Q_ARG(uint32_t, user_id), Q_ARG(QString, QString::fromStdString(scheme_name)));

    res << "{\"result\": true}\n";
}

void Scheme::copy(served::response &res, const served::request &req)
{
    const picojson::object obj = Helper::parse_object(req.body());

    const uint32_t dest_scheme_id = obj.at("scheme_id").get<int64_t>();
    const bool is_dry_run = obj.at("dry_run").get<bool>();

    const Scheme_Info scheme = Scheme::get_info(req);
    const Scheme_Info dest_scheme = Scheme::get_info(dest_scheme_id);
    if (!dest_scheme.id()
        || !scheme.extending_scheme_ids().empty()
        || !dest_scheme.extending_scheme_ids().empty())
    {
        const std::string error_msg = fmt::format("Not possible copy scheme {}{} to {}{}.",
                                                  scheme.id(), scheme.extending_scheme_ids(),
                                                  dest_scheme_id, dest_scheme.extending_scheme_ids());
        throw served::request_error(served::status_4XX::BAD_REQUEST, error_msg);
    }

    Auth_Middleware::check_permission("change_scheme");

    std::cout << "Copy " << scheme.id() << " to " << dest_scheme.id() << std::endl;

    Scheme_Copier copier(scheme.id(), dest_scheme.id(), is_dry_run);

    picojson::object data;

    auto get_counter_name = [](int index) -> std::string
    {
        using T = Scheme_Copier::Item::Counter_Type;
        switch (index) {
        case T::SCI_DELETED:        return "deleted";
        case T::SCI_DELETE_ERROR:   return "delete_error";
        case T::SCI_INSERTED:       return "inserted";
        case T::SCI_INSERT_ERROR:   return "insert_error";
        case T::SCI_UPDATED:        return "updated";
        case T::SCI_UPDATE_ERROR:   return "update_error";
        default:
            break;
        }
        return "unknown";
    };

    bool is_empty;
    int64_t counter;
    for (const std::pair<std::string, Scheme_Copier::Item>& item: copier.result_)
    {
        picojson::object data_item;

        is_empty = true;
        for (int i = 0; i < Scheme_Copier::Item::SCI_COUNT; ++i)
        {
            counter = item.second.counter_[i];

            if (!counter)
                continue;

            is_empty = false;

            data_item.emplace(get_counter_name(i), picojson::value(counter));
        }

        if (!is_empty)
            data.emplace(item.first, picojson::value(data_item));
    }

    picojson::object res_obj;
    res_obj.emplace("result", picojson::value(true));
    res_obj.emplace("data", picojson::value(std::move(data)));
    res << picojson::value(std::move(res_obj)).serialize();
}

} // namespace Rest
} // namespace Das
