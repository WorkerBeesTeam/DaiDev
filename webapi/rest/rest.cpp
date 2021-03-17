#include <iostream>

#include <served/served.hpp>
#include <served/status.hpp>
#include <served/request_error.hpp>

#include <Das/db/auth_group.h>
#include <Das/log/log_base_item.h>

#include "../telegrambot/db/tg_auth.h"
#include "../telegrambot/db/tg_user.h"

#include "dbus_object.h"

#include "rest_helper.h"
#include "json_helper.h"
#include "multipart_form_data_parser.h"
#include "csrf_middleware.h"
#include "auth_middleware.h"
#include "rest_auth.h"
#include "rest_scheme_group.h"
#include "rest_scheme.h"
#include "rest_user.h"
#include "rest.h"

namespace Das {
namespace Rest {

Q_LOGGING_CATEGORY(Rest_Log, "rest")

using namespace Helpz::DB;

Restful::Restful(DBus::Interface* dbus_iface, std::shared_ptr<JWT_Helper> jwt_helper, const Config &config) :
    server_(nullptr),
    thread_(&Restful::run, this, dbus_iface, std::move(jwt_helper), config)
{
}

Restful::~Restful()
{
    stop();
    join();
}

void Restful::stop()
{
    if (server_)
        server_->stop();
}

void Restful::join()
{
    if (thread_.joinable())
        thread_.join();
}

void Restful::run(DBus::Interface* dbus_iface, std::shared_ptr<JWT_Helper> jwt_helper, const Config &config)
{
    try
    {
        served::multiplexer mux;

        // register one or more handlers
        const std::string token_auth {"/token/auth"};
        auto auth = std::make_shared<Auth>(mux);
        auto scheme_group = std::make_shared<Scheme_Group>(mux);
        auto scheme = std::make_shared<Scheme>(mux, dbus_iface);
        auto user = std::make_shared<User>(mux);

        mux.handle("auth_group").get([](served::response &res, const served::request &req)
        {
            Auth_Middleware::check_permission("view_group");
            res.set_header("Content-Type", "application/json");
            res << gen_json_list<DB::Auth_Group>();
        });

        mux.handle("bot/auth").post([](served::response &res, const served::request &req)
        {
            const picojson::object obj = Helper::parse_object(req.body());
            const std::string& token = obj.at("token").get<std::string>();

            const qint64 now = DB::Log_Base_Item::current_timestamp();
            const QString where = "WHERE expired > " + QString::number(now) + " AND token = ?";

            Base& db = Base::get_thread_local_instance();
            const QVector<DB::Tg_Auth> auth_vect = db_build_list<DB::Tg_Auth>(db, where, {QString::fromStdString(token)});
            if (auth_vect.size() != 1)
                throw served::request_error(served::status_4XX::BAD_REQUEST, "Bad request: Unknown token");

            const DB::Tg_Auth& auth = auth_vect.front();

            Table table = db_table<DB::Tg_User>();
            table.field_names() = QStringList{table.field_names().at(DB::Tg_User::COL_user_id)};
            const QVariantList values{{Auth_Middleware::get_thread_local_user().id_}};
            bool ok = db.update(table, values, "id=" + QString::number(auth.tg_user_id())).numRowsAffected();
            if (!ok)
                throw served::request_error(served::status_4XX::BAD_REQUEST, "Bad request: Unknown user");

            db.del(db_table_name<DB::Tg_Auth>(), "tg_user_id=" + QString::number(auth.tg_user_id()));

            QMetaObject::invokeMethod(Server::WebApi::Dbus_Object::instance(), "tg_user_authorized", Qt::QueuedConnection, Q_ARG(qint64, auth.tg_user_id()));

            res.set_status(204);
        });

        mux.handle("write_item_file").put([](served::response &res, const served::request &req)
        {
            Multipart_Form_Data_Parser parser(req);
//            if (parser.parse())
            {

            }
            qCDebug(Rest_Log) << QByteArray::fromStdString(req.body());
            res.set_status(204);
        });

        // register middleware / plugin
        mux.use_before(CSRF_Middleware());
        mux.use_before(Auth_Middleware(std::move(jwt_helper), config._token_timeout, Auth::paths()));

        served::net::server server{config.address_, config.port_, mux};
        server_ = &server;

        std::cout << "Restful server start: http://" << config.address_ << ':' << config.port_ << '/' << config.base_path_ << std::endl;

        server.run(config.thread_count_);
    }
    catch(const std::exception& e)
    {
        qCCritical(Rest_Log) << "Failure:" << e.what();
    }
    catch(...)
    {
        qCCritical(Rest_Log) << "Served unknown exception:" << strerror(errno);
    }

    server_ = nullptr;
//    const QByteArray token("MZ57f6dHSAruWf4r6errrLLLodZiZ2dpPSflFHUq10aKDfEliNBZyE8JPqyuYiAL");
//    const QByteArray token_request("MZ57f6dHSAruWf4r6errrLLLodZiZ2dpPSflFHUq10aKDfEliNBZyE8JPqyuYiAL");
    //    std::cerr << "Token is " << std::boolalpha << check_csrf_token(token, token_request) << std::endl;
}

} // namespace Rest
} // namespace Das
