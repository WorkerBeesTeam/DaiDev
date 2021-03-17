
#include <Helpz/db_builder.h>

#include <Das/db/user.h>
#include <plus/das/database.h>

#include "json_helper.h"
#include "rest_helper.h"
#include "auth_middleware.h"

#include "json_helper.h"
#include "rest_auth.h"

namespace Das {
namespace Rest {

using namespace Helpz::DB;

// ----------------------------------------

/*static*/ IP_Blocker Auth::_blocker;

/*static*/ std::string Auth::auth_token_path() { return "/auth/token/"; }
/*static*/ std::string Auth::auth_captcha_path() { return "/auth/captcha/"; }

/*static*/ std::vector<std::string> Auth::paths()
{
    return { Auth::auth_token_path(),
             Auth::auth_captcha_path() };
}

Auth::Auth(served::multiplexer &mux)
{
    const std::string auth_token_path = Auth::auth_token_path();
    const std::string elem_path = auth_token_path + "{elem_id:[0-9]+}/";
    mux.handle(Auth::auth_captcha_path())
            .head(Resource_Handler{auth_captcha})
            .get(Resource_Handler{auth_captcha});
    mux.handle(auth_token_path + "refresh/")
            .post(Resource_Handler{auth_token_refresh});
    mux.handle(auth_token_path)
            .post(Resource_Handler{auth_token});
}

void Auth::auth_captcha(served::response &res, const served::request &req)
{
    const std::string ip = req.header("X-Real-IP");
    if (!_blocker(ip))
        throw served::request_error(served::status_4XX::NOT_ACCEPTABLE, "No captcha");

    if (req.method() == served::GET)
    {
        std::string captcha_id;
        res << _blocker.get_captcha(ip, captcha_id);
        res.set_header("Content-Type", "image/jpeg");
        res.set_header("Set-Cookie", "captchaid=" + captcha_id);
    }
}

void Auth::auth_token(served::response &res, const served::request &req)
{
    const std::string ip = req.header("X-Real-IP");

    try {
        const picojson::object obj = Helper::parse_object(req.body());

        if (_blocker(ip))
        {
            const std::string captcha_id = Helper::get_cookie(req, "captchaid");
            const std::string& captcha_value = obj.at("captcha").get<std::string>();
            if (!_blocker.check_captcha(ip, captcha_id, captcha_value))
                throw served::request_error(served::status_4XX::BAD_REQUEST, "Bad request: Captcha");
            res.set_header("Set-Cookie", "captchaid=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT");
        }

        const std::string& username = obj.at("username").get<std::string>();
        const std::string& password = obj.at("password").get<std::string>();

        if (username.empty() || username.size() > 64
            || password.empty() || password.size() > 4096)
            throw served::request_error(served::status_4XX::BAD_REQUEST, "Bad request: Unknown username or password");

        gen_auth_token_response(res, "WHERE username=?", {QString::fromStdString(username)}, password);
    }
    catch (...) {
        _blocker << ip;

        throw;
    }
}

void Auth::auth_token_refresh(served::response &res, const served::request &/*req*/)
{
    uint32_t user_id = Auth_Middleware::get_thread_local_user().id_;
    gen_auth_token_response(res, "WHERE id=?", {user_id});
}

void Auth::gen_auth_token_response(served::response &res, QString sql, const QVariantList& values,
                                   const std::string& password)
{
    Table table = db_table<DB::User>();
    Base& db = Base::get_thread_local_instance();
    QSqlQuery query = db.select(table, sql, values);
    if (!query.next())
        throw served::request_error(served::status_4XX::BAD_REQUEST, "Bad request: Unknown user");

    DB::User user = db_build<DB::User>(query);

    if (!password.empty() && !DB::Helper::compare_passhash(password, user.password().toStdString()))
        throw served::request_error(served::status_4XX::BAD_REQUEST, "Bad request: Unknown user.");

    picojson::object json = obj_to_pico(user, table.field_names());
    json.erase("password");

    std::string token = Auth_Middleware::create_token(user.id(), Auth_Middleware::get_thread_local_user()._session_id);
    json.emplace("token", std::move(token));

    sql = R"sql(
(SELECT p.codename FROM das_user u
RIGHT JOIN das_user_user_permissions up ON up.user_id = u.id
LEFT JOIN auth_permission p ON p.id = up.permission_id
WHERE u.id = ?
)UNION(
SELECT p.codename FROM das_user u
LEFT JOIN das_user_groups ug ON ug.user_id = u.id
RIGHT JOIN auth_group_permissions gp ON gp.group_id = ug.group_id
LEFT JOIN auth_permission p ON p.id = gp.permission_id
WHERE u.id = ?))sql";

    query = db.exec(sql, {user.id(), user.id()});

    picojson::array perms;
    while (query.next())
        perms.emplace_back(query.value(0).toString().toStdString());

    json.emplace("permissions", std::move(perms)); // TODO: use only front needed permissions

    res.set_header("Content-Type", "application/json");
    res << picojson::value{std::move(json)}.serialize();
}

} // namespace Rest
} // namespace Das
