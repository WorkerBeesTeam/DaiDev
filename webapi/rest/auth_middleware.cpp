#include <iostream>

#include <served/request_error.hpp>

#include <plus/das/jwt_helper.h>
#include <plus/das/database.h>

#include <Helpz/db_base.h>

#include "rest_helper.h"
#include "auth_middleware.h"

namespace Das {
namespace Rest {

using namespace Helpz::DB;

thread_local User thread_local_user;

/*static*/ const User& Auth_Middleware::get_thread_local_user() { return thread_local_user; }

void Auth_Middleware::check_permission(const std::string &permission)
{
    const uint32_t user_id = get_thread_local_user().id_;
    if (!DB::Helper::check_permission(user_id, permission))
        throw served::request_error(served::status_4XX::FORBIDDEN, "You don't have permission for this: " + permission);
}

bool Auth_Middleware::has_permission(const std::string &permission)
{
    try {
        check_permission(permission);
    } catch (...) {
        return false;
    }
    return true;
}

Auth_Middleware::Auth_Middleware(std::shared_ptr<JWT_Helper> jwt_helper, const std::vector<std::string>& exclude_path) :
    exclude_path_vect_(exclude_path), jwt_helper_(jwt_helper)
{
}

void Auth_Middleware::operator ()(served::response&, const served::request& req)
{
    thread_local_user.clear();

//    std::cout << served::method_to_string(req.method()) << " Auth_Middleware: " << req.url().URI() << std::endl;
    const std::string req_path = req.url().path();
    if (is_exclude(req_path))
        return;

    check_token(req);
    // Authorization: JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImRldiIsImV4cCI6MTU2OTYyNzMzNSwidXNlcl9pZCI6MjcsImVtYWlsIjoiIiwidGVhbXMiOls5XSwib3JpZ19pYXQiOjE1Njk0Njk4MDZ9.4YqIbAnxIALYdB0Knw1cajsxmgv6BnzYgqDO0ck8oxg
}

bool Auth_Middleware::is_exclude(const std::string &url_path)
{
    for (const std::string& path: exclude_path_vect_)
        if (path == url_path)
            return true;
    return false;
}

void Auth_Middleware::check_token(const served::request &req)
{
    std::string token = req.header("Authorization");
    if (token.size() <= 4)
        throw served::request_error(served::status_4XX::BAD_REQUEST, "Token is too small");

    token.replace(0, 4, std::string());

    try
    {
        const std::string json_raw = jwt_helper_->decode_and_verify(token);
        const picojson::object obj = Helper::parse_object(json_raw);
        thread_local_user.id_ = obj.at("user_id").get<int64_t>();

        const picojson::array& scheme_groups = obj.at("groups").get<picojson::array>();
        for (const picojson::value& scheme_group_id: scheme_groups)
            thread_local_user.scheme_group_set_.insert(scheme_group_id.get<int64_t>());
    }
    catch(const std::exception& e)
    {
        std::cerr << "JWT Exception: " << e.what() << " token: " << token << std::endl;
        throw served::request_error(served::status_4XX::UNAUTHORIZED, e.what());
    }
}

} // namespace Rest
} // namespace Das
