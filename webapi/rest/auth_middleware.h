#ifndef DAS_REST_AUTH_MIDDLEWARE_H
#define DAS_REST_AUTH_MIDDLEWARE_H

#include <vector>
#include <set>
#include <chrono>

#include <served/request.hpp>
#include <served/response.hpp>

namespace Das {

class JWT_Helper;

namespace Rest {

struct Auth_User
{
    uint32_t id_;
    std::string _session_id;

    void clear()
    {
        id_ = 0;
        _session_id.clear();
    }
};

class Auth_Middleware
{
    static Auth_Middleware* _obj;
public:
    static const Auth_User& get_thread_local_user();

    static void check_permission(const std::string& permission);
    static bool has_permission(const std::string& permission);

    Auth_Middleware(std::shared_ptr<JWT_Helper> jwt_helper,
                    std::chrono::seconds token_timeout,
                    const std::vector<std::string>& exclude_path = {});
    void operator ()(served::response &, const served::request & req);

    static std::string create_token(uint32_t user_id, std::string session_id = {});
private:
    bool is_exclude(const std::string& url_path);
    void check_token(const served::request& req);

    std::vector<std::string> exclude_path_vect_;
    std::shared_ptr<JWT_Helper> jwt_helper_;
    std::chrono::seconds _token_timeout;
};

} // namespace Rest
} // namespace Das

#endif // DAS_REST_AUTH_MIDDLEWARE_H
