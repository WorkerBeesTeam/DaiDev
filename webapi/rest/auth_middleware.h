#ifndef DAS_REST_AUTH_MIDDLEWARE_H
#define DAS_REST_AUTH_MIDDLEWARE_H

#include <vector>
#include <set>

#include <served/request.hpp>
#include <served/response.hpp>

namespace Das {

class JWT_Helper;

namespace Rest {

struct Auth_User
{
    uint32_t id_;
    std::set<uint32_t> scheme_group_set_;

    void clear()
    {
        id_ = 0;
        scheme_group_set_.clear();
    }
};

class Auth_Middleware
{
public:
    static const Auth_User& get_thread_local_user();

    static void check_permission(const std::string& permission);
    static bool has_permission(const std::string& permission);

    Auth_Middleware(std::shared_ptr<JWT_Helper> jwt_helper, const std::vector<std::string>& exclude_path = {});
    void operator ()(served::response &, const served::request & req);
private:
    bool is_exclude(const std::string& url_path);
    void check_token(const served::request& req);

    std::vector<std::string> exclude_path_vect_;
    std::shared_ptr<JWT_Helper> jwt_helper_;
};

} // namespace Rest
} // namespace Das

#endif // DAS_REST_AUTH_MIDDLEWARE_H
