
#include <botan/parsing.h>
#include <served/request_error.hpp>

#include "rest_helper.h"
#include "csrf_middleware.h"

#define CSRF_SECRET_LENGTH 32
#define CSRF_TOKEN_LENGTH 2 * CSRF_SECRET_LENGTH

namespace Das {
namespace Rest {

const std::string cookie_name{"csrftoken"};
const char header_name[] = "X-CSRFToken";
const char csrf_allowed_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

CSRF_Middleware::CSRF_Middleware()
{

}

void CSRF_Middleware::operator ()(served::response& res, const served::request& req)
{
    const std::string cookie_token = get_cookie_token(req);
    check_cookie_token(cookie_token, res);

    switch (req.method())
    {
    case served::method::POST:
    case served::method::PATCH:
    case served::method::PUT:
    case served::method::DELETE:
        if (!check_csrf_token(get_cookie_token(req), req.header(header_name)))
            throw served::request_error(served::status_4XX::FORBIDDEN, "Bad CSRF token");
        break;
    default: break;
    }
}

void CSRF_Middleware::check_cookie_token(const std::string& token, served::response& res)
{
    if (!is_valid_csrf_token(token))
    {
//        res.set_header("Set-Cookie", get_csrf_token());
        // TODO: set cookie token
    }
}

std::string CSRF_Middleware::get_cookie_token(const served::request& req) const
{
    return Helper::get_cookie(req, cookie_name);
}

std::string CSRF_Middleware::unsalt_csrf_token(const std::string& token)
{
    std::string secret;
    int index;
    const int allowed_length = sizeof(csrf_allowed_chars) - 1;
    const char* data = token.c_str();
    const char* salt = data + CSRF_SECRET_LENGTH;
    while (*data)
    {
        index = *data - *salt;
        if (index < 0)
            index = allowed_length + index;
        if (index < 0 || index >= allowed_length)
            return std::string();
        secret.push_back(csrf_allowed_chars[index]);
    }
    return secret;
}

bool CSRF_Middleware::is_valid_csrf_token(const std::string& token)
{
    if (token.size() != CSRF_TOKEN_LENGTH)
        return false;
    for (char c: token)
        if (c < '0' || (c > '9' && c < 'A') || (c > 'Z' && c < 'a') || c > 'z')
            return false;
    return true;
}

bool CSRF_Middleware::check_csrf_token(const std::string& token, const std::string& token_request)
{
    // TODO: check referer
    if (is_valid_csrf_token(token) && token == token_request)
    {
        // Соль из Django, не понятно зачем нужна
//        std::string unsalt = unsalt_csrf_token(token);
//        return !unsalt.isEmpty() && unsalt == unsalt_csrf_token(token_request);
        return true;
    }
    return false;
}

} // namespace Rest
} // namespace Das
