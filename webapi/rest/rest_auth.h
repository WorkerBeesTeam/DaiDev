#ifndef DAS_REST_AUTH_H
#define DAS_REST_AUTH_H

#include <served/multiplexer.hpp>

#include <QVariantList>

#include "ip_blocker.h"

namespace Das {
namespace Rest {

class Auth
{
public:
    static std::string auth_token_path();
    static std::string auth_captcha_path();
    static std::vector<std::string> paths();

    Auth(served::multiplexer &mux);

private:
    static void auth_captcha(served::response& res, const served::request& req);
    static void auth_token(served::response& res, const served::request& req);
    static void auth_token_refresh(served::response& res, const served::request& req);
    static void gen_auth_token_response(served::response& res, QString sql, const QVariantList &values,
                                        const std::string &password = {});

    static IP_Blocker _blocker;
};

} // namespace Rest
} // namespace Das

#endif // DAS_REST_AUTH_H
