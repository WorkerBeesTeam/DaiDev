#include <QDebug>


#include <jwt-cpp/include/jwt-cpp/jwt.h>

#include "jwt_helper.h"

namespace Das {

JWT_Helper::JWT_Helper(const std::string& secret_key)
{
    if (secret_key.empty())
        qCritical() << "JWT ERROR: need secret key";
    algo_ = new jwt::algorithm::hs256{secret_key};
//    token_verifier_ = new jwt::verifier<jwt::default_clock>{{}};
//    token_verifier_->allow_algorithm(jwt::algorithm::hs256{secret_key});

    auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::hs256{secret_key});
    token_verifier_ = new jwt::verifier<jwt::default_clock>{std::move(verifier)};
}

JWT_Helper::~JWT_Helper()
{
    delete token_verifier_;
    delete algo_;
}

std::string JWT_Helper::create(uint32_t user_id, std::chrono::seconds timeout, std::string session_id) const
{
    auto now = std::chrono::system_clock::now();

    if (session_id.empty())
    {
        using years	= std::chrono::duration<int64_t, std::ratio<31556952>>;
        auto tp_since_2021 = now - years{51};
        auto dur_since_2021 = tp_since_2021.time_since_epoch();
        int64_t ns_sice_2021 = std::chrono::duration_cast<std::chrono::nanoseconds>(dur_since_2021).count();

        session_id = std::to_string(user_id);
        session_id += std::to_string(ns_sice_2021);
    }

    auto token = jwt::create()
        .set_issued_at(now)
        .set_expires_at(now + timeout)
        .set_payload_claim("user_id", picojson::value{static_cast<int64_t>(user_id)})
        .set_payload_claim("session_id", picojson::value{std::move(session_id)})
        .sign(*algo_);
    return token;
}

std::string JWT_Helper::decode_and_verify(const std::string& token) const
{
    auto decoded = jwt::decode(token);
//    std::cout << "T type " << decoded.get_type() << std::endl;
//    for (auto it: decoded.get_payload_claims())
//        std::cout << "T pl claim " << it.first << std::endl;
    verify(decoded);
    return decoded.get_payload();
}

void JWT_Helper::verify(const jwt::decoded_jwt& jwt) const
{
    token_verifier_->verify(jwt);
}

} // namespace Das
