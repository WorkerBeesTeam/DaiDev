#ifndef DAS_JWT_HELPER_H
#define DAS_JWT_HELPER_H

#include <memory>
#include <set>
#include <chrono>

#include <QJsonDocument>

namespace jwt {
class decoded_jwt;
struct default_clock;
template<typename Clock>
class verifier;
namespace algorithm {
class hs256;
}
} // namespace jwt

namespace Das {

class JWT_Helper
{
public:
    JWT_Helper(const std::string& secret_key);
    ~JWT_Helper();

    std::string create(uint32_t user_id, std::chrono::seconds timeout = std::chrono::seconds{3600},
                       std::string session_id = {}) const;
    std::string decode_and_verify(const std::string& token) const;
    void verify(const jwt::decoded_jwt& jwt) const;
private:
    jwt::verifier<jwt::default_clock>* token_verifier_;
    jwt::algorithm::hs256* algo_;
};

} // namespace Das

#endif // DAS_JWT_HELPER_H
