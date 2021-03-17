#ifndef DAS_REST_IP_BLOCKER_H
#define DAS_REST_IP_BLOCKER_H

#include <string>
#include <chrono>
#include <boost/thread/shared_mutex.hpp>

namespace Das {
namespace Rest {

class IP_Blocker
{
public:
    bool operator ()(const std::string &ip);
    bool check_captcha(const std::string& ip, const std::string& captcha_id, const std::string &captcha_value);
    void operator <<(const std::string &ip);
    std::string get_captcha(const std::string &ip, std::string& captcha_id);
private:
    boost::shared_mutex _mutex;

    struct Item
    {
        std::chrono::system_clock::time_point _expired;

        struct Captcha
        {
            std::chrono::system_clock::time_point _expired;
            std::string _value;
        };

        std::map<std::string/*id*/, Captcha> _captcha_map;
    };

    std::map<std::string/*ip*/, Item> _items;
};

} // namespace Rest
} // namespace Das

#endif // DAS_REST_IP_BLOCKER_H
