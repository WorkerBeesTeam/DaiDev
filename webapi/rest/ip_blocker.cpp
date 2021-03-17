
#include "captcha_generator.h"
#include "ip_blocker.h"

namespace Das {
namespace Rest {

bool IP_Blocker::operator ()(const std::string &ip)
{
    if (ip.empty())
        return false;

    boost::shared_lock lock(_mutex);
    auto now = std::chrono::system_clock::now();

    auto it = _items.find(ip);
    return it != _items.cend()
        && it->second._expired > now;
}

bool IP_Blocker::check_captcha(const std::string &ip, const std::string &captcha_id, const std::string& captcha_value)
{
    std::lock_guard lock(_mutex);

    auto it = _items.find(ip);
    if (it == _items.cend())
        return false;

    auto& cptch_map = it->second._captcha_map;
    auto cptch_it = cptch_map.find(captcha_id);
    if (cptch_it == cptch_map.end())
        return false;

    auto now = std::chrono::system_clock::now();
    bool is_valid = cptch_it->second._expired > now
                 && cptch_it->second._value == captcha_value;

    cptch_map.erase(cptch_it);
    for (cptch_it = cptch_map.begin(); cptch_it != cptch_map.end();)
    {
        if (cptch_it->second._expired < now)
            cptch_it = cptch_map.erase(cptch_it);
        else
            ++cptch_it;
    }

    return is_valid;
}

void IP_Blocker::operator <<(const std::string &ip)
{
    if (ip.empty())
        return;

    std::lock_guard lock(_mutex);
    auto now = std::chrono::system_clock::now();
    Item item{ now + std::chrono::hours{1}, {} };

    auto p = _items.emplace(ip, item);
    if (!p.second)
    {
        if (p.first != _items.cend())
            p.first->second = std::move(item);
        else
            _items[ip] = std::move(item);
    }

    for (auto it = _items.begin(); it != _items.end();)
    {
        if (it->second._expired < now)
            it = _items.erase(it);
        else
            ++it;
    }
}

std::string IP_Blocker::get_captcha(const std::string &ip, std::string &captcha_id)
{
    if (!ip.empty())
    {
        Captcha_Generator gen;
        captcha_id = gen.gen_value(32);
        std::string value;
        std::string data = gen.create(value);

        auto now = std::chrono::system_clock::now();
        Item::Captcha captcha{ now + std::chrono::minutes{15}, std::move(value) };

        std::lock_guard lock(_mutex);

        auto it = _items.find(ip);
        if (it != _items.cend() && !data.empty())
        {
            bool ok = it->second._captcha_map.emplace(captcha_id, std::move(captcha)).second;
            if (ok)
                return data;
        }
    }
    return {};
}

} // namespace Rest
} // namespace Das
