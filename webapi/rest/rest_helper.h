#ifndef DAS_REST_HELPER_H
#define DAS_REST_HELPER_H

#define PICOJSON_USE_INT64
#include <picojson/picojson.h>

#include <served/request.hpp>
#include <served/response.hpp>
#include <served/status.hpp>
#include <served/request_error.hpp>

namespace Das {
namespace Rest {

struct Helper
{
    static std::string get_cookie(const served::request &req, const std::string& key);

    static picojson::object parse_object(const std::string& json_raw);
    static picojson::array parse_array(const std::string& json_raw);

    static uint32_t get_element_id(const served::request &req, const std::string& key = "elem_id");
};

template<typename T = std::tuple<>>
struct Resource_Handler
{
    typedef typename std::conditional<std::is_empty<T>::value,
        void(*)(served::response &, const served::request &),
        void(*)(served::response &, const served::request &, const T&)>::type Handler_Func;

    Resource_Handler(Handler_Func func, const T& data = {}) :
        _handler{func}, _data{data} {}

    void operator()(served::response &res, const served::request &req)
    {
        try {
            if constexpr (std::is_empty<T>::value)
                _handler(res, req);
            else
                _handler(res, req, _data);
        } catch (const served::request_error&) {
            throw;
        } catch (const std::exception& e) {
            throw served::request_error(served::status_5XX::INTERNAL_SERVER_ERROR, e.what());
        }
    }

    Handler_Func _handler;
    const T _data;
};

} // namespace Rest
} // namespace Das

#endif // DAS_REST_HELPER_H
