#include "json_helper.h"
#include "rest_helper.h"

namespace Das {
namespace Rest {

template<typename T>
T parse_picojson(const std::string& json_raw, const std::string& type_err_text)
{
    picojson::value val;
    const std::string err = picojson::parse(val, json_raw);
    if (!err.empty())
        throw served::request_error(served::status_4XX::BAD_REQUEST, err);
    if (!val.is<T>())
        throw served::request_error(served::status_4XX::BAD_REQUEST, type_err_text);
    T& parsed_json = val.get<T>();
    if (parsed_json.empty())
        throw served::request_error(served::status_4XX::BAD_REQUEST, "Empty");
    return std::move(parsed_json);
}

picojson::object Helper::parse_object(const std::string& json_raw)
{
    return parse_picojson<picojson::object>(json_raw, "Object is expected");
}

picojson::array Helper::parse_array(const std::string &json_raw)
{
    return parse_picojson<picojson::array>(json_raw, "Array is expected");
}

uint32_t Helper::get_element_id(const served::request &req, const std::string &key)
{
    uint32_t elem_id = stoa_or(req.params[key]);
    if (elem_id == 0)
        throw served::request_error(served::status_4XX::BAD_REQUEST, "Unknown element id");
    return elem_id;
}

} // namespace Rest
} // namespace Das
