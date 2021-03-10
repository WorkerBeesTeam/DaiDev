#ifndef DAS_REST_SCHEME_GROUP_H
#define DAS_REST_SCHEME_GROUP_H

#define PICOJSON_USE_INT64
#include <picojson/picojson.h>

#include <served/served.hpp>

namespace Das {
namespace Rest {

class Scheme_Group
{
public:
    Scheme_Group(served::multiplexer &mux);
private:
    static picojson::array get_list(uint32_t scheme_id, uint32_t user_id, uint32_t scheme_group_id = 0);
    static void get_element_list(served::response& res, const served::request& req);
    static void create_element(served::response& res, const served::request& req);
    static void update_element(served::response& res, const served::request& req);
    static void get_element(served::response& res, const served::request& req);
    static void del_element(served::response& res, const served::request& req);

    static void add_scheme(served::response& res, const served::request& req);
    static void del_scheme(served::response& res, const served::request& req);
    static void get_schemes(served::response& res, const served::request& req);
    static void add_user(served::response& res, const served::request& req);
    static void del_user(served::response& res, const served::request& req);
    static void get_users(served::response& res, const served::request& req);
};

} // namespace Rest
} // namespace Das

#endif // DAS_REST_SCHEME_GROUP_H
