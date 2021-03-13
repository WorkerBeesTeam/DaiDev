#include <Helpz/zstring.h>

#include <Das/db/user.h>

#include "json_helper.h"
#include "rest_helper.h"
#include "auth_middleware.h"
#include "rest_user.h"

namespace Das {
namespace Rest {

using namespace Helpz::DB;

User::User(served::multiplexer &mux)
{
    const std::string user_path = "/user/";
    const std::string elem_path = user_path + "{elem_id:[0-9]+}/";
    mux.handle(user_path)
            .get(Resource_Handler{get_element_list});
}

void User::get_element_list(served::response &res, const served::request &req)
{
    std::string is_header_str = req.query["header"];
    std::transform(is_header_str.begin(), is_header_str.end(), is_header_str.begin(),
        [](unsigned char c){ return std::tolower(c); });
    bool is_header = is_header_str == "1" || is_header_str == "true";

    Auth_Middleware::check_permission("view_user");

    using T = DB::User;
    Table table = db_table<T>();

    if (is_header)
    {
        table.field_names() = QStringList{
            table.field_names().at(T::COL_id),
            table.field_names().at(T::COL_first_name),
            table.field_names().at(T::COL_last_name),
            table.field_names().at(T::COL_username)
        };
    }

    picojson::array json_array;

    Helpz::DB::Base& db = Helpz::DB::Base::get_thread_local_instance();
    auto q = db.select(table);
    while (q.next())
    {
        picojson::object obj;
        for (int i = 0; i < table.field_names().size(); ++i)
            obj.emplace(table.field_names().at(i).toStdString(), pico_from_qvariant(q.value(i)));
        json_array.emplace_back(std::move(obj));
    }

    res.set_header("Content-Type", "application/json");
    res << picojson::value{std::move(json_array)}.serialize();
}

} // namespace Rest
} // namespace Das
