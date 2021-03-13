#ifndef DAS_REST_USER_H
#define DAS_REST_USER_H

#include <served/multiplexer.hpp>

namespace Das {
namespace Rest {

class User
{
public:
    User(served::multiplexer &mux);

    static void get_element_list(served::response& res, const served::request& req);
};

} // namespace Rest
} // namespace Das

#endif // DAS_REST_USER_H
