#ifndef DAS_REST_CONFIG_H
#define DAS_REST_CONFIG_H

#include <string>
#include <chrono>

namespace Das {
namespace Rest {

struct Config
{
    int thread_count_;
    std::string address_, port_, base_path_;
    std::chrono::seconds _token_timeout;
};

} // namespace Rest
} // namespace Das

#endif // DAS_REST_CONFIG_H
