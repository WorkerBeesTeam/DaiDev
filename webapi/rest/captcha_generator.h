#ifndef DAS_REST_CAPTCHA_GENERATOR_H
#define DAS_REST_CAPTCHA_GENERATOR_H

#include <string>

namespace Das {
namespace Rest {

class Captcha_Generator
{
public:
    std::string create(std::string& value);
    std::string gen_value(std::size_t size);
};

} // namespace Rest
} // namespace Das

#endif // DAS_REST_CAPTCHA_GENERATOR_H
