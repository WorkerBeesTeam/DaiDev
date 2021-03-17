#include <chrono>
#include <iostream>

#include <stdio.h>
#include <jpeglib.h>
#include <jerror.h>

//#include "CImg/plugins/jpeg_buffer.h"
#define cimg_plugin "CImg/plugins/jpeg_buffer.h"
#define cimg_display 0
#include "CImg.h"
using namespace cimg_library;

#include "captcha_generator.h"

namespace Das {
namespace Rest {

std::string Captcha_Generator::create(std::string &value)
{
    value = gen_value(5);

    CImg<uint8_t> captcha(256, 64, 1, 3, 0), color(3);
    char letter[2] = { 0 };
    for (uint32_t k = 0; k < 6; ++k)
    {
        CImg<uint8_t> tmp;
        *letter = value[k];
        if (*letter)
        {
            cimg_forX(color,i) color[i] = (uint8_t)(128 + (std::rand() % 127));
            tmp.draw_text((int)(2 + 8 * cimg::rand()),
                          (int)(12 * cimg::rand()),
                          letter, color.data(), 0, 1, std::rand() % 2 ? 38 : 57).resize(-100, -100, 1, 3);
            const uint32_t dir = std::rand() % 4, wph = tmp.width() + tmp.height();
            cimg_forXYC(tmp, x, y, v)
            {
                const int val = dir == 0 ? x + y :
                                           (dir == 1 ? x + tmp.height() - y :
                                                       (dir == 2 ? y + tmp.width() - x :
                                                                   tmp.width() - x + tmp.height() - y));
                tmp(x, y, v) = (uint8_t)std::max(0.0f, std::min(255.0f, 1.5f * tmp(x, y, v) * val / wph));
            }
            if (std::rand() % 2)
                tmp = (tmp.get_dilate(3) -= tmp);
            tmp.blur((float)cimg::rand() * 0.8f).normalize(0, 255);
            const float sin_offset = (float)cimg::rand(-1, 1) * 3,
                    sin_freq = (float)cimg::rand(-1, 1) / 7;
            cimg_forYC(captcha,y,v)
                    captcha.get_shared_row(y, 0, v)
                        .shift((int)(4 * std::cos(y * sin_freq + sin_offset)));
            captcha.draw_image(6 + 40*k, tmp);
        }
    }

    // Add geometric and random noise
    CImg<uint8_t> copy = (+captcha).fill(0);
    for (uint32_t l = 0; l<3; ++l)
    {
        if (l)
            copy.blur(0.5f).normalize(0,148);
        for (uint32_t k = 0; k<10; ++k)
        {
            cimg_forX(color, i)
                    color[i] = (uint8_t)(128 + cimg::rand() * 127);
            if (cimg::rand() < 0.5f)
                copy.draw_circle((int)(cimg::rand() * captcha.width()),
                                 (int)(cimg::rand() * captcha.height()),
                                 (int)(cimg::rand() * 30),
                                 color.data(), 0.6f, ~0U);
            else
                copy.draw_line((int)(cimg::rand() * captcha.width()),
                               (int)(cimg::rand() * captcha.height()),
                               (int)(cimg::rand() * captcha.width()),
                               (int)(cimg::rand() * captcha.height()),
                               color.data(), 0.6f);
        }
    }
    captcha |= copy;
    captcha.noise(10, 2);

    captcha.draw_rectangle(0, 0, captcha.width() - 1, captcha.height() - 1,
                               CImg<uint8_t>::vector(255, 255, 255).data(), 1.0f, ~0U);
    captcha = (+captcha).fill(255) - captcha;

    unsigned buf_size = 500000;

    std::string data;
    data.reserve(buf_size * 2);
    captcha.save_jpeg_buffer(reinterpret_cast<JOCTET*>(data.data()), buf_size, 60);
    data.resize(buf_size);

    std::cout << "Captcha buf_size: " << buf_size << std::endl;

    return data;
}

std::string Captcha_Generator::gen_value(std::size_t size)
{
    const char alphabet[] = "0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";
    std::srand(static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count()));

    std::string value;

    while (size--)
    {
        const int i = std::rand() % sizeof(alphabet);
        value += alphabet[i];
    }

    return value;
}

} // namespace Rest
} // namespace Das
