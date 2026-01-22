#ifndef ZODIACS
#define ZODIACS

#include <string>
#include "httplib.h"

std::string get_chinese_zodiac(const std::string& date);
std::string get_western_zodiac(const std::string& date);

httplib::Server &get_server();

std::string generate_share_id();

#endif //ZODIACS