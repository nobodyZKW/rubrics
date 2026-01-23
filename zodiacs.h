#ifndef ZODIACS
#define ZODIACS

#include <string>
#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#include "httplib.h"

std::string get_chinese_zodiac(const std::string& date);
std::string get_western_zodiac(const std::string& date);

httplib::SSLServer &get_server();

std::string generate_share_id();

#endif //ZODIACS
