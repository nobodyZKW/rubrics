// zodiacs.cpp
#include "zodiacs.h"
#include <stdexcept>
#include <sstream>
#include <vector>
#include <iostream>
#include <jsoncpp/json/json.h>
#include <algorithm>
#include <map>
#include <random>
#include <iomanip>
#include <ctime>
#include <mutex> // Required for std::mutex and std::lock_guard
#include <fstream>
#include <cstdlib>
#include <memory>
#include <openssl/sha.h>
#include <thread>

// Authentication and session management
struct User {
    std::string username;
    std::string password_hash;
    std::string salt;
};

struct SearchHistory {
    std::string date;
    std::string chinese_zodiac;
    std::string western_zodiac;
    std::time_t timestamp;
};

std::map<std::string, User> users;
struct SessionInfo {
    std::string username;
    std::time_t expires_at;
};
std::map<std::string, SessionInfo> sessions; // session_id -> info
std::map<std::string, std::vector<SearchHistory>> user_history; // username -> history
std::mutex auth_mutex;
constexpr std::time_t kSessionTtlSeconds = 60 * 60;

// Helper function to hash password
std::string hash_password(const std::string& password, const std::string& salt) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, salt.c_str(), salt.size());
    SHA256_Update(&sha256, password.c_str(), password.size());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string generate_salt() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::mutex gen_mutex;

    std::stringstream ss;
    std::lock_guard<std::mutex> lock(gen_mutex);
    for (int i = 0; i < 32; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

void load_users() {
    std::ifstream file("users.json");
    if (!file.is_open()) {
        // Create default admin user if file doesn't exist
        User admin;
        admin.username = "admin";
        admin.salt = generate_salt();
        admin.password_hash = hash_password("admin123", admin.salt);
        users["admin"] = admin;
        
        // Save to file
        Json::Value root;
        Json::Value user_obj;
        user_obj["username"] = admin.username;
        user_obj["password_hash"] = admin.password_hash;
        user_obj["salt"] = admin.salt;
        root["admin"] = user_obj;
        
        std::ofstream out_file("users.json");
        Json::StreamWriterBuilder builder;
        std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
        writer->write(root, &out_file);
        return;
    }
    
    Json::Value root;
    Json::Reader reader;
    if (reader.parse(file, root)) {
        for (const auto& key : root.getMemberNames()) {
            User user;
            user.username = root[key]["username"].asString();
            user.password_hash = root[key]["password_hash"].asString();
            user.salt = root[key].isMember("salt") ? root[key]["salt"].asString() : "";
            users[key] = user;
        }
    }
}

void save_users() {
    Json::Value root;
    for (const auto& pair : users) {
        Json::Value user_obj;
        user_obj["username"] = pair.second.username;
        user_obj["password_hash"] = pair.second.password_hash;
        user_obj["salt"] = pair.second.salt;
        root[pair.first] = user_obj;
    }
    
    std::ofstream file("users.json");
    Json::StreamWriterBuilder builder;
    std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
    writer->write(root, &file);
}

bool get_session_user(const std::string& session_id, std::string& username_out, bool* expired_out = nullptr) {
    std::lock_guard<std::mutex> lock(auth_mutex);
    auto session_it = sessions.find(session_id);
    if (session_it == sessions.end()) {
        return false;
    }

    const std::time_t now = std::time(nullptr);
    if (now >= session_it->second.expires_at) {
        if (expired_out) {
            *expired_out = true;
        }
        sessions.erase(session_it);
        return false;
    }

    if (expired_out) {
        *expired_out = false;
    }
    username_out = session_it->second.username;
    return true;
}

bool invalidate_session(const std::string& session_id, bool* expired_out = nullptr) {
    std::lock_guard<std::mutex> lock(auth_mutex);
    auto session_it = sessions.find(session_id);
    if (session_it == sessions.end()) {
        return false;
    }

    const std::time_t now = std::time(nullptr);
    if (now >= session_it->second.expires_at) {
        if (expired_out) {
            *expired_out = true;
        }
        sessions.erase(session_it);
        return false;
    }

    if (expired_out) {
        *expired_out = false;
    }
    sessions.erase(session_it);
    return true;
}

// Generate session ID
std::string generate_session_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::mutex gen_mutex;

    std::stringstream ss;
    std::lock_guard<std::mutex> lock(gen_mutex);
    for (int i = 0; i < 16; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

// Add search to history
void add_to_history(const std::string& username, const std::string& date, 
    const std::string& chinese = "", const std::string& western = "") {
    std::lock_guard<std::mutex> lock(auth_mutex);
    SearchHistory entry;
    entry.date = date;
    entry.chinese_zodiac = chinese;
    entry.western_zodiac = western;
    entry.timestamp = std::time(nullptr);
    user_history[username].push_back(entry);
}       

// Helper function to parse date from string
bool parse_date(const std::string& date, int& day, int& month, int& year) {
    std::istringstream ss(date);
    char delimiter;
    if (!(ss >> day >> delimiter >> month >> delimiter >> year) || delimiter != '-') {
        return false;
    }
    return true;
}

// Helper function to check if a date is within a valid range
bool is_valid_date(int day, int month, int year) {
    if (year < 1930 || year > 2031) return false;
    if (month < 1 || month > 12) return false;
    if (day < 1 || day > 31) return false;
    if ((month == 4 || month == 6 || month == 9 || month == 11) && day > 30) return false;
    if (month == 2) {
        if ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) {
            if (day > 29) return false;
        } else {
            if (day > 28) return false;
        }
    }

    // Additional checks for the date range
    if (year == 1930 && (month < 1 || (month == 1 && day < 30))) return false;
    if (year == 2031 && (month > 1 || (month == 1 && day > 22))) return false;

    return true;
}

// Helper function to get the Chinese zodiac animal for a given year
std::string get_chinese_zodiac_animal(int year) {
    std::vector<std::string> animals = {"Monkey", "Rooster", "Dog", "Pig", "Rat", "Ox", "Tiger", "Rabbit", "Dragon", "Snake", "Horse", "Sheep"};
    return animals[year % 12];
}

// List of Chinese New Year dates
std::vector<std::pair<int, std::string>> chinese_new_year_dates = {
    {1930, "30-01-1930"}, {1931, "17-02-1931"}, {1932, "06-02-1932"}, {1933, "26-01-1933"}, {1934, "14-02-1934"},
    {1935, "04-02-1935"}, {1936, "24-01-1936"}, {1937, "11-02-1937"}, {1938, "31-01-1938"}, {1939, "19-02-1939"},
    {1940, "08-02-1940"}, {1941, "27-01-1941"}, {1942, "15-02-1942"}, {1943, "05-02-1943"}, {1944, "25-01-1944"},
    {1945, "13-02-1945"}, {1946, "02-02-1946"}, {1947, "22-01-1947"}, {1948, "10-02-1948"}, {1949, "29-01-1949"},
    {1950, "17-02-1950"}, {1951, "06-02-1951"}, {1952, "27-01-1952"}, {1953, "14-02-1953"}, {1954, "03-02-1954"},
    {1955, "24-01-1955"}, {1956, "12-02-1956"}, {1957, "31-01-1957"}, {1958, "18-02-1958"}, {1959, "08-02-1959"},
    {1960, "28-01-1960"}, {1961, "15-02-1961"}, {1962, "05-02-1962"}, {1963, "25-01-1963"}, {1964, "13-02-1964"},
    {1965, "02-02-1965"}, {1966, "21-01-1966"}, {1967, "09-02-1967"}, {1968, "30-01-1968"}, {1969, "17-02-1969"},
    {1970, "06-02-1970"}, {1971, "27-01-1971"}, {1972, "15-02-1972"}, {1973, "03-02-1973"}, {1974, "23-01-1974"},
    {1975, "11-02-1975"}, {1976, "31-01-1976"}, {1977, "18-02-1977"}, {1978, "07-02-1978"}, {1979, "28-01-1979"},
    {1980, "16-02-1980"}, {1981, "05-02-1981"}, {1982, "25-01-1982"}, {1983, "13-02-1983"}, {1984, "02-02-1984"},
    {1985, "20-02-1985"}, {1986, "09-02-1986"}, {1987, "29-01-1987"}, {1988, "17-02-1988"}, {1989, "06-02-1989"},
    {1990, "27-01-1990"}, {1991, "15-02-1991"}, {1992, "04-02-1992"}, {1993, "23-01-1993"}, {1994, "10-02-1994"},
    {1995, "31-01-1995"}, {1996, "19-02-1996"}, {1997, "07-02-1997"}, {1998, "28-01-1998"}, {1999, "16-02-1999"},
    {2000, "05-02-2000"}, {2001, "24-01-2001"}, {2002, "12-02-2002"}, {2003, "01-02-2003"}, {2004, "22-01-2004"},
    {2005, "09-02-2005"}, {2006, "29-01-2006"}, {2007, "18-02-2007"}, {2008, "07-02-2008"}, {2009, "26-01-2009"},
    {2010, "14-02-2010"}, {2011, "03-02-2011"}, {2012, "23-01-2012"}, {2013, "10-02-2013"}, {2014, "31-01-2014"},
    {2015, "19-02-2015"}, {2016, "08-02-2016"}, {2017, "28-01-2017"}, {2018, "16-02-2018"}, {2019, "05-02-2019"},
    {2020, "25-01-2020"}, {2021, "12-02-2021"}, {2022, "01-02-2022"}, {2023, "22-01-2023"}, {2024, "10-02-2024"},
    {2025, "29-01-2025"}, {2026, "17-02-2026"}, {2027, "06-02-2027"}, {2028, "26-01-2028"}, {2029, "13-02-2029"},
    {2030, "03-02-2030"}, {2031, "23-01-2031"}
};

std::string get_chinese_zodiac(const std::string& date) {
    int day, month, year;
    if (!parse_date(date, day, month, year)) {
        throw std::invalid_argument("Invalid date format. Please use DD-MM-YYYY.");
    }

    if (!is_valid_date(day, month, year)) {
        throw std::invalid_argument("Invalid date or date out of supported range.");
    }

    int chinese_new_year_day, chinese_new_year_month, chinese_new_year_year;
    for (const auto& entry : chinese_new_year_dates) {
        if (entry.first == year) {
            parse_date(entry.second, chinese_new_year_day, chinese_new_year_month, chinese_new_year_year);
            if (month > chinese_new_year_month || (month == chinese_new_year_month && day >= chinese_new_year_day)) {
                return get_chinese_zodiac_animal(year);
            } else {
                return get_chinese_zodiac_animal(year - 1);
            }
        }
    }

    throw std::invalid_argument("Chinese New Year date not found for the given year.");
}

std::string get_western_zodiac(const std::string& date) {
    int day, month, year;
    if (!parse_date(date, day, month, year)) {
        throw std::invalid_argument("Invalid date format. Please use DD-MM-YYYY.");
    }

    if (!is_valid_date(day, month, year)) {
        throw std::invalid_argument("Invalid date or date out of supported range.");
    }

    if ((month == 3 && day >= 21) || (month == 4 && day <= 19)) {
        return "Aries";
    } else if ((month == 4 && day >= 20) || (month == 5 && day <= 20)) {
        return "Taurus";
    } else if ((month == 5 && day >= 21) || (month == 6 && day <= 21)) {
        return "Gemini";
    } else if ((month == 6 && day >= 22) || (month == 7 && day <= 22)) {
        return "Cancer";
    } else if ((month == 7 && day >= 23) || (month == 8 && day <= 22)) {
        return "Leo";
    } else if ((month == 8 && day >= 23) || (month == 9 && day <= 22)) {
        return "Virgo";
    } else if ((month == 9 && day >= 23) || (month == 10 && day <= 23)) {
        return "Libra";
    } else if ((month == 10 && day >= 24) || (month == 11 && day <= 21)) {
        return "Scorpio";
    } else if ((month == 11 && day >= 22) || (month == 12 && day <= 21)) {
        return "Sagittarius";
    } else if ((month == 12 && day >= 22) || (month == 1 && day <= 19)) {
        return "Capricorn";
    } else if ((month == 1 && day >= 20) || (month == 2 && day <= 18)) {
        return "Aquarius";
    } else if ((month == 2 && day >= 19) || (month == 3 && day <= 20)) {
        return "Pisces";
    }

    
    throw std::invalid_argument("Failed to determine Western zodiac sign.");
}

// Helper function to generate a unique share ID
std::string generate_share_id() {
    // These static variables are initialized once in a thread-safe manner (C++11+)
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    // FIX: A mutex is needed to protect access to the non-thread-safe 'gen'
    static std::mutex gen_mutex;

    std::stringstream ss;
    // Lock the mutex to ensure exclusive access to the random number generator
    std::lock_guard<std::mutex> lock(gen_mutex);
    for (int i = 0; i < 8; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

// Storage for shared results - now thread-safe
std::map<std::string, Json::Value> shared_results;
std::mutex shared_results_mutex;

// Helper function to parse JSON array of dates
std::vector<std::string> parse_date_array(const std::string& json_str) {
    Json::Value root;
    Json::Reader reader;
    std::vector<std::string> dates;
    
    if (reader.parse(json_str, root) && root.isArray()) {
        for (const auto& date : root) {
            if (date.isString()) {
                dates.push_back(date.asString());
            }
        }
    }
    return dates;
}

// Helper function to generate date range
std::vector<std::string> generate_date_range(const std::string& start_date, const std::string& end_date) {
    std::vector<std::string> dates;
    
    int start_day, start_month, start_year;
    int end_day, end_month, end_year;
    
    if (!parse_date(start_date, start_day, start_month, start_year) ||
        !parse_date(end_date, end_day, end_month, end_year)) {
        return dates;
    }
    
    // Simple date iteration (basic implementation)
    // For production, consider using a proper date library
    for (int year = start_year; year <= end_year; ++year) {
        int start_m = (year == start_year) ? start_month : 1;
        int end_m = (year == end_year) ? end_month : 12;
        
        for (int month = start_m; month <= end_m; ++month) {
            int start_d = (year == start_year && month == start_month) ? start_day : 1;
            int end_d = (year == end_year && month == end_month) ? end_day : 31;
            
            // Adjust for month lengths
            if (month == 4 || month == 6 || month == 9 || month == 11) {
                end_d = std::min(end_d, 30);
            } else if (month == 2) {
                bool is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
                end_d = std::min(end_d, is_leap ? 29 : 28);
            }
            
            for (int day = start_d; day <= end_d; ++day) {
                std::ostringstream date_ss;
                date_ss << std::setfill('0') << std::setw(2) << day << "-"
                        << std::setfill('0') << std::setw(2) << month << "-"
                        << year;
                dates.push_back(date_ss.str());
                
                // Limit to prevent excessive ranges
                if (dates.size() >= 366) {
                    return dates;
                }
            }
        }
    }
    
    return dates;
}

bool file_exists(const std::string& path) {
    std::ifstream file(path);
    return file.good();
}

std::string get_source_dir() {
    std::string path = __FILE__;
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) {
        return ".";
    }
    return path.substr(0, pos);
}

struct CertPaths {
    std::string cert_path;
    std::string key_path;
};

CertPaths ensure_certificates() {
    std::string base_dir = get_source_dir();
    std::string cert_path = base_dir + "/cert.pem";
    std::string key_path = base_dir + "/key.pem";

    if (!file_exists(cert_path) || !file_exists(key_path)) {
        std::cerr << "Generating self-signed TLS certificate..." << std::endl;
        std::string command =
            "openssl req -x509 -newkey rsa:2048 -keyout \"" + key_path +
            "\" -out \"" + cert_path + "\" -days 365 -nodes -subj \"/CN=localhost\"";
        if (std::system(command.c_str()) != 0) {
            throw std::runtime_error("Failed to generate TLS certificate.");
        }
    }

    return {cert_path, key_path};
}

httplib::SSLServer &get_server() {
    static std::unique_ptr<httplib::SSLServer> svr;
    static bool server_initialized = false;

    if (server_initialized) {
        return *svr;
    }

    if (!svr) {
        CertPaths certs = ensure_certificates();
        svr.reset(new httplib::SSLServer(certs.cert_path.c_str(), certs.key_path.c_str()));
        if (!svr->is_valid()) {
            throw std::runtime_error("Failed to initialize TLS server.");
        }
    }


    // Load users from file
    load_users();


    // FIX: Add a logger to help with debugging
    svr->set_logger([](const httplib::Request& req, const httplib::Response& res) {
        std::cout << "[ " << req.method << " ] " << req.path << " -> " << res.status << std::endl;
    });


    svr->Post("/login", [](const httplib::Request& req, httplib::Response& res) {
        Json::Value request_body;
        Json::Reader reader;
        
        if (!reader.parse(req.body, request_body) || 
            !request_body.isMember("username") || !request_body.isMember("password")) {
            res.status = 400;
            res.set_content("{\"error\": \"Username and password required\"}", "application/json");
            return;
        }
        
        std::string username = request_body["username"].asString();
        std::string password = request_body["password"].asString();
        
        std::lock_guard<std::mutex> lock(auth_mutex);
        auto user_it = users.find(username);
        if (user_it != users.end()) {
            std::string password_hash = hash_password(password, user_it->second.salt);
            if (user_it->second.password_hash != password_hash) {
                res.status = 401;
                res.set_content("{\"error\": \"Invalid credentials\"}", "application/json");
                return;
            }

            if (user_it->second.salt.empty()) {
                user_it->second.salt = generate_salt();
                user_it->second.password_hash = hash_password(password, user_it->second.salt);
                save_users();
            }

            std::string session_id = generate_session_id();
            SessionInfo session;
            session.username = username;
            session.expires_at = std::time(nullptr) + kSessionTtlSeconds;
            sessions[session_id] = session;
            
            Json::Value response;
            response["success"] = true;
            response["session_id"] = session_id;
            response["username"] = username;
            response["expires_at"] = static_cast<Json::Int64>(session.expires_at);
            
            Json::StreamWriterBuilder builder;
            std::string json_response = Json::writeString(builder, response);
            res.set_content(json_response, "application/json");
        } else {
            res.status = 401;
            res.set_content("{\"error\": \"Invalid credentials\"}", "application/json");
        }
    });

    // Register endpoint
    svr->Post("/register", [](const httplib::Request& req, httplib::Response& res) {
        Json::Value request_body;
        Json::Reader reader;
        
        if (!reader.parse(req.body, request_body) || 
            !request_body.isMember("username") || !request_body.isMember("password")) {
            res.status = 400;
            res.set_content("{\"error\": \"Username and password required\"}", "application/json");
            return;
        }
        
        std::string username = request_body["username"].asString();
        std::string password = request_body["password"].asString();
        
        std::lock_guard<std::mutex> lock(auth_mutex);
        if (users.find(username) != users.end()) {
            res.status = 409;
            res.set_content("{\"error\": \"Username already exists\"}", "application/json");
            return;
        }
        
        User new_user;
        new_user.username = username;
        new_user.salt = generate_salt();
        new_user.password_hash = hash_password(password, new_user.salt);
        users[username] = new_user;
        save_users();
        
        res.set_content("{\"success\": true}", "application/json");
    });

    // Logout endpoint
    svr->Post("/logout", [](const httplib::Request& req, httplib::Response& res) {
        std::string session_id = req.get_header_value("Authorization");
        if (session_id.empty()) {
            res.status = 401;
            res.set_content("{\"error\": \"Authorization required\"}", "application/json");
            return;
        }

        bool expired = false;
        if (!invalidate_session(session_id, &expired)) {
            res.status = 401;
            if (expired) {
                res.set_content("{\"error\": \"Session expired\"}", "application/json");
            } else {
                res.set_content("{\"error\": \"Invalid session\"}", "application/json");
            }
            return;
        }

        res.set_content("{\"success\": true}", "application/json");
    });

    // History endpoint
    svr->Get("/history", [](const httplib::Request& req, httplib::Response& res) {
        std::string session_id = req.get_header_value("Authorization");
        if (session_id.empty()) {
            res.status = 401;
            res.set_content("{\"error\": \"Authorization required\"}", "application/json");
            return;
        }
        
        std::string username;
        bool expired = false;
        if (!get_session_user(session_id, username, &expired)) {
            res.status = 401;
            if (expired) {
                res.set_content("{\"error\": \"Session expired\"}", "application/json");
            } else {
                res.set_content("{\"error\": \"Invalid session\"}", "application/json");
            }
            return;
        }

        Json::Value response(Json::arrayValue);
        
        std::lock_guard<std::mutex> lock(auth_mutex);
        if (user_history.find(username) != user_history.end()) {
            for (const auto& entry : user_history[username]) {
                Json::Value history_entry;
                history_entry["date"] = entry.date;
                history_entry["chinese_zodiac"] = entry.chinese_zodiac;
                history_entry["western_zodiac"] = entry.western_zodiac;
                history_entry["timestamp"] = static_cast<int64_t>(entry.timestamp);
                response.append(history_entry);
            }
        }
        
        Json::StreamWriterBuilder builder;
        std::string json_response = Json::writeString(builder, response);
        res.set_content(json_response, "application/json");
    });

    // Helper function to get username from session
    auto get_username_from_session = [](const httplib::Request& req) -> std::string {
        std::string session_id = req.get_header_value("Authorization");
        if (session_id.empty()) return "";
        std::string username;
        if (!get_session_user(session_id, username)) {
            return "";
        }
        return username;
    };

    // Modified Chinese zodiac endpoint to track history
    svr->Get("/chinese", [&get_username_from_session](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_param("date")) {
            res.status = 400;
            res.set_content("{\"error\": \"Date parameter is required\"}", "application/json");
            return;
        }
        
        std::string date = req.get_param_value("date");
        try {
            std::string zodiac = get_chinese_zodiac(date);
            std::string username = get_username_from_session(req);
            
            if (!username.empty()) {
                add_to_history(username, date, zodiac, "");
            }
            
            res.set_content("{\"zodiac\": \"" + zodiac + "\"}", "application/json");
        } catch (const std::invalid_argument& e) {
            res.status = 400;
            res.set_content("{\"error\": \"" + std::string(e.what()) + "\"}", "application/json");
        }
    });

    // Modified Western zodiac endpoint to track history
    svr->Get("/western", [&get_username_from_session](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_param("date")) {
            res.status = 400;
            res.set_content("{\"error\": \"Date parameter is required\"}", "application/json");
            return;
        }
        
        std::string date = req.get_param_value("date");
        try {
            std::string zodiac = get_western_zodiac(date);
            std::string username = get_username_from_session(req);
            
            if (!username.empty()) {
                add_to_history(username, date, "", zodiac);
            }
            
            res.set_content("{\"zodiac\": \"" + zodiac + "\"}", "application/json");
        } catch (const std::invalid_argument& e) {
            res.status = 400;
            res.set_content("{\"error\": \"" + std::string(e.what()) + "\"}", "application/json");
        }
    });

    // Combined zodiac endpoint for history tracking
    svr->Get("/zodiac", [&get_username_from_session](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_param("date")) {
            res.status = 400;
            res.set_content("{\"error\": \"Date parameter is required\"}", "application/json");
            return;
        }
        
        std::string date = req.get_param_value("date");
        try {
            std::string chinese_zodiac = get_chinese_zodiac(date);
            std::string western_zodiac = get_western_zodiac(date);
            std::string username = get_username_from_session(req);
            
            if (!username.empty()) {
                add_to_history(username, date, chinese_zodiac, western_zodiac);
            }
            
            Json::Value response;
            response["chinese_zodiac"] = chinese_zodiac;
            response["western_zodiac"] = western_zodiac;
            
            Json::StreamWriterBuilder builder;
            std::string json_response = Json::writeString(builder, response);
            res.set_content(json_response, "application/json");
        } catch (const std::invalid_argument& e) {
            res.status = 400;
            res.set_content("{\"error\": \"" + std::string(e.what()) + "\"}", "application/json");
        }
    });

    // Bulk operations endpoint
    svr->Post("/bulk", [&get_username_from_session](const httplib::Request& req, httplib::Response& res) {
        Json::Value response;
        Json::Value results(Json::arrayValue);
        
        try {
            std::vector<std::string> dates = parse_date_array(req.body);
            
            if (dates.empty()) {
                res.status = 400;
                res.set_content("{\"error\": \"Invalid JSON or empty date array\"}", "application/json");
                return;
            }
            
            if (dates.size() > 100) {
                res.status = 400;
                res.set_content("{\"error\": \"Maximum 100 dates allowed per request\"}", "application/json");
                return;
            }
            
            for (const auto& date : dates) {
                Json::Value result;
                result["date"] = date;
                
                try {
                    result["chinese_zodiac"] = get_chinese_zodiac(date);
                    result["western_zodiac"] = get_western_zodiac(date);
                    result["success"] = true;

                    std::string username = get_username_from_session(req);
                    if (!username.empty()) {
                        add_to_history(username, date, result["chinese_zodiac"].asString(), result["western_zodiac"].asString());
                    }
                } catch (const std::invalid_argument& e) {
                    result["error"] = e.what();
                    result["success"] = false;
                }
                
                results.append(result);
            }
            
            response["results"] = results;
            response["total_processed"] = static_cast<int>(dates.size());
            
            Json::StreamWriterBuilder builder;
            std::string json_response = Json::writeString(builder, response);
            res.set_content(json_response, "application/json");
            
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content("{\"error\": \"Failed to process bulk request\"}", "application/json");
        }
    });

    // Date range endpoint
    svr->Get("/range", [&get_username_from_session](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_param("start") || !req.has_param("end")) {
            res.status = 400;
            res.set_content("{\"error\": \"Both start and end date parameters are required\"}", "application/json");
            return;
        }
        
        std::string start_date = req.get_param_value("start");
        std::string end_date = req.get_param_value("end");
        std::string username = get_username_from_session(req);

        
        try {
            std::vector<std::string> dates = generate_date_range(start_date, end_date);
            
            if (dates.empty()) {
                res.status = 400;
                res.set_content("{\"error\": \"Invalid date range or format\"}", "application/json");
                return;
            }
            
            Json::Value response;
            Json::Value results(Json::arrayValue);
            
            for (const auto& date : dates) {
                Json::Value result;
                result["date"] = date;
                
                try {
                    result["chinese_zodiac"] = get_chinese_zodiac(date);
                    result["western_zodiac"] = get_western_zodiac(date);
                    result["success"] = true;

                    
                    if (!username.empty()) {
                        add_to_history(username, date, result["chinese_zodiac"].asString(), result["western_zodiac"].asString());
                    }
                } catch (const std::invalid_argument& e) {
                    result["error"] = e.what();
                    result["success"] = false;
                }
                
                results.append(result);
            }
            
            response["results"] = results;
            response["date_range"] = Json::Value(Json::objectValue);
            response["date_range"]["start"] = start_date;
            response["date_range"]["end"] = end_date;
            response["total_dates"] = static_cast<int>(dates.size());
            
            Json::StreamWriterBuilder builder;
            std::string json_response = Json::writeString(builder, response);
            res.set_content(json_response, "application/json");
            
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content("{\"error\": \"Failed to process date range\"}", "application/json");
        }
    });

    // Share results endpoint
    svr->Post("/share", [&get_username_from_session](const httplib::Request& req, httplib::Response& res) {
        Json::Value request_body;
        Json::Reader reader;
        
        if (!reader.parse(req.body, request_body) || !request_body.isMember("date")) {
            res.status = 400;
            res.set_content("{\"error\": \"Date parameter is required in JSON body\"}", "application/json");
            return;
        }
        
        try {
            std::string date = request_body["date"].asString();
            
            // Generate zodiac results for the date
            std::string chinese_zodiac = get_chinese_zodiac(date);
            std::string western_zodiac = get_western_zodiac(date);
            
            // Create JSON response with the results
            Json::Value result;
            result["date"] = date;
            result["chinese_zodiac"] = chinese_zodiac;
            result["western_zodiac"] = western_zodiac;
            result["shared_at"] = std::time(nullptr);

            std::string username = get_username_from_session(req);

            if (!username.empty()) {
                add_to_history(username, date, result["chinese_zodiac"].asString(), result["western_zodiac"].asString());
            }
            
            // Generate a unique share ID
            std::string share_id = generate_share_id();
            
            // Store the result in the shared_results map
            {
                std::lock_guard<std::mutex> lock(shared_results_mutex);
                shared_results[share_id] = result;
            }
            
            // Return the share ID and results
            Json::Value response;
            response["share_id"] = share_id;
            response["share_url"] = "/shared/" + share_id;
            response["result"] = result;
            
            Json::StreamWriterBuilder builder;
            std::string json_response = Json::writeString(builder, response);
            res.set_content(json_response, "application/json");
            
        } catch (const std::invalid_argument& e) {
            res.status = 400;
            res.set_content("{\"error\": \"" + std::string(e.what()) + "\"}", "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            std::string error_msg = "{\"error\": \"An unexpected error occurred: " + std::string(e.what()) + "\"}";
            res.set_content(error_msg, "application/json");
            std::cerr << "Error in /share: " << e.what() << std::endl;
        }
    });

    // Get shared results endpoint
    svr->Get("/shared/([a-f0-9]+)", [](const httplib::Request& req, httplib::Response& res) {
        std::string share_id = req.matches[1];
        
        std::lock_guard<std::mutex> lock(shared_results_mutex);
        auto it = shared_results.find(share_id);
        if (it == shared_results.end()) {
            res.status = 404;
            res.set_content("{\"error\": \"Shared result not found\"}", "application/json");
            return;
        }
        
        Json::StreamWriterBuilder builder;
        std::string json_response = Json::writeString(builder, it->second);
        res.set_content(json_response, "application/json");
    });

    // API Documentation endpoint (Swagger-like)
    svr->Get("/api-docs", [](const httplib::Request& req, httplib::Response& res) {
        Json::Value swagger;
        swagger["openapi"] = "3.0.0";
        
        Json::Value info;
        info["title"] = "Zodiac Calculator API";
        info["version"] = "1.0.0";
        info["description"] = "API for calculating Chinese and Western zodiac signs";
        swagger["info"] = info;
        
        Json::Value servers(Json::arrayValue);
        Json::Value server;
        server["url"] = "https://localhost:8080";
        server["description"] = "Development server";
        servers.append(server);
        swagger["servers"] = servers;
        
        Json::Value paths;
        
        // Chinese zodiac endpoint
        Json::Value chinese_path;
        Json::Value chinese_get;
        chinese_get["summary"] = "Get Chinese zodiac sign";
        chinese_get["parameters"] = Json::Value(Json::arrayValue);
        Json::Value date_param;
        date_param["name"] = "date";
        date_param["in"] = "query";
        date_param["required"] = true;
        date_param["schema"]["type"] = "string";
        date_param["schema"]["pattern"] = "^\\d{2}-\\d{2}-\\d{4}$";
        date_param["description"] = "Date in DD-MM-YYYY format";
        chinese_get["parameters"].append(date_param);
        chinese_path["get"] = chinese_get;
        paths["/chinese"] = chinese_path;
        
        // Western zodiac endpoint
        Json::Value western_path;
        Json::Value western_get;
        western_get["summary"] = "Get Western zodiac sign";
        western_get["parameters"] = Json::Value(Json::arrayValue);
        western_get["parameters"].append(date_param);
        western_path["get"] = western_get;
        paths["/western"] = western_path;
        
        // Bulk operations endpoint
        Json::Value bulk_path;
        Json::Value bulk_post;
        bulk_post["summary"] = "Get zodiac signs for multiple dates";
        bulk_post["requestBody"]["required"] = true;
        bulk_post["requestBody"]["content"]["application/json"]["schema"]["type"] = "array";
        bulk_post["requestBody"]["content"]["application/json"]["schema"]["items"]["type"] = "string";
        bulk_post["requestBody"]["content"]["application/json"]["example"] = Json::Value(Json::arrayValue);
        bulk_post["requestBody"]["content"]["application/json"]["example"].append("01-01-2000");
        bulk_post["requestBody"]["content"]["application/json"]["example"].append("15-06-1995");
        bulk_path["post"] = bulk_post;
        paths["/bulk"] = bulk_path;
        
        // Range endpoint
        Json::Value range_path;
        Json::Value range_get;
        range_get["summary"] = "Get zodiac signs for date range";
        range_get["parameters"] = Json::Value(Json::arrayValue);
        Json::Value start_param = date_param;
        start_param["name"] = "start";
        start_param["description"] = "Start date in DD-MM-YYYY format";
        Json::Value end_param = date_param;
        end_param["name"] = "end";
        end_param["description"] = "End date in DD-MM-YYYY format";
        range_get["parameters"].append(start_param);
        range_get["parameters"].append(end_param);
        range_path["get"] = range_get;
        paths["/range"] = range_path;
        
        // Share endpoint
        Json::Value share_path;
        Json::Value share_post; 
        share_post["summary"] = "Share zodiac result";
        share_post["parameters"] = Json::Value(Json::arrayValue);
        share_post["parameters"].append(date_param);
        share_path["post"] = share_post;
        paths["/share"] = share_path;

        // Logout endpoint
        Json::Value logout_path;
        Json::Value logout_post;
        logout_post["summary"] = "Logout and invalidate session";
        logout_path["post"] = logout_post;
        paths["/logout"] = logout_path;
        
        // Shared result endpoint
        Json::Value shared_path;
        Json::Value shared_get;
        shared_get["summary"] = "Get shared zodiac result";
        shared_get["parameters"] = Json::Value(Json::arrayValue);
        Json::Value share_id_param;
        share_id_param["name"] = "shareId";
        share_id_param["in"] = "path";
        share_id_param["required"] = true;
        share_id_param["schema"]["type"] = "string";
        share_id_param["description"] = "Share ID";
        shared_get["parameters"].append(share_id_param);
        shared_path["get"] = shared_get;
        paths["/shared/{shareId}"] = shared_path;

        // Zodiac Endpoint
        Json::Value zodiac_path;
        Json::Value zodiac_get;
        zodiac_get["summary"] = "Get zodiac sign";
        zodiac_get["parameters"] = Json::Value(Json::arrayValue);
        zodiac_get["parameters"].append(date_param);
        zodiac_path["get"] = zodiac_get;
        paths["/zodiac"] = zodiac_path;
        
        swagger["paths"] = paths;
        
        Json::StreamWriterBuilder builder;
        std::string json_response = Json::writeString(builder, swagger);
        res.set_content(json_response, "application/json");
    });

    // Serve static files (our HTML/JS)
    svr->set_mount_point("/", "./static");

    server_initialized = true;

    std::cout << "HTTPS server starting on port 8080..." << std::endl;
    svr->listen("0.0.0.0", 8080);


    return *svr;
}


// int main() {
//     httplib::SSLServer &svr = get_server();
//     std::cout << "Server starting on port 8080..." << std::endl;
//     svr.listen("0.0.0.0", 8080);
//     return 0;
// }
