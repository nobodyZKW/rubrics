#define CATCH_CONFIG_MAIN
#include "test/catch.hpp"
#include "zodiacs.h"

#include <unordered_map>
#include <unordered_set>
#include <stdexcept>
#include <jsoncpp/json/json.h>
#include <thread>
#include <chrono>
#include <set>
#include <vector>
#include <map>

// Helper function to make HTTP requests
httplib::Result make_request(const std::string& method, const std::string& path, 
                           const std::string& body = "", 
                           const std::map<std::string, std::string>& headers = {},
                           const httplib::Headers& get_headers = {}) {
    httplib::SSLClient cli("localhost", 8080);
    cli.enable_server_certificate_verification(false);
    
    if (method == "GET") {
        return cli.Get(path, get_headers);
    } else if (method == "POST") {
        httplib::Headers request_headers;
        for (const auto& entry : headers) {
            request_headers.insert(entry);
        }
        return cli.Post(path, request_headers, body, "application/json");
    }
    
    return httplib::Result();
}

// Helper function to parse JSON response
Json::Value parse_json_response(const httplib::Result& result) {
    Json::Value root;
    Json::Reader reader;
    auto response = result.value();
    if (response.status == 200 && reader.parse(response.body, root)) {
        return root;
    }
    return Json::Value();
}


// Test setup and teardown
struct TestSetup {
    TestSetup() {
        static bool server_running = false;
        if(!server_running){
            std::thread server_thread(get_server);
            server_thread.detach();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            server_running = true;
        }
    }
};

// Test authentication endpoints
TEST_CASE("Authentication Endpoints", "[Auth]") {
    TestSetup setup;
    
    SECTION("Register New User") {
        Json::Value request;
        request["username"] = "testuser";
        request["password"] = "testpass";
        
        Json::StreamWriterBuilder builder;
        std::string request_body = Json::writeString(builder, request);
        
        auto result = make_request("POST", "/register", request_body);
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json["success"].asBool() == true);
    }
    
    SECTION("Register Duplicate User") {
        Json::Value request;
        request["username"] = "testuser";
        request["password"] = "testpass";
        
        Json::StreamWriterBuilder builder;
        std::string request_body = Json::writeString(builder, request);
        
        auto result = make_request("POST", "/register", request_body);
        auto response = result.value();
        REQUIRE(response.status == 409);
    }
    
    SECTION("Register Missing Fields") {
        Json::Value request;
        request["username"] = "testuser";
        // Missing password
        
        Json::StreamWriterBuilder builder;
        std::string request_body = Json::writeString(builder, request);
        
        auto result = make_request("POST", "/register", request_body);
        auto response = result.value();
        REQUIRE(response.status == 400);
        
    }
    
    SECTION("Login Valid User") {
        Json::Value request;
        request["username"] = "testuser";
        request["password"] = "testpass";
        
        Json::StreamWriterBuilder builder;
        std::string request_body = Json::writeString(builder, request);
        
        auto result = make_request("POST", "/login", request_body);
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json["success"].asBool() == true);
        REQUIRE(response_json["username"].asString() == "testuser");
        REQUIRE(!response_json["session_id"].asString().empty());
    }
    
    SECTION("Login Invalid Credentials") {
        Json::Value request;
        request["username"] = "testuser";
        request["password"] = "wrongpass";
        
        Json::StreamWriterBuilder builder;
        std::string request_body = Json::writeString(builder, request);
        
        auto result = make_request("POST", "/login", request_body);
        auto response = result.value();
        REQUIRE(response.status == 401);
        
    }
    
    SECTION("Login Missing Fields") {
        Json::Value request;
        request["username"] = "testuser";
        // Missing password
        
        Json::StreamWriterBuilder builder;
        std::string request_body = Json::writeString(builder, request);
        
        auto result = make_request("POST", "/login", request_body);
        auto response = result.value();
        REQUIRE(response.status == 400);
        
    }
}

// Test history endpoint
TEST_CASE("History Endpoint", "[History]") {
    TestSetup setup;
    std::string session_id;
    
    SECTION("Get History Without Auth") {
        auto result = make_request("GET", "/history");
        auto response = result.value();
        REQUIRE(response.status == 401);
        
    }
    
    SECTION("Get History With Invalid Session") {
        std::map<std::string, std::string> headers = {{"Authorization", "invalid-session"}};
        auto result = make_request("GET", "/history");
        auto response = result.value();
        REQUIRE(response.status == 401);
    }
    
    SECTION("Get History With Valid Session") {
        // First login to get session
        Json::Value login_request;
        login_request["username"] = "testuser";
        login_request["password"] = "testpass";
        
        Json::StreamWriterBuilder builder;
        std::string login_body = Json::writeString(builder, login_request);
        
        auto login_result = make_request("POST", "/login", login_body);
        auto login_response = login_result.value();
        REQUIRE(login_response.status == 200);
        
        Json::Value login_response_json = parse_json_response(login_result);
        session_id = login_response_json["session_id"].asString();


        // Now get history
        httplib::Headers headers = {{"Authorization", session_id}};
        auto result = make_request("GET", "/history", "", {}, headers);
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json.isArray());
    }
}

// Test combined zodiac endpoint
TEST_CASE("Combined Zodiac Endpoint", "[Zodiac]") {
    TestSetup setup;
    
    SECTION("Get Combined Zodiac Valid Date") {
        auto result = make_request("GET", "/zodiac?date=15-06-1995");
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json["chinese_zodiac"].asString() == "Pig");
        REQUIRE(response_json["western_zodiac"].asString() == "Gemini");
    }
    
    SECTION("Get Combined Zodiac Invalid Date") {
        auto result = make_request("GET", "/zodiac?date=invalid-date");
        auto response = result.value();
        REQUIRE(response.status == 400);
        
    }
    
    SECTION("Get Combined Zodiac Missing Date") {
        auto result = make_request("GET", "/zodiac");
        auto response = result.value();
        REQUIRE(response.status == 400);
        
    }
    
    SECTION("Get Combined Zodiac With Auth") {
        // Login first
        Json::Value login_request;
        login_request["username"] = "testuser";
        login_request["password"] = "testpass";
        
        Json::StreamWriterBuilder builder;
        std::string login_body = Json::writeString(builder, login_request);
        
        auto login_result = make_request("POST", "/login", login_body);
        auto login_response = login_result.value();
        REQUIRE(login_response.status == 200);
        
        Json::Value login_response_json = parse_json_response(login_result);
        std::string session_id = login_response_json["session_id"].asString();
        
        // Get zodiac with auth
        std::map<std::string, std::string> headers = {{"Authorization", session_id}};
        auto result = make_request("GET", "/zodiac?date=15-06-1995");
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json["chinese_zodiac"].asString() == "Pig");
        REQUIRE(response_json["western_zodiac"].asString() == "Gemini");

        httplib::Headers get_headers = {{"Authorization", session_id}};
        
        // Check that history was added
        auto history_result = make_request("GET", "/history", "", {}, get_headers);
        auto history_response = history_result.value();
        REQUIRE(history_response.status == 200);
        
        Json::Value history_response_json = parse_json_response(history_result);
        REQUIRE(history_response_json.isArray());
    }
}

// Test bulk operations endpoint
TEST_CASE("Bulk Operations Endpoint", "[Bulk]") {
    TestSetup setup;
    
    SECTION("Bulk Operations Valid Dates") {
        std::string request_body = "[\"01-01-2000\", \"15-06-1995\", \"31-12-2020\"]";
        
        auto result = make_request("POST", "/bulk", request_body);
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json["total_processed"].asInt() == 3);
        REQUIRE(response_json["results"].isArray());
        REQUIRE(response_json["results"].size() == 3);
        
        // Check first result
        Json::Value first_result = response_json["results"][0];
        REQUIRE(first_result["date"].asString() == "01-01-2000");
        REQUIRE(first_result["success"].asBool() == true);
        REQUIRE(first_result["chinese_zodiac"].asString() == "Rabbit");
        REQUIRE(first_result["western_zodiac"].asString() == "Capricorn");
    }
    
    SECTION("Bulk Operations With Invalid Dates") {
        std::string request_body = "[\"01-01-2000\", \"invalid-date\", \"31-12-2020\"]";
        
        auto result = make_request("POST", "/bulk", request_body);
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json["total_processed"].asInt() == 3);
        REQUIRE(response_json["results"].isArray());
        REQUIRE(response_json["results"].size() == 3);
        
        // Check that invalid date has error
        Json::Value invalid_result = response_json["results"][1];
        REQUIRE(invalid_result["date"].asString() == "invalid-date");
        REQUIRE(invalid_result["success"].asBool() == false);
        REQUIRE(!invalid_result["error"].asString().empty());
    }
    
    SECTION("Bulk Operations Empty Array") {
        std::string request_body = "[]";
        
        auto result = make_request("POST", "/bulk", request_body);
        auto response = result.value();
        REQUIRE(response.status == 400);
        
    }
    
    SECTION("Bulk Operations Too Many Dates") {
        std::string request_body = "[";
        for (int i = 0; i < 101; ++i) {
            if (i > 0) request_body += ",";
            request_body += "\"01-01-2000\"";
        }
        request_body += "]";
        
        auto result = make_request("POST", "/bulk", request_body);
        auto response = result.value();
        REQUIRE(response.status == 400);
        
    }
    
    SECTION("Bulk Operations Invalid JSON") {
        std::string request_body = "invalid json";
        
        auto result = make_request("POST", "/bulk", request_body);
        auto response = result.value();
        REQUIRE(response.status == 400);
        
    }
}

// Test date range endpoint
TEST_CASE("Date Range Endpoint", "[Range]") {
    TestSetup setup;
    
    SECTION("Date Range Valid Range") {
        auto result = make_request("GET", "/range?start=01-01-2020&end=05-01-2020");
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json["total_dates"].asInt() == 5);
        REQUIRE(response_json["date_range"]["start"].asString() == "01-01-2020");
        REQUIRE(response_json["date_range"]["end"].asString() == "05-01-2020");
        REQUIRE(response_json["results"].isArray());
        REQUIRE(response_json["results"].size() == 5);
        
        // Check first result
        Json::Value first_result = response_json["results"][0];
        REQUIRE(first_result["date"].asString() == "01-01-2020");
        REQUIRE(first_result["success"].asBool() == true);
        REQUIRE(first_result["chinese_zodiac"].asString() == "Pig");
        REQUIRE(first_result["western_zodiac"].asString() == "Capricorn");
    }
    
    SECTION("Date Range Missing Parameters") {
        auto result = make_request("GET", "/range?start=01-01-2020");
        auto response = result.value();
        REQUIRE(response.status == 400);
        
    }
    
    SECTION("Date Range Invalid Dates") {
        auto result = make_request("GET", "/range?start=invalid&end=also-invalid");
        auto response = result.value();
        REQUIRE(response.status == 400);
        
    }
    
    SECTION("Date Range Large Range") {
        auto result = make_request("GET", "/range?start=01-01-2020&end=01-01-2021");
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json["total_dates"].asInt() == 366);
    }
}

// Test share endpoints
TEST_CASE("Share Endpoints", "[Share]") {
    TestSetup setup;
    
    SECTION("Share Valid Date") {
        Json::Value request;
        request["date"] = "15-06-1995";
        
        Json::StreamWriterBuilder builder;
        std::string request_body = Json::writeString(builder, request);
        
        auto result = make_request("POST", "/share", request_body);
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(!response_json["share_id"].asString().empty());
        REQUIRE(response_json["share_url"].asString().find("/shared/") != std::string::npos);
        REQUIRE(response_json["result"]["chinese_zodiac"].asString() == "Pig");
        REQUIRE(response_json["result"]["western_zodiac"].asString() == "Gemini");
    }
    
    SECTION("Share Invalid Date") {
        Json::Value request;
        request["date"] = "invalid-date";
        
        Json::StreamWriterBuilder builder;
        std::string request_body = Json::writeString(builder, request);
        
        auto result = make_request("POST", "/share", request_body);
        auto response = result.value();
        REQUIRE(response.status == 400);
        
    }
    
    SECTION("Share Missing Date") {
        Json::Value request;
        // Missing date
        
        Json::StreamWriterBuilder builder;
        std::string request_body = Json::writeString(builder, request);
        
        auto result = make_request("POST", "/share", request_body);
        auto response = result.value();
        REQUIRE(response.status == 400);
        
    }
    
    SECTION("Get Shared Result Valid ID") {
        // First share a result
        Json::Value share_request;
        share_request["date"] = "15-06-1995";
        
        Json::StreamWriterBuilder builder;
        std::string share_body = Json::writeString(builder, share_request);
        
        auto share_result = make_request("POST", "/share", share_body);
        auto share_response = share_result.value();
        REQUIRE(share_response.status == 200);
        
        Json::Value share_response_json = parse_json_response(share_result);
        std::string share_id = share_response_json["share_id"].asString();

        std::string share_url = "/shared/" + share_id;
        
        // Now get the shared result
        auto result = make_request("GET", share_url);
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json["date"].asString() == "15-06-1995");
        REQUIRE(response_json["chinese_zodiac"].asString() == "Pig");
        REQUIRE(response_json["western_zodiac"].asString() == "Gemini");
    }
    
    SECTION("Get Shared Result Invalid ID") {
        auto result = make_request("GET", "/shared/invalid-id");
        auto response = result.value();
        REQUIRE(response.status == 404);
    
    }
}

// Test API documentation endpoint
TEST_CASE("API Documentation Endpoint", "[Docs]") {
    TestSetup setup;
    
    SECTION("Get API Documentation") {
        auto result = make_request("GET", "/api-docs");
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json["openapi"].asString() == "3.0.0");
        REQUIRE(response_json["info"]["title"].asString() == "Zodiac Calculator API");
        REQUIRE(response_json["info"]["version"].asString() == "1.0.0");
        REQUIRE(response_json["paths"].isObject());
        
        // Check that all expected endpoints are documented
        REQUIRE(response_json["paths"].isMember("/chinese"));
        REQUIRE(response_json["paths"].isMember("/western"));
        REQUIRE(response_json["paths"].isMember("/zodiac"));
        REQUIRE(response_json["paths"].isMember("/bulk"));
        REQUIRE(response_json["paths"].isMember("/range"));
        REQUIRE(response_json["paths"].isMember("/share"));
        REQUIRE(response_json["paths"].isMember("/shared/{shareId}"));
    }
}

// Test individual zodiac endpoints with auth
TEST_CASE("Individual Zodiac Endpoints With Auth", "[ZodiacAuth]") {
    TestSetup setup;
    std::string session_id;
    
    SECTION("Setup Auth") {
        // Login to get session
        Json::Value login_request;
        login_request["username"] = "testuser";
        login_request["password"] = "testpass";
        
        Json::StreamWriterBuilder builder;
        std::string login_body = Json::writeString(builder, login_request);
        
        auto login_result = make_request("POST", "/login", login_body);
        auto login_response = login_result.value();
        REQUIRE(login_response.status == 200);
        
        Json::Value login_response_json = parse_json_response(login_result);
        session_id = login_response_json["session_id"].asString();
    }
    
    SECTION("Chinese Zodiac With Auth") {
        std::map<std::string, std::string> headers = {{"Authorization", session_id}};
        auto result = make_request("GET", "/chinese?date=15-06-1995");
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json["zodiac"].asString() == "Pig");
    }
    
    SECTION("Western Zodiac With Auth") {
        std::map<std::string, std::string> headers = {{"Authorization", session_id}};
        auto result = make_request("GET", "/western?date=15-06-1995");
        auto response = result.value();
        REQUIRE(response.status == 200);
        
        Json::Value response_json = parse_json_response(result);
        REQUIRE(response_json["zodiac"].asString() == "Gemini");
    }
}

// Test error handling
TEST_CASE("Error Handling", "[Errors]") {
    TestSetup setup;
    
    SECTION("Invalid JSON in POST requests") {
        std::string invalid_json = "{ invalid json }";
        
        auto result = make_request("POST", "/login", invalid_json);
        auto response = result.value();
        REQUIRE(response.status == 400);
        
    }
    
    SECTION("Non-existent endpoints") {
        auto result = make_request("GET", "/nonexistent");
        auto response = result.value();
        REQUIRE(response.status == 404);
    }
    
    SECTION("Method not allowed") {
        auto result = make_request("POST", "/chinese");
        auto response = result.value();
        REQUIRE(response.status == 404); // Should return 404 for POST to GET endpoint
    }
}

// Test concurrent access
TEST_CASE("Concurrent Access", "[Concurrency]") {
    TestSetup setup;
    
    SECTION("Multiple Users Accessing Same Endpoint") {
        std::vector<std::thread> threads;
        std::vector<int> results;
        
        for (int i = 0; i < 10; ++i) {
            threads.emplace_back([&results, i]() {
                auto result = make_request("GET", "/zodiac?date=15-06-1995");
                auto response = result.value();
                results.push_back(response.status);
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
        
        // All requests should succeed
        for (int status : results) {
            REQUIRE(status == 200);
        }
    }
    const char* user_file = "users.json";
    if(std::remove(user_file) != 0){
        std::cerr << "Error deleting user file: " << std::strerror(errno) << std::endl;
    }
    else{
        std::cout << "User file deleted" << std::endl;
    }
}

TEST_CASE("Chinese Tests", "[Chinese]"){

    std::unordered_map<std::string, std::string> test_all_zodiacs = {{"Rat", "30-06-2008"},
            {"Ox", "30-06-2009"},
            {"Tiger", "30-06-2010"},
            {"Rabbit", "30-06-2011"},
            {"Dragon", "30-06-2012"},
            {"Snake", "30-06-2013"},
            {"Horse", "30-06-2014"},
            {"Sheep", "30-06-2015"},
            {"Monkey", "30-06-2016"},
            {"Rooster", "30-06-2017"},
            {"Dog", "30-06-2018"},
            {"Pig", "30-06-2019"}
        };
    
    SECTION("Test All"){
        for(auto [animal, date] : test_all_zodiacs){
            REQUIRE(get_chinese_zodiac(date) == animal);
        }
    }
    
    SECTION("Test January"){
        std::unordered_map<std::string, std::string> test_jan = {
            {"Ox", "01-01-2022"},
            {"Tiger", "01-01-2023"},
            {"Rabbit", "01-01-2024"}
        };

        for(auto [animal, date] : test_jan){
            REQUIRE(get_chinese_zodiac(date) == animal);
        }
    }

    SECTION("Test Before Lunar New Year"){
        std::unordered_map<std::string, std::string> test_before = {
            {"Rooster", "05-02-1970"},
            {"Dog", "26-01-1971"},
            {"Pig", "14-02-1972"}
        };

        for(auto [animal,date] : test_before){
            REQUIRE(get_chinese_zodiac(date) == animal);
        }
    }

    SECTION("Test Lunar New Year"){
        std::unordered_map<std::string, std::string> test_lunar = {
            {"Dog", "06-02-1970"},
            {"Pig", "27-01-1971"},
            {"Rat", "15-02-1972"}
        };
        for(auto [animal,date] : test_lunar){
            REQUIRE(get_chinese_zodiac(date) == animal);
        }
    }

    SECTION("Test Chinese Leap Years"){
        std::unordered_map<std::string, std::string> test_leap = {
            {"Dragon", "29-02-2000"},
            {"Monkey", "29-02-2004"},
            {"Monkey", "29-02-2016"}
        };

        for(auto [animal,date] : test_leap){
            REQUIRE(get_chinese_zodiac(date) == animal);
        }
    }

    SECTION("Test Chinese Date Range Limits"){
        std::unordered_map<std::string, std::string> test_date_limits = {
            {"Horse", "30-01-1930"},
            {"Dog", "22-01-2031"}
        }; 

        for(auto [animal, date] : test_date_limits){
            REQUIRE(get_chinese_zodiac(date) == animal);
        }
    }

    SECTION("Test Invalid Dates"){
        std::unordered_set<std::string> test_invalid_dates = 
            {"29-01-1930",  // Before supported range
            "23-01-2031",  //After supported range
            "31-06-2008",  //Invalid end of month
            "01-13-2025",  //Invalid month
            "00-01-2000",  //Invalid day
            "29-02-2013",  //Invalid leap year
            "2023-01-01",
            "30/01/1989",
            "not-a-date",
            "",
            " ",
            "-30-01-1954"
        };

        for(auto date : test_invalid_dates){
            REQUIRE_THROWS_AS(get_chinese_zodiac(date), std::invalid_argument);
        }
    }

    SECTION("Test Near Chinese New Year"){
        std::unordered_map<std::string, std::string> test_near_new_year = {
            {"Dragon", "28-01-2025"},
            {"Snake", "30-01-2025"},
            {"Snake", "29-01-2025"}
        };

        for(auto [animal,date] : test_near_new_year){
            REQUIRE(get_chinese_zodiac(date) == animal);
        }
    }
}

TEST_CASE("Western Tests","[Western]"){
    SECTION("Test All"){
        std::unordered_map<std::string, std::string> test_all = {
            {"Aries", "01-04-1960"},
            {"Taurus", "01-05-1960"},
            {"Gemini", "01-06-1960"},
            {"Cancer", "01-07-1960"},
            {"Leo", "01-08-1960"},
            {"Virgo", "01-09-1960"},
            {"Libra", "01-10-1960"},
            {"Scorpio", "01-11-1960"},
            {"Sagittarius", "01-12-1960"},
            {"Capricorn", "01-01-1960"},
            {"Aquarius", "01-02-1960"},
            {"Pisces", "01-03-1960"}
        };

        for(auto [sign, date] : test_all){
            REQUIRE(get_western_zodiac(date) == sign);
        }
    }

    SECTION("Test Start Dates"){
        std::unordered_map<std::string, std::string> test_start = {
            {"Aries", "21-03-1999"},
            {"Taurus", "20-04-1999"},
            {"Gemini", "21-05-1999"},
            {"Cancer", "22-06-1999"},
            {"Leo", "23-07-1999"},
            {"Virgo", "23-08-1999"},
            {"Libra", "23-09-1999"},
            {"Scorpio", "24-10-1999"},
            {"Sagittarius", "23-11-1999"},
            {"Capricorn", "23-12-1999"},
            {"Aquarius", "23-01-2000"},
            {"Pisces", "23-02-2000"}
        };

        for(auto [sign, date] : test_start){
            REQUIRE(get_western_zodiac(date) == sign);
        }
    }

    SECTION("Test End Dates"){
        std::unordered_map<std::string, std::string> test_end = {
            {"Aries", "19-04-1999"},
            {"Taurus", "20-05-1999"},
            {"Gemini", "21-06-1999"},
            {"Cancer", "22-07-1999"},
            {"Leo", "22-08-1999"},
            {"Virgo", "22-09-1999"},
            {"Libra", "23-10-1999"},
            {"Scorpio", "21-11-1999"},
            {"Sagittarius", "21-12-1999"},
            {"Capricorn", "19-01-1999"},
            {"Aquarius", "18-02-2000"},
            {"Pisces", "20-03-2000"}
        };

        for(auto [sign, date] : test_end){
            REQUIRE(get_western_zodiac(date) == sign);
        }
    }

    SECTION("Test Leap Years"){
        std::unordered_map<std::string, std::string> test_leap = {
            {"Pisces", "29-02-2000"},
            {"Pisces", "29-02-2004"},
            {"Pisces", "29-02-2016"}
        };

        for(auto [sign, date] : test_leap){
            REQUIRE(get_western_zodiac(date) == sign);
        }

    }

    SECTION("Test Date Range Limits"){
        std::unordered_map<std::string, std::string> test_range_limits = {
            {"Aquarius", "30-01-1930"},
            {"Aquarius", "22-01-2031"}
        };

        for(auto [sign, date] : test_range_limits){
            REQUIRE(get_western_zodiac(date) == sign);
        }
    }

    SECTION("Test Invalid Dates"){
        std::unordered_set<std::string> test_invalid_dates = {
            "29-01-1930",  //# Before supported range
            "23-01-2031",  //# After supported range
            "31-06-2008",  //# Invalid end of month
            "01-13-2025",  //# Invalid month
            "00-01-2000",  //# Invalid day
            "29-02-2013",  //# Invalid leap year
            "2023-01-01",
            "30/01/1989",
            "not-a-date",
            "",
            " ",
            "-30-01-1954"
        };

        for(auto date : test_invalid_dates){
            REQUIRE_THROWS_AS(get_western_zodiac(date), std::invalid_argument);
        }
    }

    
}

// Test helper functions that can be tested directly
TEST_CASE("Helper Functions", "[Helpers]") {
    SECTION("Parse Date Array") {
        // Test valid JSON array
        std::string valid_json = "[\"01-01-2000\", \"15-06-1995\", \"31-12-2020\"]";
        // Note: parse_date_array is not exposed in header, so we can't test it directly
        // This would need to be moved to the header file or tested through the bulk endpoint
        
        // Test invalid JSON
        std::string invalid_json = "not json";
        // Should return empty vector
        
        // Test empty array
        std::string empty_json = "[]";
        // Should return empty vector
    }
    
    SECTION("Generate Date Range") {
        // Test valid date range
        std::string start_date = "01-01-2020";
        std::string end_date = "05-01-2020";
        // Should return 5 dates
        
        // Test invalid date range
        std::string invalid_start = "invalid";
        std::string invalid_end = "also-invalid";
        // Should return empty vector
        
        // Test large date range (should be limited)
        std::string large_start = "01-01-2020";
        std::string large_end = "01-01-2021";
        // Should return limited number of dates (max 366)
    }
    
    SECTION("Generate Share ID") {
        // Test that share IDs are unique
        std::set<std::string> share_ids;
        for (int i = 0; i < 100; ++i) {
            std::string id = generate_share_id(); // Not exposed in header
            share_ids.insert(id);
        }
        REQUIRE(share_ids.size() == 100); // All should be unique
    }
}
