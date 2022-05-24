#pragma once

#include <string>
#include <curl/curl.h>

namespace jwtverifier {

    class Curl {
        CURL* curl_;

    public:
        Curl();
        ~Curl();
        std::string get(const std::string& url, const std::string& headers = "");
    };

}
