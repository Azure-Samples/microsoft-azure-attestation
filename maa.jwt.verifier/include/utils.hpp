#pragma once

#include <string>
#include <vector>

namespace mvj::json {
    std::string get_value(const std::string& str, const std::string& key);    
    std::vector<std::string> get_array(const std::string& str, const std::string& key);
}

namespace mvj::strings {
    void split(const std::string& str, const std::string& delim, std::vector<std::string>& result);
    void remove_char(std::string& str, char c);
    void remove_spaces(std::string& str);
    void tolower(std::string& in);
}

namespace mvj::file {
    bool get_lines(const std::string& filename, std::vector<std::string>& out);
}
