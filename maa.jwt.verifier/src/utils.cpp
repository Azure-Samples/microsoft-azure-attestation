#include <utils.hpp>

#include <context.hpp>
#include <regex>
#include <iostream>
#include <fstream>

namespace jwtverifier::json {

    std::string get_value(const std::string& str, const std::string& key) {
        if (str.empty()) {
            Context::log("Input string is empty, cannot get value for key " + key);
            return "";
        }
        std::regex rgx(".*" + key + "[ \n\r]*\"[ \n\r]*:[ \n\r]*\"[ \n\r]*([^\"]*)");
        std::smatch match;
        std::string result = (std::regex_search(str.begin(), str.end(), match, rgx)) ? std::string(match[1]) : "";
        return result;
    }

    std::vector<std::string> get_array(const std::string& str, const std::string& key) {
        if (str.empty()) {
            Context::log("Input string is empty, cannot get array of value for key " + key);
            return std::vector<std::string>();
        }
        std::regex rgx(".*" + key + "[ \n\r]*\"[ \n\r]*:[ \n\r]*[[ \n\r]*([^\\]]*)");
        std::smatch match;
        std::string values = (std::regex_search(str.begin(), str.end(), match, rgx)) ? std::string(match[1]) : "";
        strings::remove_char(values, '"');
        std::vector<std::string> result;
        jwtverifier::strings::split(values, ",", result);
        return result;
    }
}

namespace jwtverifier::strings {

    void split(const std::string& str, const std::string& delim, std::vector<std::string>& result) {
        std::regex regex(delim);
        result = std::vector<std::string>(std::sregex_token_iterator(str.begin(), str.end(), regex, -1), std::sregex_token_iterator());
    }

    void remove_char(std::string& str, char c) {
        str.erase(std::remove(str.begin(), str.end(), c), str.end());
    }

    void remove_spaces(std::string& str) {
        str.erase(remove_if(str.begin(), str.end(), isspace), str.end());
    }

    void tolower(std::string& in) {
        std::transform(in.begin(), in.end(), in.begin(), [](int c) { return static_cast<char>(std::tolower(c)); });
    }

}

namespace jwtverifier::file {
    bool get_lines(const std::string& filename, std::vector<std::string>& out) {
        if (filename.empty()) {
            Context::log("Faile name is empty, exiting");
            return false;
        }
        out.clear();
        std::ifstream infile;
        infile.open(filename);
        if (infile) {
            while (!infile.eof())
            {
                std::string line;
                getline(infile, line);
                out.push_back(line);
            }
            infile.close();
            if (out.empty()) {
                Context::log("Could not find any record in file: " + filename);
                return false;
            }
        }
        else {
            Context::log("Failed to open file: " + filename);
            return false;
        }
        return true;
    }
}
