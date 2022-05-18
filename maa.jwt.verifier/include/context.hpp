#pragma once

#include <string>
#include <vector>
#include <iostream>

namespace mvj {

    class Context {
        bool is_verbose_;
        std::string jwt_filename_;
        Context();

    public:

        static Context& instance() {
            static Context instance_;
            return instance_;
        }

        template <typename T = std::string>
        static void log(const T& v) {
            if (Context::instance().is_verbose()) std::cout << v << std::endl;
        }
        static void always_log(const std::string& message);

        void set(const std::vector<std::string>& args);
        void dump() const;
        bool is_verbose() const;
        const std::string& get_jwt_filename() const;

    private:
        void set_verbose(const std::string& v);
        void set_jwt_filename(const std::string& v);
        void help_and_exit(const std::string& v = "");
        void reset();
    };
}
