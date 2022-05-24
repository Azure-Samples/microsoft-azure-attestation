#include <context.hpp>
#include <utils.hpp>

#include <functional>
#include <chrono>
#include <unordered_map>

namespace jwtverifier {

    typedef void (Context::* ContextMemFn)(const std::string&);

    Context::Context() {
        this->is_verbose_ = false;
        this->jwt_filename_ = "";
    }

    void Context::always_log(const std::string& message) {
        std::cout << "---\t" << message << std::endl;
    }

    void Context::set(const std::vector<std::string>& args) {
        const size_t sz = args.size();
        if (sz < 2) {
            this->help_and_exit();
        }

        this->reset();
        const std::unordered_map<std::string, ContextMemFn> opt_setters({
            {"-v", &Context::set_verbose},
            {"--verbose", &Context::set_verbose},
            {"-h", &Context::help_and_exit},
            {"--help", &Context::help_and_exit}
        });

        for (size_t i = 1; i < sz; ++i) {
            std::string arg = args[i];
            strings::tolower(arg);

            auto opt_it = opt_setters.find(arg);
            if (opt_it != opt_setters.end()) {
                std::invoke(opt_it->second, this, "");
                continue;
            }

            if (this->jwt_filename_.empty()) {
                this->jwt_filename_ = args[i];
                continue;
            }

            this->help_and_exit();
        }
    }

    void Context::dump() const {
        if (this->is_verbose_) {
            std::cout << std::endl << "Arguments for this run:" << std::endl;
            std::cout << '\t' << "jwt_filename " << '\t' << ":" << '\t' << this->jwt_filename_ << std::endl;
        }
    }

    bool Context::is_verbose() const { return this->is_verbose_; }
    const std::string& Context::get_jwt_filename() const { return this->jwt_filename_; }

    void Context::set_verbose(const std::string&) { this->is_verbose_ = true; }
    void Context::set_jwt_filename(const std::string& v) { this->jwt_filename_ = v; }

    void Context::help_and_exit(const std::string&) {
        std::cout << std::endl;
        std::cout << "Usage: jwt_varifier [options] file" << std::endl;
        std::cout << std::endl;
        std::cout << "Arguments:" << std::endl;
        std::cout << "    -v or --verbose          Include verbose messages" << std::endl;
        std::cout << "    -h or --help             Print Help (this message) and exit" << std::endl;
        std::cout << std::endl;
        exit(EXIT_SUCCESS);
    }

    void Context::reset() {
        this->is_verbose_ = false;
        this->jwt_filename_.clear();
    }
}
