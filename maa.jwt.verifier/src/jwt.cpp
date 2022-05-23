#include <jwt.hpp>

#include <utils.hpp>
#include <context.hpp>
#include <base64.hpp>
#include <regex>

namespace jwtverifier {

    Jwt::Jwt() {}
        
    bool Jwt::deserialize(const std::string& token) {
        try {
            encoded_token_ = token;
            std::vector<std::string> hps; 
            strings::split(token, "\\.", hps);
    
            if (hps.size() != 3) {
                throw std::runtime_error("Invalid token!");
            }
            encoded_header_ = hps[0];
            encoded_payload_ = hps[1];
            encoded_signature_ = hps[2];
    
            decoded_header_ = decode(encoded_header_);
            decoded_payload_ = decode(encoded_payload_);
    
            jku_ = json::get_value(decoded_header_, "jku");
            kid_ = json::get_value(decoded_header_, "kid");
            attest_dns_ = parse_dns();
            tenant_ = parse_tenant();
        }
        catch (const std::exception& ex) {
            Context::log("Failed to deserialize JWT, exception: " + std::string(ex.what()));
            return false;
        }
        catch (const std::string& ex) {
            Context::log("Failed to deserialize JWT, exception: " + ex);
            return false;
        }
        catch (...) {
            Context::log("Failed to deserialize JWT");
            return false;
        }
        return true;
    }

    std::string Jwt::get_jku() const { return jku_; }
    std::string Jwt::get_tenant() const { return tenant_; }
    std::string Jwt::get_kid() const { return kid_; }

    std::string Jwt::parse_dns() const {
        if (decoded_header_.empty()) {
            Context::log("Empty decoded JWT header, cannot retrieve attest DNS");
            return "";
        }
        std::regex rgx("https://([0-9a-zA-Z.]*)");
        std::smatch match;
        std::string result = (std::regex_search(decoded_header_.begin(), decoded_header_.end(), match, rgx)) ? std::string(match[1]) : "";
        return result;
    }

    std::string Jwt::parse_tenant() const {
        if (attest_dns_.empty()) {
            Context::log("Empty attest DNS, cannot retrieve tenant name");
            return "";
        }
        std::string result = attest_dns_.substr(0, attest_dns_.find_first_of("."));
        return result;
    }

    std::string Jwt::decode(const std::string& data) const {
        std::string uri_dec(data);
        const size_t sz = data.size();
        const size_t padding = 4 * static_cast<size_t>(sz % 4 != 0) - (sz % 4);
        uri_dec.resize(sz + padding, '=');
        auto decoded = base64::decode(uri_dec);
        std::string decoded_str(decoded.begin(), decoded.end());
        return decoded_str;
    }
}
