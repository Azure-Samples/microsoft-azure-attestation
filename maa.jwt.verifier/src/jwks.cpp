#include <jwks.hpp>

#include <utils.hpp>
#include <context.hpp>
#include <regex>

namespace jwtverifier {

    Jwk::Jwk(const std::string& str) : kid(), kty(), x5c() {
        kid = json::get_value(str, "kid");
        kty = json::get_value(str, "kty");
        x5c = json::get_array(str, "x5c");
    }

    Jwks::Jwks(const std::string& str) {
        std::vector<std::string> raw_keys;
        jwtverifier::strings::split(str, "\\}[ \n\r]*,", raw_keys);
        for (auto raw_key : raw_keys) {
            Jwk key(raw_key);
            keys_[key.kid] = key;
        }
    }
    
    bool Jwks::get_certs(const std::string& key, std::vector<std::string>& certs) const {
        certs.clear();
        auto it = keys_.find(key);
        if (it != keys_.end()) {
            certs = it->second.x5c;
            return true;
        }
        else {
            Context::log("Could not find key: " + key);
            return false;
        }
    }

}
