#pragma once

#include <string>

namespace jwtverifier {

    class Jwt {
        std::string encoded_token_;

        std::string encoded_header_;
        std::string encoded_payload_;
        std::string encoded_signature_;

        std::string decoded_header_;
        std::string decoded_payload_;

        std::string jku_;
        std::string kid_;
        std::string attest_dns_;
        std::string tenant_;

    public:
        Jwt();
        bool deserialize(const std::string& token);

        std::string get_jku() const;
        std::string get_tenant() const;
        std::string get_kid() const;

    private:
        std::string parse_dns() const;
        std::string parse_tenant() const;
        std::string decode(const std::string& data) const;
    };

}
