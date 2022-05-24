#pragma once

#include <unordered_map>
#include <string>
#include <vector>

namespace jwtverifier {

    // Jwk struct wraps parameters of a JSON Web Key (JWK), received from MAA service.
    // JWK is a JavaScript Object Notation (JSON) data structure 
    // that represents a cryptographic key.
    // See the spec https://tools.ietf.org/html/rfc7517
    struct Jwk {

        // The "kid" (key ID) parameter is used to match a specific key.
        // See section-4.5 of RFC7517 https://tools.ietf.org/html/rfc7517#section-4.5
        std::string kid;
        
        // The "kty" (key type) parameter identifies the cryptographic 
        // algorithm family used with the key, such as "RSA" or "EC".
        // See section-4.1 of RFC7517 https://tools.ietf.org/html/rfc7517#section-4.1
        std::string kty;

        // The "x5c" (X.509 certificate chain) parameter contains a chain of one
        //    or more PKIX certificates.
        // See section-4.7 of RFC7517 https://tools.ietf.org/html/rfc7517#section-4.7
        // See also X.509 spec RFC5280 https://tools.ietf.org/html/rfc5280
        std::vector<std::string> x5c;
        
        Jwk() {}
        explicit Jwk(const std::string& str);        
    };

    class Jwks {
        std::unordered_map<std::string, Jwk> keys_;

    public:
        explicit Jwks(const std::string& keys_str);
        bool get_certs(const std::string& key, std::vector<std::string>& certs) const;
    };

}
