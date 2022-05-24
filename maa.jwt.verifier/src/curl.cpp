#include <curl.hpp>

#include <context.hpp>
#include <cstdlib>
#include <cstring>

namespace jwtverifier {
    
    struct MemoryChunk {
        char* memory;
        size_t size;
        MemoryChunk() {
            memory = (char*)malloc(1); // will be grown as needed by the realloc above
            size = 0; // no data at this point
        }
        ~MemoryChunk() {
            free(memory);
        }
    };

    static size_t write_cb(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t realsize = size * nmemb;
        struct MemoryChunk* mem = (struct MemoryChunk*)userp;
        char* ptr = (char*)realloc(mem->memory, mem->size + realsize + 1);
        if (ptr == nullptr) {
            Context::log("Failed to allocate memory, realloc returned NULL, not enough memory");
            return 0;
        }
        mem->memory = ptr;
        memcpy(&(mem->memory[mem->size]), contents, realsize);
        mem->size += realsize;
        mem->memory[mem->size] = 0;
        return realsize;
    }

    Curl::Curl(): curl_(nullptr) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    Curl::~Curl() {
        curl_global_cleanup();
    }

    std::string Curl::get(const std::string& url, const std::string& headers) {
        if (url.empty()) {
            Context::log("Failed to send get request, input url is empty");
            return "";
        }
        if (curl_ != nullptr) {
            curl_easy_cleanup(curl_);
            curl_ = nullptr;
        }

        MemoryChunk chunk;
        curl_ = curl_easy_init();
        std::string response = "";
        if (curl_ != nullptr) {
            curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
            
            // Headers 
            struct curl_slist* header_list = nullptr;
            if (!headers.empty()) {
                header_list = curl_slist_append(header_list, headers.c_str());
                curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, header_list);
            }

            // Verbose
            if (Context::instance().is_verbose()) {
                curl_easy_setopt(curl_, CURLOPT_VERBOSE, 1L);
            }

            // Options
            curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, 1L); // [required] follow HTTP 3xx redirects
            curl_easy_setopt(curl_, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2); // [required] MAA supports only TLSv1.2
            curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L); // [per system] Do not verify the peer's SSL certificate
            curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_cb); // [required] send all data to this function
            curl_easy_setopt(curl_, CURLOPT_WRITEDATA, (void*)&chunk); // [required] we pass our 'chunk' struct to the callback function

            CURLcode res = curl_easy_perform(curl_);
            if (CURLE_OK != res) {
                Context::log("curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
            }
            else {
                Context::log("Received " + std::to_string(chunk.size) + " bytes");
                response = std::string(chunk.memory);
            }
            curl_easy_cleanup(curl_);
            curl_slist_free_all(header_list);
        }
        return response;
    }
}
