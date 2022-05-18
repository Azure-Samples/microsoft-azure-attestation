cmake_minimum_required(VERSION 3.10.0)

if(CMAKE_HOST_WIN32)
    set(WINDOWS 1)
elseif(CMAKE_HOST_UNIX)
    set(LINUX 1)
endif()

if(WINDOWS)
    set(VCPKG_TARGET_TRIPLET "x64-windows" CACHE STRING "")
elseif(LUNUX)
    set(VCPKG_TARGET_TRIPLET "x64-linux" CACHE STRING "")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(jwt-verifier LANGUAGES CXX)

set(COMPONENT "OEHOSTVERIFY")

set(SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/src/base64.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/context.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/curl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/jwks.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/jwt.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/utils.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/x509.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
)

set(HEADERS
	${CMAKE_CURRENT_SOURCE_DIR}/include/base64.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/context.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/curl.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/jwks.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/jwt.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/utils.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/x509.hpp
)

set(OPENSSL_USE_STATIC_LIBS TRUE)
 
find_package(OpenEnclave CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
if(WINDOWS)
    find_package(CURL CONFIG REQUIRED)
endif()

add_executable(jwt-verifier ${SOURCES} ${HEADERS})

target_link_libraries(jwt-verifier PRIVATE openenclave::oehostverify)
target_link_libraries(jwt-verifier PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(WINDOWS)
    target_link_libraries(jwt-verifier PRIVATE CURL::libcurl)
    target_include_directories(jwt-verifier PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT jwt-verifier)
    target_compile_options(jwt-verifier PRIVATE /W4 /WX)
elseif(LINUX)
    target_link_libraries(jwt-verifier PRIVATE curl)
    target_include_directories(jwt-verifier PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_options(jwt-verifier PRIVATE -Wall -Wextra -pedantic -Werror)
endif()
