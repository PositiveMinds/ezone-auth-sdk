include(FetchContent)

# cpp-httplib — single-header HTTP library (with OpenSSL for HTTPS/TLS support)
FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG        v0.16.0
)
# Enable OpenSSL support in cpp-httplib before MakeAvailable so the
# compile definition is applied consistently across all translation units.
set(HTTPLIB_REQUIRE_OPENSSL ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(httplib)

add_executable(ezone-server
    main.cpp
    server.cpp
)

target_include_directories(ezone-server PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/rest
)

# CPPHTTPLIB_OPENSSL_SUPPORT is required for httplib::SSLClient (Resend provider)
# and for serving HTTPS when use_tls = true.
target_compile_definitions(ezone-server PRIVATE
    CPPHTTPLIB_OPENSSL_SUPPORT
)

target_link_libraries(ezone-server PRIVATE
    ezone-sdk
    httplib::httplib
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Hardened flags (inherit from parent but also set explicitly for the server)
if(MSVC)
    target_compile_options(ezone-server PRIVATE /W4 /GS /sdl)
else()
    target_compile_options(ezone-server PRIVATE
        -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2)
endif()
