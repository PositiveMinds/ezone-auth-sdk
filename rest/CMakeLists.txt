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

# hiredis — minimal Redis client, backing an optional distributed rate
# limiter (rest/server.cpp's RedisRateLimiter) so multiple server replicas
# share one counter instead of each enforcing its own independent
# per-process limit. Purely opt-in at runtime: with no EZONE_REDIS_HOST set,
# the server falls back to the existing in-memory limiter, so this changes
# nothing for existing single-instance deployments.
option(EZONE_USE_REDIS_RATELIMIT "Enable Redis-backed distributed rate limiting" ON)
if(EZONE_USE_REDIS_RATELIMIT)
    FetchContent_Declare(
        hiredis
        GIT_REPOSITORY https://github.com/redis/hiredis.git
        GIT_TAG        v1.2.0
    )
    set(DISABLE_TESTS ON CACHE BOOL "" FORCE)
    set(ENABLE_SSL     OFF CACHE BOOL "" FORCE)
    set(ENABLE_SSL_TESTS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(hiredis)

    # hiredis is vendored C, not this project's code -- the top-level
    # CMakeLists.txt's add_compile_options(/W4 /WX ...) bakes those flags
    # directly into this directory's inherited COMPILE_OPTIONS, which every
    # target defined in this subdirectory (hiredis included, via
    # FetchContent's add_subdirectory) picks up at creation time. Neither
    # target_compile_options(/WX-) nor the COMPILE_WARNING_AS_ERROR property
    # can cancel an already-baked-in raw /WX (both were tried and silently
    # failed) -- CMake has no "unset a previously added compile option"
    # verb, so the only reliable fix is to replace the target's own
    # COMPILE_OPTIONS outright rather than append to it.
    foreach(_hiredis_tgt hiredis hiredis_static)
        if(TARGET ${_hiredis_tgt})
            set_target_properties(${_hiredis_tgt} PROPERTIES COMPILE_OPTIONS "")
        endif()
    endforeach()
endif()

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

# main.cpp reads server config from environment variables via getenv(), which
# MSVC's CRT flags as "unsafe" (C4996) and recommends _dupenv_s for — not
# applicable here (single-threaded startup, no buffer to overflow). Silence
# it rather than switching to a Windows-only API for portable config code.
if(MSVC)
    target_compile_definitions(ezone-server PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

target_link_libraries(ezone-server PRIVATE
    ezone-sdk
    httplib::httplib
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(EZONE_USE_REDIS_RATELIMIT)
    target_compile_definitions(ezone-server PRIVATE EZONE_REDIS_RATELIMIT_ENABLED)
    target_link_libraries(ezone-server PRIVATE hiredis::hiredis)
endif()

# Hardened flags (inherit from parent but also set explicitly for the server)
if(MSVC)
    target_compile_options(ezone-server PRIVATE /W4 /GS /sdl)
else()
    target_compile_options(ezone-server PRIVATE -Wall -Wextra -fstack-protector-strong)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # See the top-level CMakeLists.txt comment -- _FORTIFY_SOURCE is a
        # glibc-specific hardening macro, not applicable on macOS.
        target_compile_options(ezone-server PRIVATE -D_FORTIFY_SOURCE=2)
    endif()
endif()
