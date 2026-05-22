cmake_minimum_required(VERSION 3.20)
project(ezone-sdk VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Security-hardened compiler flags
if(MSVC)
    add_compile_options(/W4 /WX /GS /sdl /guard:cf)
    add_link_options(/NXCOMPAT /DYNAMICBASE /GUARD:CF)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic -Werror
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fPIC
    )
    add_link_options(-Wl,-z,relro -Wl,-z,now)
endif()

# Find OpenSSL (3.x required for modern EVP API)
find_package(OpenSSL 3.0 REQUIRED)

# Optional: PostgreSQL support via libpq
option(EZONE_POSTGRES "Build PostgreSQL storage adapter" OFF)
if(EZONE_POSTGRES)
    find_package(PostgreSQL REQUIRED)
endif()

# SDK library
set(EZONE_SDK_SOURCES
    src/crypto_engine.cpp
    src/storage_adapter.cpp
    src/auth.cpp
    src/ezone_c.cpp
    src/email/log_provider.cpp
    src/email/resend_provider.cpp
)
if(EZONE_POSTGRES)
    list(APPEND EZONE_SDK_SOURCES src/postgres_adapter.cpp)
endif()

add_library(ezone-sdk STATIC ${EZONE_SDK_SOURCES})

target_include_directories(ezone-sdk
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(ezone-sdk
    PUBLIC OpenSSL::SSL OpenSSL::Crypto
)

if(EZONE_POSTGRES)
    target_compile_definitions(ezone-sdk PUBLIC EZONE_POSTGRES_ENABLED)
    target_link_libraries(ezone-sdk PUBLIC PostgreSQL::PostgreSQL)
endif()

# Tests
enable_testing()

add_executable(test_crypto tests/test_crypto_engine.cpp)
target_link_libraries(test_crypto PRIVATE ezone-sdk)
add_test(NAME crypto_engine_tests COMMAND test_crypto)

add_executable(test_auth tests/test_auth.cpp)
target_link_libraries(test_auth PRIVATE ezone-sdk)
add_test(NAME auth_flow_tests COMMAND test_auth)

# REST server (optional — requires network access to fetch cpp-httplib)
option(EZONE_BUILD_SERVER "Build the ezone REST server" ON)
if(EZONE_BUILD_SERVER)
    add_subdirectory(rest)
endif()
