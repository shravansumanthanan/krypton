cmake_minimum_required(VERSION 3.15)
project(krypton_pqc_addon)

# Set C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 1. Configure liboqs for minimal static build
set(OQS_USE_OPENSSL OFF CACHE BOOL "Do not use OpenSSL" FORCE)
set(OQS_DIST_BUILD ON CACHE BOOL "Build for distribution" FORCE)
set(OQS_ENABLE_KEM_ml_kem_768 ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_ml_dsa_65 ON CACHE BOOL "" FORCE)
set(OQS_MINIMAL_BUILD "KEM_ml_kem_768;SIG_ml_dsa_65" CACHE STRING "" FORCE)
set(OQS_BUILD_SHARED_LIBS OFF CACHE BOOL "Build static lib" FORCE)
set(OQS_OPT_TARGET "generic" CACHE STRING "Generic optimizations" FORCE)

if(CMAKE_OSX_ARCHITECTURES STREQUAL "x86_64")
    set(CMAKE_SYSTEM_PROCESSOR "x86_64")
endif()

# Add liboqs subdirectory
add_subdirectory(liboqs)

# 2. Get node-addon-api include directory
execute_process(COMMAND node -p "require('node-addon-api').include"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE NODE_ADDON_API_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REPLACE "\"" "" NODE_ADDON_API_DIR "${NODE_ADDON_API_DIR}")

# 3. Create the Node Addon library
add_library(${PROJECT_NAME} SHARED src/krypton_pqc_addon.cc)
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")

# Link and include
target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_JS_LIB} oqs)
target_include_directories(${PROJECT_NAME} PRIVATE 
    ${CMAKE_JS_INC} 
    ${NODE_ADDON_API_DIR} 
    liboqs/src
    ${CMAKE_BINARY_DIR}/liboqs/include
)

# Mac-specific linkage flags for Node Addons
if(APPLE)
  set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif()
