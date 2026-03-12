cmake_minimum_required(VERSION 3.10)
project(winSockServer)

# Force C++14 standard (required for <thread> and standard modern C++)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Create the executable
add_executable(winSockServer winSockServer.cpp)

# Explicitly link the native Windows libraries
# This bypasses any issues with #pragma comment(lib) being ignored by the build system
target_link_libraries(winSockServer ws2_32 bcrypt)