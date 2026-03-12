# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.10)

project ("winSock")

# Include sub-projects.
add_subdirectory ("winSockClient")
add_subdirectory ("winSockServer")
