cmake_minimum_required (VERSION 3.12)
project(Client)

#default Release mode
set(DEFAULT_BUILD_TYPE Release)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${DEFAULT_BUILD_TYPE}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${DEFAULT_BUILD_TYPE}" CACHE STRING "Used default build type (${DEFAULT_BUILD_TYPE})." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()

add_executable(client_tester)
add_executable(client_shell)

include("${CMAKE_CURRENT_SOURCE_DIR}/src/CMakeLists.txt")

target_include_directories(client_tester PRIVATE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  )

target_include_directories(client_shell PRIVATE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/nacl-aes>
  )

set_target_properties(client_tester PROPERTIES COMPILE_FLAGS "-fPIC -Wall -ffunction-sections -fdata-sections -fvisibility=hidden")
set_target_properties(client_shell PROPERTIES COMPILE_FLAGS "-fPIC -Wall -ffunction-sections -fdata-sections -fvisibility=hidden -g -fsanitize=address")
set_target_properties(client_shell PROPERTIES LINK_FLAGS "-g -fsanitize=address")
