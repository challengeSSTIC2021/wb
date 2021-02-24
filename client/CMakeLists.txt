cmake_minimum_required (VERSION 3.12)
project(Client)

#default Release mode
set(DEFAULT_BUILD_TYPE Release)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${DEFAULT_BUILD_TYPE}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${DEFAULT_BUILD_TYPE}" CACHE STRING "Used default build type (${DEFAULT_BUILD_TYPE})." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()

find_library(GCRYPT_LIB gcrypt REQUIRED)

#add_compile_options("-fsanitize=address")
#link_libraries("-fsanitize=address")
#link_libraries("-s")

add_executable(client_tester)
add_executable(client_shell)
add_library(vlc_module SHARED)

include("${CMAKE_CURRENT_SOURCE_DIR}/src/CMakeLists.txt")

target_include_directories(client_tester PRIVATE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  )

target_include_directories(client_shell PRIVATE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  )

target_include_directories(vlc_module PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  /usr/include/vlc/plugins
  )

target_link_libraries(client_shell PRIVATE ${GCRYPT_LIB})
target_link_libraries(vlc_module PRIVATE -lvlccore ${GCRYPT_LIB})

set_target_properties(vlc_module PROPERTIES OUTPUT_NAME chall_plugin)

set_target_properties(client_tester PROPERTIES COMPILE_FLAGS "-fPIC -Wall -ffunction-sections -fdata-sections -fvisibility=hidden")
set_target_properties(client_shell PROPERTIES COMPILE_FLAGS "-fPIC -Wall -ffunction-sections -fdata-sections -fvisibility=hidden")
set_target_properties(vlc_module PROPERTIES COMPILE_FLAGS "-fPIC -Wall -ffunction-sections -fdata-sections -fvisibility=hidden -DHTTP_WITH_VLC -D__PLUGIN__ -D_FILE_OFFSET_BITS=64 -D_REENTRANT -D_THREAD_SAFE -g -O2")




