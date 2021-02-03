cmake_minimum_required (VERSION 3.12)
project(WhiteboxLib)

#default Release mode
set(DEFAULT_BUILD_TYPE Release)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${DEFAULT_BUILD_TYPE}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${DEFAULT_BUILD_TYPE}" CACHE STRING "Used default build type (${DEFAULT_BUILD_TYPE})." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()

# verify input option
macro(VERIFY_HEX NAME VAR EXPECTED_LEN)

  string(LENGTH "${VAR}" REAL_LEN)

  if (NOT (${REAL_LEN} STREQUAL ${EXPECTED_LEN}))
    message(FATAL_ERROR "Option ${NAME} : Expected ${EXPECTED_LEN} characters, found ${REAL_LEN} (\"${VAR}\")")
  endif()

  string(REGEX MATCH "^[0-9a-fA-F]*$" MATCH_VAR ${VAR})

  if (NOT ("${MATCH_VAR}" STREQUAL "${VAR}"))
    message(FATAL_ERROR "Option ${NAME} : Not a hexa string (\"${VAR}\")")
  endif()

endmacro()


# get mandatory argument
VERIFY_HEX( WB_SUFFIX "${WB_SUFFIX}" 16)
VERIFY_HEX( WB_KEY "${WB_KEY}" 32)
VERIFY_HEX( WB_AESENC_KEY "${WB_AESENC_KEY}" 32)

add_custom_command(
  OUTPUT  WB_VM.c
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/wb_gen/genWhitebox.py" --vmout "${CMAKE_CURRENT_BINARY_DIR}/WB_VM.c" --suffix "${WB_SUFFIX}" --key "${WB_KEY}" --aesKey "${WB_AESENC_KEY}" -q
)

add_library(wblib SHARED WB_VM.c)

include("${CMAKE_CURRENT_SOURCE_DIR}/src/CMakeLists.txt")

target_include_directories(wblib PRIVATE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/nacl-aes>
  )

set_target_properties(wblib PROPERTIES COMPILE_FLAGS "-fPIC -Wall -ffunction-sections -fdata-sections -fvisibility=hidden")
set_target_properties(wblib PROPERTIES LINK_FLAGS "-s")
set_target_properties(wblib PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)


