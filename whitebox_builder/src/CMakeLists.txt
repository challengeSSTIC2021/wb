

include("${CMAKE_CURRENT_LIST_DIR}/nacl-aes/CMakeLists.txt")




file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/include")

add_custom_command(
  OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/include/AESKEY.h"
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/wb_gen/genAES.py" --out "${CMAKE_CURRENT_BINARY_DIR}/include/AESKEY.h" --aesKey "${WB_AESENC_KEY}"
)
add_custom_target(gen_header DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/include/AESKEY.h")

add_library(constructor INTERFACE)
target_include_directories(constructor INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/nacl-aes>
  )

target_sources(constructor INTERFACE
    "${CMAKE_CURRENT_LIST_DIR}/AES_constructor.c")

add_dependencies(constructor gen_header)

target_link_libraries(wblib PRIVATE constructor)


add_executable(test "${CMAKE_CURRENT_LIST_DIR}/test.c")

target_include_directories(test PRIVATE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  )

add_dependencies(test wblib)
target_link_libraries(test wblib)

ADD_CUSTOM_COMMAND(
        TARGET test
        POST_BUILD
        COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/wb_gen/check_test.py" -k "${WB_KEY}" -t $<TARGET_FILE:test>
    )
