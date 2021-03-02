
include(ExternalProject)

set(CJSON_CMAKE_ARGS

    -DENABLE_CJSON_TEST=Off
    -DENABLE_CJSON_UTILS=Off
    -DBUILD_SHARED_LIBS=Off
    -DCMAKE_BUILD_TYPE=Release
    -DENABLE_HIDDEN_SYMBOLS=On

    )

ExternalProject_Add(cJson
    GIT_REPOSITORY      "https://github.com/DaveGamble/cJSON.git"
    GIT_PROGRESS        "true"
    GIT_TAG             "v1.7.14"
    CMAKE_ARGS          ${CJSON_CMAKE_ARGS}
    UPDATE_COMMAND      ""
    INSTALL_COMMAND     "")

ExternalProject_get_property(cJson SOURCE_DIR)
set(CJSON_SOURCE_DIR "${SOURCE_DIR}")
ExternalProject_get_property(cJson BINARY_DIR)
set(CJSON_LIB "${BINARY_DIR}/libcjson.a")



target_sources(client_tester PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/context.c"
    "${CMAKE_CURRENT_LIST_DIR}/wb_loader.c"
    "${CMAKE_CURRENT_LIST_DIR}/key-client.c")

target_link_libraries(client_tester PRIVATE -ldl -lcurl)



target_sources(client_shell PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/context.c"
    "${CMAKE_CURRENT_LIST_DIR}/wb_loader.c"
    "${CMAKE_CURRENT_LIST_DIR}/key-client.c"
    "${CMAKE_CURRENT_LIST_DIR}/media-client.c")

target_include_directories(client_shell PRIVATE
    "${CJSON_SOURCE_DIR}")

target_link_libraries(client_shell PRIVATE -ldl -lcurl ${CJSON_LIB})

add_dependencies(client_shell cJson)



target_sources(vlc_module PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/context.c"
    "${CMAKE_CURRENT_LIST_DIR}/wb_loader.c"
    "${CMAKE_CURRENT_LIST_DIR}/key-client.c"
    "${CMAKE_CURRENT_LIST_DIR}/media-client.c")

target_include_directories(vlc_module PRIVATE
    "${CJSON_SOURCE_DIR}")

target_link_libraries(vlc_module PRIVATE -ldl ${CJSON_LIB})

add_dependencies(vlc_module cJson)

