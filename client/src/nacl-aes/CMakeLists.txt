
set(AES_SOURCE
    "${CMAKE_CURRENT_LIST_DIR}/afternm.c"
    "${CMAKE_CURRENT_LIST_DIR}/beforenm.c"
    "${CMAKE_CURRENT_LIST_DIR}/common.c"
    "${CMAKE_CURRENT_LIST_DIR}/consts.c"
    "${CMAKE_CURRENT_LIST_DIR}/int128.c"
    "${CMAKE_CURRENT_LIST_DIR}/stream.c"
    "${CMAKE_CURRENT_LIST_DIR}/xor_afternm.c"
)

target_sources(client_shell PRIVATE ${AES_SOURCE})
target_sources(vlc_module PRIVATE ${AES_SOURCE})
