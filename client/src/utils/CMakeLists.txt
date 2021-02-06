
target_sources(client_tester PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/wb_loader.c")

target_link_libraries(client_tester PRIVATE -ldl -lcurl)
