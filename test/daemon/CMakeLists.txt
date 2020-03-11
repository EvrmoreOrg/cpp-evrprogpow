add_executable(kawpow kawpow.cpp)

target_link_libraries(kawpow PRIVATE ethash -levent)
target_include_directories(kawpow PRIVATE ${ETHASH_PRIVATE_INCLUDE_DIR})
set_target_properties(kawpow PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)