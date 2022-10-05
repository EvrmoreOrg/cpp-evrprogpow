add_executable(evrprogpow evrprogpow.cpp)

target_link_libraries(evrprogpow PRIVATE ethash -levent)
target_include_directories(evrprogpow PRIVATE ${ETHASH_PRIVATE_INCLUDE_DIR})
set_target_properties(evrprogpow PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)