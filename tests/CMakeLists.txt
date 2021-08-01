configure_file(${CMAKE_CURRENT_SOURCE_DIR}/unit-test.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/unit-test.h)

macro(build_test NAME)
    add_executable(${NAME} ${NAME}.cpp)
    target_link_libraries(${NAME} modbus)
    target_include_directories(${NAME}
        PRIVATE
            ${CMAKE_CURRENT_BINARY_DIR}
            ${CMAKE_CURRENT_BINARY_DIR}/..) # this path is needed for modbus-version.h
endmacro()

build_test(bandwidth-server-one)
build_test(bandwidth-server-many-up)
build_test(bandwidth-client)
build_test(random-test-server)
build_test(random-test-client)
build_test(unit-test-server)
build_test(unit-test-client)
build_test(version)

add_test(NAME unit-test
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/unit-tests.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
