cmake_minimum_required(VERSION 3.6)
project(ocx-or1kiss)

add_subdirectory(or1kiss EXCLUDE_FROM_ALL)

enable_testing()
add_subdirectory(ocx)

set_property(TARGET or1kiss PROPERTY POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_STANDARD 11)

set(src "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(inc "${CMAKE_CURRENT_SOURCE_DIR}/ocx/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/or1kiss/include")

set(sources "${src}/ocx-or1kiss.cpp")

add_library(ocx-or1kiss MODULE ${sources})

target_include_directories(ocx-or1kiss PUBLIC ${inc})
target_link_libraries(ocx-or1kiss or1kiss)

target_compile_options(ocx-or1kiss PRIVATE -Werror -Wall)

add_test(NAME ocx-or1kiss
         COMMAND $<TARGET_FILE:ocx-test-runner>
                 --gtest_filter=ocx_basic.*
                 $<TARGET_FILE:ocx-or1kiss> non_applicable)
