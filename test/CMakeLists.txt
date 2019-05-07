cmake_minimum_required(VERSION 3.2.2)

project(ARK_CPP_PSP_OS_TESTS C CXX)

set(BUILD_GMOCK OFF FORCE)

add_subdirectory(lib/googletest)

include(CTest)
enable_testing()

set (PROJECT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../lib")

include_directories(${PROJECT_SOURCE_DIR}/../src)
include_directories(${PROJECT_SOURCE_DIR}/../src/lib)
include_directories(${PROJECT_SOURCE_DIR}/../src/lib/bcl)
include_directories(${PROJECT_SOURCE_DIR}/../src/lib/rfc6979)
include_directories(${PROJECT_SOURCE_DIR}/../src/lib/uECC)
include_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

set (TEST_SRC
	${PROJECT_SOURCE_DIR}/crypto_test.cpp
	${PROJECT_SOURCE_DIR}/net_test.cpp
	${PROJECT_SOURCE_DIR}/rng_test.cpp
	${PROJECT_SOURCE_DIR}/time_test.cpp
)

find_library(ARK_CPP_PSP_OS_TESTS PUBLIC)

add_executable(ARK_CPP_PSP_OS_TESTS ${TEST_SRC})

target_link_libraries(ARK_CPP_PSP_OS_TESTS ARK_CPP_PSP_OS_LIB gtest gtest_main)

add_test(NAME test COMMAND ARK_CPP_PSP_OS_TESTS)
