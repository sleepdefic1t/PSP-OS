
cmake_minimum_required(VERSION 3.2.2)

project(ARK_CPP_PSP_OS_LIB C CXX)

set(BCL_SRC
	lib/bcl/Base58Check.cpp
	lib/bcl/CurvePoint.cpp
	lib/bcl/Ecdsa.cpp
	lib/bcl/FieldInt.cpp
	lib/bcl/Ripemd160.cpp
	lib/bcl/Sha256Hash.cpp
	lib/bcl/Sha256.cpp
	lib/bcl/Sha512.cpp
	lib/bcl/Uint256.cpp
	lib/bcl/Utils.cpp
)

set(uECC_SRC
	lib/uECC/uECC.c
)

set(COMMON_SRC
    psp_crypto.cpp
    psp_rng.cpp
    psp_time.cpp
)

add_library(${PROJECT_NAME} STATIC
	${BCL_SRC}
	${uECC_SRC}
	${COMMON_SRC}
)

set(ark_cpp_psp_os_build_include_dirs
    ${PROJECT_SOURCE_DIR}
)

include_directories(${ark_cpp_psp_os_build_include_dirs})
include_directories(${PROJECT_SOURCE_DIR}/lib/)
include_directories(${PROJECT_SOURCE_DIR}/lib/bcl)
include_directories(${PROJECT_SOURCE_DIR}/lib/rfc6979)
include_directories(${PROJECT_SOURCE_DIR}/lib/uECC)

target_include_directories( ${PROJECT_NAME} PUBLIC
	${ark_cpp_psp_os_build_include_dirs}
)

if (MSVC)
	target_link_libraries(${PROJECT_NAME} PUBLIC crypt32)
endif()
