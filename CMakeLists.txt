# Qwertycoin: C++ client, tools and libraries.
# Copyright 2019 (c) The Qwertycoin Group.
# Licensed under the GNU General Public License, Version 3.
# See the file LICENSE from this package for details.

cmake_minimum_required(VERSION 3.10)
message(STATUS "CMake version ${CMAKE_VERSION}")

if(POLICY CMP0074)
    # Allow find_package() to use <PackageName>_ROOT variables.
    # This policy was introduced in CMake version 3.12.
    cmake_policy(SET CMP0074 NEW)
endif()

list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_LIST_DIR}/cmake")
list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_LIST_DIR}/cmake/find")

# Configure project build type.
set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "Supported build types" FORCE)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
message(STATUS "CMake build type: ${CMAKE_BUILD_TYPE}")

set(PROJECT_DISPLAY_NAME "Qwertycoin")
set(PROJECT_NAME "qwertycoin")
set(PROJECT_DESCRIPTION "Safe. Simple. Seamless. Secure.")
set(PROJECT_VERSION "${PROJECT_GIT_TAG}")
set(PROJECT_COPYRIGHT "Copyright 2019 The Qwertycoin Group")
set(PROJECT_VENDOR_NAME "The Qwertycoin Group")
set(PROJECT_VENDOR_URL "https://qwertycoin.org")
project(${PROJECT_NAME} LANGUAGES C CXX)

if(APPLE OR FREEBSD)
    # Compile src/Platform/OSX/System/asm.s file.
    enable_language(ASM)
endif()

include(project/CompilerSettings)
include(project/GlobalOptions)
include(project/GlobalVariables)

# External dependencies
set_directory_properties(PROPERTIES EP_BASE "${CMAKE_CURRENT_BINARY_DIR}/_ExternalProjects")
include(ExternalProject)
include(external/Boost)
include(external/GTest)
include(external/MiniUPnP)
include(external/sparsehash)
include(external/Threads)

# Check whether we're on a 32-bit or 64-bit system
math(EXPR BITS "8*${CMAKE_SIZEOF_VOID_P}")
set(ARCH_WIDTH ${BITS} CACHE STRING "Width of architecture to build for")
message(STATUS "Building for a ${ARCH_WIDTH}-bit system")

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/external/db_drivers")

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/lib")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/external/Backward")

#include(ExternalProject)
#ExternalProject_Add(lmdb
#  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/db_drivers/liblmdb
#  BUILD_COMMAND make all
#  INSTALL_COMMAND make install --prefix=${CMAKE_CURRENT_BINARY_DIR}/../lib
#  BUILD_IN_SOURCE 1
#)


include_directories(${LMDB_INCLUDE})
include_directories(${CMAKE_CURRENT_LIST_DIR}/external/boost/archive)


if(BUILD_WITH_TOOLS)
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/src")
endif()

if(BUILD_WITH_PACKAGE)
    include(project/CPackConfig)
endif()

#if(BUILD_WITH_TESTS)
#    enable_testing()
#    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/tests")
#endif()

find_library(BFD_LIBRARY bfd)
if(BFD_LIBRARY)
  set(BFD_LIBRARY "${BFD_LIBRARY}")
  message(STATUS "Found BFD_LIBRARY located at ${BFD_LIBRARY}")
  include_directories(BFD_INCLUDE_DIR /usr/include)
endif()
if(NOT BFD_LIBRARY)
  message(FATAL_ERROR "Could not find required libbfd from binutils package.")
endif()

