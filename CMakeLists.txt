# Qwertycoin: C++ client, tools and libraries.
# Copyright 2019 (c) The Qwertycoin Group.
# Licensed under the GNU General Public License, Version 3.
# See the file LICENSE from this package for details.

cmake_minimum_required(VERSION 3.10)

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
project(${PROJECT_NAME} VERSION ${PROJECT_VERSION} LANGUAGES C CXX)

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
include(external/MiniUPnP)
include(external/sparsehash)
include(external/Threads)

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/lib")

if(BUILD_WITH_TOOLS)
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/src")
endif()

if(BUILD_WITH_PACKAGE)
    include(project/CPackConfig)
endif()
