# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
get_filename_component(PROJECT_ROOT ${CMAKE_CURRENT_LIST_FILE} DIRECTORY)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_MODULE_PATH "${PROJECT_ROOT}/cmake")
include(${PROJECT_ROOT}/cmake/Cmocka.cmake)
include(${PROJECT_ROOT}/cmake/AddCmockaTest.cmake)
include(${PROJECT_ROOT}/cmake/Amcl.cmake)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

function(ADD_CMOCKA_TEST_ENVIRONMENT _TARGET_NAME)
    if (WIN32 OR CYGWIN OR MINGW)
        file(TO_NATIVE_PATH "${cmocka-library_BINARY_DIR}" CMOCKA_DLL_PATH)

        if (TARGET_SYSTEM_EMULATOR)
            set(DLL_PATH_ENV "WINEPATH=${CMOCKA_DLL_PATH};$ENV{WINEPATH}")
        else()
            set(DLL_PATH_ENV "PATH=${CMOCKA_DLL_PATH};$ENV{PATH}")
        endif()
        #
        # IMPORTANT NOTE: The set_tests_properties(), below, internally
        # stores its name/value pairs with a semicolon delimiter.
        # because of this we must protect the semicolons in the path
        #
        string(REPLACE ";" "\\;" DLL_PATH_ENV "${DLL_PATH_ENV}")

        set_tests_properties(${_TARGET_NAME}
                             PROPERTIES
                                ENVIRONMENT
                                    "${DLL_PATH_ENV}")
    endif()
endfunction()

set_source_files_properties(aes_test.c crypto_context.c test_main.c
                            PROPERTIES
                            COMPILE_DEFINITIONS
                            UNIT_TESTING=1)
enable_testing()
include_directories(${CMOCKA_INCLUDE_DIR} ${PROJECT_ROOT} include ../include)
### The most simple test
add_cmocka_test(aes_test
                SOURCES crypto_context.c test_main.c aes_test.c
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                LINK_LIBRARIES ${CMOCKA_LIBRARY} ${AMCL_LIBRARY} OpenSSL::Crypto)
add_cmocka_test_environment(aes_test)


