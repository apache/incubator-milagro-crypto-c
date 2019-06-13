include(CMakeParseArguments)
 
 # Check prereqs
 find_program( GCOV_PATH gcov )
 find_program( LCOV_PATH  NAMES lcov lcov.bat lcov.exe lcov.perl)
 find_program( GENHTML_PATH NAMES genhtml genhtml.perl genhtml.bat )
 find_program( GCOVR_PATH gcovr PATHS ${CMAKE_SOURCE_DIR}/scripts/test)
 find_package (Python COMPONENTS Interpreter Development)
 
 if(NOT GCOV_PATH)
     message(FATAL_ERROR "gcov not found! Aborting...")
 endif() # NOT GCOV_PATH
 
 if("${CMAKE_CXX_COMPILER_ID}" MATCHES "(Apple)?[Cc]lang")
     if("${CMAKE_CXX_COMPILER_VERSION}" VERSION_LESS 3)
         message(FATAL_ERROR "Clang version must be 3.0.0 or greater! Aborting...")
     endif()
 elseif(NOT CMAKE_COMPILER_IS_GNUCXX)
     message(FATAL_ERROR "Compiler is not GNU gcc! Aborting...")
 endif()
 
 set(COVERAGE_COMPILER_FLAGS "-g --coverage -fprofile-arcs -ftest-coverage"
     CACHE INTERNAL "")
 
 set(CMAKE_CXX_FLAGS_COVERAGE
     ${COVERAGE_COMPILER_FLAGS}
     CACHE STRING "Flags used by the C++ compiler during coverage builds."
     FORCE )
 set(CMAKE_C_FLAGS_COVERAGE
     ${COVERAGE_COMPILER_FLAGS}
     CACHE STRING "Flags used by the C compiler during coverage builds."
     FORCE )
 set(CMAKE_EXE_LINKER_FLAGS_COVERAGE
     ""
     CACHE STRING "Flags used for linking binaries during coverage builds."
     FORCE )
 set(CMAKE_SHARED_LINKER_FLAGS_COVERAGE
     ""
     CACHE STRING "Flags used by the shared libraries linker during coverage builds."
     FORCE )
 mark_as_advanced(
     CMAKE_CXX_FLAGS_COVERAGE
     CMAKE_C_FLAGS_COVERAGE
     CMAKE_EXE_LINKER_FLAGS_COVERAGE
     CMAKE_SHARED_LINKER_FLAGS_COVERAGE )
 
 if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
     message(WARNING "Code coverage results with an optimised (non-Debug) build may be misleading")
 endif() # NOT CMAKE_BUILD_TYPE STREQUAL "Debug"
 
 if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
     link_libraries(gcov)
 else()
     set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
 endif()
 
 # Defines a target for running and collection code coverage information
 # Builds dependencies, runs the given executable and outputs reports.
 # NOTE! The executable should always have a ZERO as exit code otherwise
 # the coverage generation will not complete.
 #
 # SETUP_TARGET_FOR_COVERAGE_LCOV(
 #     NAME testrunner_coverage                    # New target name
 #     EXECUTABLE testrunner -j ${PROCESSOR_COUNT} # Executable in PROJECT_BINARY_DIR
 #     DEPENDENCIES testrunner                     # Dependencies to build first
 # )
 function(SETUP_TARGET_FOR_COVERAGE_LCOV)
 
     set(options NONE)
     set(oneValueArgs NAME)
     set(multiValueArgs EXECUTABLE EXECUTABLE_ARGS DEPENDENCIES LCOV_ARGS GENHTML_ARGS)
     cmake_parse_arguments(Coverage "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
 
     if(NOT LCOV_PATH)
         message(FATAL_ERROR "lcov not found! Aborting...")
     endif() # NOT LCOV_PATH
 
     if(NOT GENHTML_PATH)
         message(FATAL_ERROR "genhtml not found! Aborting...")
     endif() # NOT GENHTML_PATH
 
     # Setup target
     add_custom_target(${Coverage_NAME}
 
         # Cleanup lcov
         COMMAND ${LCOV_PATH} ${Coverage_LCOV_ARGS} --gcov-tool ${GCOV_PATH} -directory . --zerocounters
         # Create baseline to make sure untouched files show up in the report
         COMMAND ${LCOV_PATH} ${Coverage_LCOV_ARGS} --gcov-tool ${GCOV_PATH} -c -i -d . -o ${Coverage_NAME}.base
 
         # Run tests
         COMMAND ${Coverage_EXECUTABLE} ${Coverage_EXECUTABLE_ARGS}
 
         # Capturing lcov counters and generating report
         COMMAND ${LCOV_PATH} ${Coverage_LCOV_ARGS} --gcov-tool ${GCOV_PATH} --directory . --capture --output-file ${Coverage_NAME}.info
         # add baseline counters
         COMMAND ${LCOV_PATH} ${Coverage_LCOV_ARGS} --gcov-tool ${GCOV_PATH} -a ${Coverage_NAME}.base -a ${Coverage_NAME}.info --output-file ${Coverage_NAME}.total
         COMMAND ${LCOV_PATH} ${Coverage_LCOV_ARGS} --gcov-tool ${GCOV_PATH} --remove ${Coverage_NAME}.total ${COVERAGE_LCOV_EXCLUDES} --output-file ${PROJECT_BINARY_DIR}/${Coverage_NAME}.info.cleaned
         COMMAND ${GENHTML_PATH} ${Coverage_GENHTML_ARGS} -o ${Coverage_NAME} ${PROJECT_BINARY_DIR}/${Coverage_NAME}.info.cleaned
         COMMAND ${CMAKE_COMMAND} -E remove ${Coverage_NAME}.base ${Coverage_NAME}.total ${PROJECT_BINARY_DIR}/${Coverage_NAME}.info.cleaned
 
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
         DEPENDS ${Coverage_DEPENDENCIES}
         COMMENT "Resetting code coverage counters to zero.\nProcessing code coverage counters and generating report."
     )
 
     # Show where to find the lcov info report
     add_custom_command(TARGET ${Coverage_NAME} POST_BUILD
         COMMAND ;
         COMMENT "Lcov code coverage info report saved in ${Coverage_NAME}.info."
     )
 
     # Show info where to find the report
     add_custom_command(TARGET ${Coverage_NAME} POST_BUILD
         COMMAND ;
         COMMENT "Open ./${Coverage_NAME}/index.html in your browser to view the coverage report."
     )
 
 endfunction() # SETUP_TARGET_FOR_COVERAGE_LCOV
 
 # Defines a target for running and collection code coverage information
 # Builds dependencies, runs the given executable and outputs reports.
 # NOTE! The executable should always have a ZERO as exit code otherwise
 # the coverage generation will not complete.
 #
 # SETUP_TARGET_FOR_COVERAGE_GCOVR_XML(
 #     NAME ctest_coverage                    # New target name
 #     EXECUTABLE ctest -j ${PROCESSOR_COUNT} # Executable in PROJECT_BINARY_DIR
 #     DEPENDENCIES executable_target         # Dependencies to build first
 # )
 function(SETUP_TARGET_FOR_COVERAGE_GCOVR_XML)
 
     set(options NONE)
     set(oneValueArgs NAME)
     set(multiValueArgs EXECUTABLE EXECUTABLE_ARGS DEPENDENCIES)
     cmake_parse_arguments(Coverage "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
 
     if(NOT Python_FOUND)
         message(FATAL_ERROR "python not found! Aborting...")
     endif()
 
     if(NOT GCOVR_PATH)
         message(FATAL_ERROR "gcovr not found! Aborting...")
     endif() # NOT GCOVR_PATH
 
     # Combine excludes to several -e arguments
     set(GCOVR_EXCLUDES "")
     foreach(EXCLUDE ${COVERAGE_GCOVR_EXCLUDES})
         string(REPLACE "*" "\\*" EXCLUDE_REPLACED ${EXCLUDE})
         list(APPEND GCOVR_EXCLUDES "-e")
         list(APPEND GCOVR_EXCLUDES "${EXCLUDE_REPLACED}")
     endforeach()
 
     add_custom_target(${Coverage_NAME}
         # Run tests
         ${Coverage_EXECUTABLE} ${Coverage_EXECUTABLE_ARGS}
 
         # Running gcovr
         COMMAND ${GCOVR_PATH} --xml
             -r ${PROJECT_SOURCE_DIR} ${GCOVR_EXCLUDES}
             --object-directory=${PROJECT_BINARY_DIR}
             -o ${Coverage_NAME}.xml
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
         DEPENDS ${Coverage_DEPENDENCIES}
         COMMENT "Running gcovr to produce Cobertura code coverage report."
     )
 
     # Show info where to find the report
     add_custom_command(TARGET ${Coverage_NAME} POST_BUILD
         COMMAND ;
         COMMENT "Cobertura code coverage report saved in ${Coverage_NAME}.xml."
     )
 
 endfunction() # SETUP_TARGET_FOR_COVERAGE_GCOVR_XML
 
 # Defines a target for running and collection code coverage information
 # Builds dependencies, runs the given executable and outputs reports.
 # NOTE! The executable should always have a ZERO as exit code otherwise
 # the coverage generation will not complete.
 #
 # SETUP_TARGET_FOR_COVERAGE_GCOVR_HTML(
 #     NAME ctest_coverage                    # New target name
 #     EXECUTABLE ctest -j ${PROCESSOR_COUNT} # Executable in PROJECT_BINARY_DIR
 #     DEPENDENCIES executable_target         # Dependencies to build first
 # )
 function(SETUP_TARGET_FOR_COVERAGE_GCOVR_HTML)
 
     set(options NONE)
     set(oneValueArgs NAME)
     set(multiValueArgs EXECUTABLE EXECUTABLE_ARGS DEPENDENCIES)
     cmake_parse_arguments(Coverage "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
 
     if(NOT Python_FOUND)
         message(FATAL_ERROR "python not found! Aborting...")
     endif()
 
     if(NOT GCOVR_PATH)
         message(FATAL_ERROR "gcovr not found! Aborting...")
     endif() # NOT GCOVR_PATH
 
     # Combine excludes to several -e arguments
     set(GCOVR_EXCLUDES "")
     foreach(EXCLUDE ${COVERAGE_GCOVR_EXCLUDES})
         string(REPLACE "*" "\\*" EXCLUDE_REPLACED ${EXCLUDE})
         list(APPEND GCOVR_EXCLUDES "-e")
         list(APPEND GCOVR_EXCLUDES "${EXCLUDE_REPLACED}")
     endforeach()
 
     add_custom_target(${Coverage_NAME}
         # Run tests
         ${Coverage_EXECUTABLE} ${Coverage_EXECUTABLE_ARGS}
 
         # Create folder
         COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/${Coverage_NAME}
 
         # Running gcovr
         COMMAND ${Python_EXECUTABLE} ${GCOVR_PATH} --html --html-details
             -r ${PROJECT_SOURCE_DIR} ${GCOVR_EXCLUDES}
             --object-directory=${PROJECT_BINARY_DIR}
             -o ${Coverage_NAME}/index.html
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
         DEPENDS ${Coverage_DEPENDENCIES}
         COMMENT "Running gcovr to produce HTML code coverage report."
     )
 
     # Show info where to find the report
     add_custom_command(TARGET ${Coverage_NAME} POST_BUILD
         COMMAND ;
         COMMENT "Open ./${Coverage_NAME}/index.html in your browser to view the coverage report."
     )
 
 endfunction() # SETUP_TARGET_FOR_COVERAGE_GCOVR_HTML
 
 function(APPEND_COVERAGE_COMPILER_FLAGS)
     set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COVERAGE_COMPILER_FLAGS}" PARENT_SCOPE)
     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COVERAGE_COMPILER_FLAGS}" PARENT_SCOPE)
     message(STATUS "Appending code coverage compiler flags: ${COVERAGE_COMPILER_FLAGS}")
 endfunction() # APPEND_COVERAGE_COMPILER_FLAGS
