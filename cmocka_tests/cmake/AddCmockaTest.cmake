

function(ADD_CMOCKA_TEST _TARGET_NAME)

    set(one_value_arguments
    )

    set(multi_value_arguments
        SOURCES
        COMPILE_OPTIONS
        LINK_LIBRARIES
        LINK_OPTIONS
    )

    cmake_parse_arguments(_add_cmocka_test
        ""
        "${one_value_arguments}"
        "${multi_value_arguments}"
        ${ARGN}
    )

    if (NOT DEFINED _add_cmocka_test_SOURCES)
        message(FATAL_ERROR "No sources provided for target ${_TARGET_NAME}")
    endif()

    add_executable(${_TARGET_NAME} ${_add_cmocka_test_SOURCES})

    if (DEFINED _add_cmocka_test_COMPILE_OPTIONS)
        target_compile_options(${_TARGET_NAME}
            PRIVATE ${_add_cmocka_test_COMPILE_OPTIONS}
        )
    endif()

    if (DEFINED _add_cmocka_test_LINK_LIBRARIES)
        target_link_libraries(${_TARGET_NAME}
            PRIVATE ${_add_cmocka_test_LINK_LIBRARIES}
        )
    endif()

    if (DEFINED _add_cmocka_test_LINK_OPTIONS)
        set_target_properties(${_TARGET_NAME}
            PROPERTIES LINK_FLAGS
            ${_add_cmocka_test_LINK_OPTIONS}
        )
    endif()

    add_test(${_TARGET_NAME}
        ${TARGET_SYSTEM_EMULATOR} ${_TARGET_NAME}
    )

endfunction (ADD_CMOCKA_TEST)
