
IF(UNIX)
    FIND_PATH(CMOCKA_INCLUDE_DIR cmocka.h
      "$ENV{LIB_DIR}/include"
      "/usr/include"
      "/usr/include/cmockery"
      "${CMAKE_SOURCE_DIR}/include"
      "${CMAKE_SOURCE_DIR}/include/cmocka"
      NO_DEFAULT_PATH
      )

    SET(CMAKE_FIND_LIBRARY_PREFIXES "" "lib")
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".so" ".a" ".lib")
    FIND_LIBRARY(CMOCKA_LIBRARY NAMES cmocka PATHS
      $ENV{LIB}
      /usr/lib
      /usr/lib/x86_64-linux-gnu
      "$ENV{LIB_DIR}/lib"
      "${CMAKE_SOURCE_DIR}/lib"
      #mingw
      c:/msys/local/lib
      NO_DEFAULT_PATH
      )
ELSE()
    FIND_PATH(CMOCKA_INCLUDE_DIR cmocka.h
        "${PROJECT_ROOT}/include"
      )

    FILE(GLOB CMOCKA_LIBRARY NAMES
        "${PROJECT_ROOT}/lib/cmocka*.lib"
        "${PROJECT_ROOT}/lib/cmocka*.a"
        )
ENDIF()


IF (CMOCKA_INCLUDE_DIR AND CMOCKA_LIBRARY)
    SET(CMOCKA_FOUND TRUE)
ENDIF (CMOCKA_INCLUDE_DIR AND CMOCKA_LIBRARY)

MESSAGE(STATUS "CMocka Include: ${CMOCKA_INCLUDE_DIR}")


IF (CMOCKA_FOUND)
    MESSAGE(STATUS "Found CMocka: ${CMOCKA_LIBRARY}")
ELSE (CMOCKA_FOUND)
        MESSAGE(FATAL_ERROR "Could not find Cmocka")
ENDIF (CMOCKA_FOUND)
