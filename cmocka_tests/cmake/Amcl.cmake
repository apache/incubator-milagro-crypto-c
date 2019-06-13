IF(UNIX)
    FIND_PATH(AMCL_INCLUDE_DIR amcl.h
      "../include"
      "${PROJECT_ROOT}/../include"
      "${CMAKE_SOURCE_DIR}/../include"
      NO_DEFAULT_PATH
      )

    SET(CMAKE_FIND_LIBRARY_PREFIXES "" "lib")
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".so" ".a" ".lib")
    FIND_LIBRARY(AMCL_LIBRARY NAMES amcl_core PATHS
      $ENV{LIB}
      ../lib
      /usr/lib/x86_64-linux-gnu
      "$ENV{LIB_DIR}/lib"
      "${CMAKE_SOURCE_DIR}/lib"
      #mingw
      c:/msys/local/lib
      NO_DEFAULT_PATH
      )
ELSE()
    FIND_PATH(AMCL_INCLUDE_DIR amcl.h
      "${PROJECT_ROOT}/include"
      "${PROJECT_ROOT}/../include"
      )

    FILE(GLOB AMCL_LIBRARY NAMES 
        "${PROJECT_ROOT}/../lib/*amcl_core.lib"
        "${CMAKE_SOURCE_DIR}/../lib/*amcl_core.so"
        )
ENDIF()


IF (AMCL_INCLUDE_DIR AND AMCL_LIBRARY)
    SET(AMCL_FOUND TRUE)
ENDIF (AMCL_INCLUDE_DIR AND AMCL_LIBRARY)

MESSAGE(STATUS "Apache Milagro Include: ${AMCL_INCLUDE_DIR}")


IF (AMCL_FOUND)
    MESSAGE(STATUS "Found Apache Milagro: ${AMCL_LIBRARY}")
ELSE (AMCL_FOUND)
        MESSAGE(FATAL_ERROR "Could not find Apache Milagro")
ENDIF (AMCL_FOUND)
