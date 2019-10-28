cmake_minimum_required(VERSION 2.8.12)
project(sysrepo-tsn-plugin)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wpedantic")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include_directories("${PROJECT_SOURCE_DIR}/inc")

find_package(CJSON REQUIRED)
include_directories(${CJSON_INCLUDE_DIRS})
set(LIBS ${LIBS} ${CJSON_LIBRARIES})

find_package(NL REQUIRED)
include_directories(${NL_INCLUDE_DIRS})
set(LIBS ${LIBS} ${NL_LIBRARIES})

find_package(NLGEN REQUIRED)
include_directories(${NLGEN_INCLUDE_DIRS})
set(LIBS ${LIBS} ${NLGEN_LIBRARIES})

find_package(TSN REQUIRED)
include_directories(${TSN_INCLUDE_DIRS})
set(LIBS ${LIBS} ${TSN_LIBRARIES})

find_package(SYSREPO REQUIRED)
include_directories(${SYSREPO_INCLUDE_DIRS})
set(LIBS ${LIBS} ${SYSREPO_LIBRARIES})

set(SOURCES 
		src/main.c
		src/common.c
		src/qbv.c
		src/qbu.c)

add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
target_link_libraries(${CMAKE_PROJECT_NAME} ${LIBS})

install(TARGETS ${CMAKE_PROJECT_NAME} RUNTIME DESTINATION bin)

macro(INSTALL_EXAMPLE_YANG MODULE_NAME REVISION)
    # install the YANG module
    set(CMD "${CALL_SYSREPOCTL_BIN} --install --yang=${CMAKE_CURRENT_SOURCE_DIR}/yang/${MODULE_NAME}${REVISION}.yang --permissions=666")
endmacro(INSTALL_EXAMPLE_YANG)
