cmake_minimum_required(VERSION 3.16)
project(dynscanner_dbg LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(dynscanner STATIC
    src/core/debug_session.cpp
    src/core/analyzer.cpp
)

target_include_directories(dynscanner
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(dynscanner PRIVATE src/linux/ptrace_debug_session.cpp)
    target_include_directories(dynscanner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_sources(dynscanner PRIVATE src/windows/windbg_debug_session.cpp)
    target_include_directories(dynscanner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(dynscanner PRIVATE dbghelp)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_sources(dynscanner PRIVATE src/macos/mach_debug_session.cpp)
    target_include_directories(dynscanner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    find_library(FOUNDATION_FRAMEWORK Foundation)
    if (FOUNDATION_FRAMEWORK)
        target_link_libraries(dynscanner PRIVATE ${FOUNDATION_FRAMEWORK})
    endif()
    target_link_libraries(dynscanner PRIVATE "-framework CoreServices" "-framework ApplicationServices")
endif()

target_compile_features(dynscanner PUBLIC cxx_std_20)

target_link_libraries(dynscanner PRIVATE pthread)

add_executable(dynscanner_cli src/main.cpp)

target_link_libraries(dynscanner_cli PRIVATE dynscanner)

