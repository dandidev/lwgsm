cmake_minimum_required(VERSION 3.0.0)

# Setup project
project(LwLibPROJECT)

# -------------------------------------------------
# This CMakeLists.txt is used only if it is a top-level file.
# Purpose of it is to be able to compile project in standalone way only
#
# When library sources are to be included in another project
# user shall use /lwgsm/CMakeLists.txt instead
if (NOT PROJECT_IS_TOP_LEVEL)
    message(FATAL_ERROR "This CMakeLists.txt can only be used as top-level. Use /lwgsm/CMakeLists.txt for library include purpose")
endif()

# Set as executable
add_executable(${PROJECT_NAME})

# Add key executable block
target_sources(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/dev/main.c

    # Development additional files
    ${CMAKE_CURRENT_LIST_DIR}/lwgsm/src/system/lwgsm_mem_lwmem.c
    ${CMAKE_CURRENT_LIST_DIR}/../lwmem/lwmem/src/lwmem/lwmem.c
    ${CMAKE_CURRENT_LIST_DIR}/../lwmem/lwmem/src/system/lwmem_sys_posix.c
    
    # Port specific
    ${CMAKE_CURRENT_LIST_DIR}/lwgsm/src/system/lwgsm_sys_posix.c
    ${CMAKE_CURRENT_LIST_DIR}/lwgsm/src/system/lwgsm_ll_posix.c
    )

# Add key include paths
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/dev
    ${CMAKE_CURRENT_LIST_DIR}/../lwmem/lwmem/src/include

    # Port specific
    ${CMAKE_CURRENT_LIST_DIR}/lwgsm/src/include/system/port/posix
    )

# Compilation definition information
target_compile_definitions(${PROJECT_NAME} PUBLIC
    WIN32
    _DEBUG
    CONSOLE
    LWGSM_DEV
    )

# Add subdir with lwgsm and link to the project
add_subdirectory("lwgsm")
target_link_libraries(${PROJECT_NAME} lwgsm)
target_link_libraries(${PROJECT_NAME} lwgsm_api)
target_link_libraries(${PROJECT_NAME} lwgsm_apps)
add_subdirectory("snippets")
target_link_libraries(${PROJECT_NAME} lwgsm_snippets)

# Add POSIX pthread lib
target_link_libraries(${PROJECT_NAME} pthread)