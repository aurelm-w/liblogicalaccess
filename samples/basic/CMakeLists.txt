cmake_minimum_required(VERSION 3.10)
project(basic
    LANGUAGES CXX
)

# Common libraries
set(LIBLOGICALACCESS_COMMON_LIBRARIES
    logicalaccess
    iso7816cards
    desfirecards
    iso7816readers
    pcscreaders
)

# basic
add_executable(basic
    basic.cpp
)

target_link_libraries(basic
    PRIVATE
        ${LIBLOGICALACCESS_COMMON_LIBRARIES}
)

# basic_pki
add_executable(basic_pki
    basic_pki.cpp
)

target_link_libraries(basic_pki
    PRIVATE
        ${LIBLOGICALACCESS_COMMON_LIBRARIES}
)

# basic_desfire_sam
add_executable(basic_desfire_sam
    basic_desfire_sam.cpp
)

target_link_libraries(basic_desfire_sam
    PRIVATE
        ${LIBLOGICALACCESS_COMMON_LIBRARIES}
        samavcards
)

# basic_duox
add_executable(basic_duox
    basic_duox.cpp
)

target_link_libraries(basic_duox
    PRIVATE
        ${LIBLOGICALACCESS_COMMON_LIBRARIES}
)

# Installation
install(
    TARGETS
        basic
        basic_pki
        basic_desfire_sam
        basic_duox
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
)