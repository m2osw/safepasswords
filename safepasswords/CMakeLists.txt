# Copyright (c) 2011-2023 Made to Order Software Corp.  All Rights Reserved
#
# https://snapwebsites.org/project/safepasswords
# contact@m2osw.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

##
## safepasswords library
##
project(safepasswords CXX ASM)

# Put the version in the header file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/version.h
)

add_library(${PROJECT_NAME} SHARED
    file.cpp
    password.cpp
    string.cpp
    utils.cpp
    version.cpp
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${LIBEXCEPT_INCLUDE_DIRS}
        ${LIBUTF8_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${SNAPLOGGER_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME}
    ${LIBEXCEPT_LIBRARIES}
    ${LIBUTF8_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${SNAPLOGGER_LIBRARIES}
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION
        ${SAFEPASSWORDS_VERSION_MAJOR}.${SAFEPASSWORDS_VERSION_MINOR}

    SOVERSION
        ${SAFEPASSWORDS_VERSION_MAJOR}
)

install(
    TARGETS
        ${PROJECT_NAME}

    RUNTIME DESTINATION
        bin

    LIBRARY DESTINATION
        lib

    ARCHIVE DESTINATION
        lib
)

install(
    FILES
        exception.h
        file.h
        string.h
        ${CMAKE_CURRENT_BINARY_DIR}/version.h

    DESTINATION
        include/safepasswords
)


# vim: ts=4 sw=4 et
