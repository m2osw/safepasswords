# - Find SafePasswords
#
# SAFEPASSWORDS_FOUND        - System has SafePasswords
# SAFEPASSWORDS_INCLUDE_DIRS - The SafePasswords include directories
# SAFEPASSWORDS_LIBRARIES    - The libraries needed to use SafePasswords
# SAFEPASSWORDS_DEFINITIONS  - Compiler switches required for using SafePasswords
#
# License:
#
# Copyright (c) 2011-2024  Made to Order Software Corp.  All Rights Reserved
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

find_path(
    SAFEPASSWORDS_INCLUDE_DIR
        safepasswords/version.h

    PATHS
        ENV SAFEPASSWORDS_INCLUDE_DIR
)

find_library(
    SAFEPASSWORDS_LIBRARY
        safepasswords

    PATHS
        ${SAFEPASSWORDS_LIBRARY_DIR}
        ENV SAFEPASSWORDS_LIBRARY
)

mark_as_advanced(
    SAFEPASSWORDS_INCLUDE_DIR
    SAFEPASSWORDS_LIBRARY
)

set(SAFEPASSWORDS_INCLUDE_DIRS ${SAFEPASSWORDS_INCLUDE_DIR})
set(SAFEPASSWORDS_LIBRARIES    ${SAFEPASSWORDS_LIBRARY})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    SafePasswords
    REQUIRED_VARS
        SAFEPASSWORDS_INCLUDE_DIR
        SAFEPASSWORDS_LIBRARY
)

# vim: ts=4 sw=4 et
