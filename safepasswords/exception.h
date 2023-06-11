// Copyright (c) 2019-2022  Made to Order Software Corp.  All Rights Reserved
//
// https://snapwebsites.org/project/prinbee
// contact@m2osw.com
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#pragma once

/** \file
 * \brief Safe Passwords exceptions.
 *
 * This files declares a few exceptions that the Safe Passwords
 * implementation uses when a parameter is wrong or something goes
 * wrong (can't open a file, can't access OpenSSL, etc.)
 *
 * The Safe Passwords library also makes use of snaplogger so it
 * emits corresponding error messages along its exceptions.
 */


// libexcept
//
#include    <libexcept/exception.h>


namespace safepasswords
{



DECLARE_MAIN_EXCEPTION(safepasswords_exception);

DECLARE_EXCEPTION(safepasswords_exception, digest_not_available);
DECLARE_EXCEPTION(safepasswords_exception, encryption_failed);
DECLARE_EXCEPTION(safepasswords_exception, function_failure);
DECLARE_EXCEPTION(safepasswords_exception, invalid_parameter);
DECLARE_EXCEPTION(safepasswords_exception, not_enough_privileges);
DECLARE_EXCEPTION(safepasswords_exception, not_enough_resources);
DECLARE_EXCEPTION(safepasswords_exception, value_unavailable);



} // namespace safepasswords
// vim: ts=4 sw=4 et
