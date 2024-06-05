// Copyright (c) 2011-2024  Made to Order Software Corp.  All Rights Reserved
//
// https://snapwebsites.org/project/safepasswords
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

// safepasswords
//
#include    "safepasswords/utils.h"


// C++
//
#include    <algorithm>


// last include
//
#include    <snapdev/poison.h>



namespace safepasswords
{



/** \brief Clear a string so password do not stay in memory if possible.
 *
 * This function is used to clear the memory used by passwords. This
 * is a useful security trick, although really with encrypted passwords
 * in the Cassandra database, we will have passwords laying around anyway.
 *
 * \todo
 * See whether we could instead extend the std::string class? That way
 * we have that in the destructor and we can reuse it all over the place
 * where we load a password.
 *
 * \param[in,out] str  The string to clear.
 */
void clear_string(std::string & str)
{
    std::for_each(
              str.begin()
            , str.end()
            , [](auto & c)
            {
                c = 0;
            });
    str.clear();
}



} // namespace safepasswords
// vim: ts=4 sw=4 et
