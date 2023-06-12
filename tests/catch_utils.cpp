// Copyright (c) 2019-2023  Made to Order Software Corp.  All Rights Reserved
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

// self
//
#include    "catch_main.h"


// safepasswords
//
#include    <safepasswords/utils.h>


// libutf8
//
#include    <libutf8/libutf8.h>


// C++
//
#include    <set>


// C
//
#include    <malloc.h>


// last include
//
#include    <snapdev/poison.h>



CATCH_TEST_CASE("utils", "[utils][string]")
{
    CATCH_START_SECTION("utils: clear string")
    {
        for(int count(0); count < 10; ++count)
        {
            std::string s;
            std::size_t const length(rand() % 200 + 1);
            for(std::size_t l(0); l < length; ++l)
            {
                char32_t const wc(SNAP_CATCH2_NAMESPACE::random_char(SNAP_CATCH2_NAMESPACE::character_t::CHARACTER_UNICODE));
                s += libutf8::to_u8string(wc);
            }
            CATCH_REQUIRE_FALSE(s.empty());
            safepasswords::clear_string(s);
            CATCH_REQUIRE(s.empty());
        }
    }
    CATCH_END_SECTION()
}



// vim: ts=4 sw=4 et
