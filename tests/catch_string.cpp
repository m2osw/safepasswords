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
#include    <safepasswords/string.h>


// C++
//
#include    <set>




namespace
{


bool is_zero(char const * ptr, std::size_t size)
{
    for(std::size_t idx(0); idx < size; ++idx)
    {
        if(ptr[idx] != '\0')
        {
            return false;
        }
    }

    return true;
}


}
// no name namespace



CATCH_TEST_CASE("string", "[string]")
{
    CATCH_START_SECTION("string: verify constructor (empty)")
    {
        safepasswords::string empty;
        CATCH_REQUIRE(empty.empty());
        CATCH_REQUIRE(empty.length() == 0);
        CATCH_REQUIRE(empty.data() == nullptr);
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("string: verify constructor (char const *)")
    {
        char const * ptr(nullptr);
        {
            safepasswords::string simple("password1");
            CATCH_REQUIRE_FALSE(simple.empty());
            CATCH_REQUIRE(simple.length() == 9);
            ptr = simple.data();
            CATCH_REQUIRE(ptr != nullptr);
            CATCH_REQUIRE(memcmp(simple.data(), "password1", 9) == 0);
        }
        CATCH_REQUIRE(is_zero(ptr, 9));
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("string: verify constructor (char const * + length)")
    {
        char const * ptr(nullptr);
        {
            safepasswords::string full("password1-and-length", 13);
            CATCH_REQUIRE_FALSE(full.empty());
            CATCH_REQUIRE(full.length() == 13);
            ptr = full.data();
            CATCH_REQUIRE(ptr != nullptr);
            CATCH_REQUIRE(memcmp(full.data(), "password1-and", 13) == 0);
        }
        CATCH_REQUIRE(is_zero(ptr, 13));
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("string: verify to_std_string()")
    {
        char const * secrets[] = {
            "pwd1",
            "top-secret",
            "hidden",
            "invisible",
        };
        for(std::size_t idx(0); idx < std::size(secrets); ++idx)
        {
            std::size_t const len(strlen(secrets[idx]));
            char const * ptr(nullptr);
            {
                safepasswords::string simple(secrets[idx]);
                CATCH_REQUIRE_FALSE(simple.empty());
                CATCH_REQUIRE(simple.length() == len);
                CATCH_REQUIRE(simple.to_std_string() == secrets[idx]);
                ptr = simple.data();
                CATCH_REQUIRE(ptr != nullptr);
                CATCH_REQUIRE(memcmp(simple.data(), secrets[idx], len) == 0);
            }
            CATCH_REQUIRE(is_zero(ptr, len));
        }
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("string: verify clear()")
    {
        char const * secrets[] = {
            "clear",
            "this",
            "secret",
            "now",
        };
        for(std::size_t idx(0); idx < std::size(secrets); ++idx)
        {
            std::size_t const len(strlen(secrets[idx]));
            char const * ptr(nullptr);
            {
                safepasswords::string p(secrets[idx]);
                CATCH_REQUIRE_FALSE(p.empty());
                CATCH_REQUIRE(p.length() == len);
                CATCH_REQUIRE(p.to_std_string() == secrets[idx]);
                ptr = p.data();
                CATCH_REQUIRE(ptr != nullptr);
                CATCH_REQUIRE(memcmp(p.data(), secrets[idx], len) == 0);
                p.clear();
                CATCH_REQUIRE(is_zero(ptr, len));
            }
        }
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("string: append one character at a time")
    {
        char const * secrets[] = {
            "clear",
            "this",
            "secret",
            "now",
        };
        for(std::size_t idx(0); idx < std::size(secrets); ++idx)
        {
            std::size_t const len(strlen(secrets[idx]));
            char const * ptr(nullptr);
            {
                safepasswords::string p;
                CATCH_REQUIRE(p.empty());
                for(std::size_t pos(0); pos < len; ++pos)
                {
                    p += secrets[idx][pos];
                }
                CATCH_REQUIRE(p.length() == len);
                CATCH_REQUIRE(p.to_std_string() == secrets[idx]);
                ptr = p.data();
                CATCH_REQUIRE(ptr != nullptr);
                CATCH_REQUIRE(memcmp(p.data(), secrets[idx], len) == 0);
                p.clear();
                CATCH_REQUIRE(is_zero(ptr, len));
            }
        }
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("string: append half a string at a time")
    {
        char const * secrets[] = {
            "a longer password is better here",
            "because we want to add two halves",
            "and then make sure that it worked as expected",
            "plus the smallest password should be 8 chars.",
        };
        for(std::size_t idx(0); idx < std::size(secrets); ++idx)
        {
            std::size_t const len(strlen(secrets[idx]));
            char const * ptr(nullptr);
            {
                safepasswords::string p;
                CATCH_REQUIRE(p.empty());

                // first half
                //
                char buf[256];
                memcpy(buf, secrets[idx], len / 2);
                buf[len / 2] = '\0';
                p += buf;
                CATCH_REQUIRE(p.length() == len / 2);
                CATCH_REQUIRE(p.to_std_string() == buf);

                // second half
                //
                p += secrets[idx] + len / 2;
                CATCH_REQUIRE(p.length() == len);
                CATCH_REQUIRE(p.to_std_string() == secrets[idx]);
                ptr = p.data();
                CATCH_REQUIRE(ptr != nullptr);
                CATCH_REQUIRE(memcmp(p.data(), secrets[idx], len) == 0);

                // reset
                //
                p.clear();
                CATCH_REQUIRE(is_zero(ptr, len));
            }
        }
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("string: append passwords together")
    {
        char const * secrets[] = {
            "a longer password is better here",
            "because we want to add two halves",
            "and then make sure that it worked as expected",
            "plus the smallest password should be 8 chars.",
        };

        char const * ptr(nullptr);
        std::string concatenation;

        {
            safepasswords::string p;
            CATCH_REQUIRE(p.empty());

            for(std::size_t idx(0); idx < std::size(secrets); ++idx)
            {
                safepasswords::string end(secrets[idx], strlen(secrets[idx]));
                p += end;
                concatenation += secrets[idx];

                CATCH_REQUIRE(p.to_std_string() == concatenation);
            }

            ptr = p.data();
        }

        CATCH_REQUIRE(is_zero(ptr, concatenation.length()));
    }
    CATCH_END_SECTION()

}


// vim: ts=4 sw=4 et
