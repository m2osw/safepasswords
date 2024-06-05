// Copyright (c) 2019-2024  Made to Order Software Corp.  All Rights Reserved
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

#include    <safepasswords/exception.h>


// snapdev
//
#include    <snapdev/not_used.h>


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



namespace safepasswords
{
namespace detail
{

// for test purposes, we can capture the free() call, ignore otherwise
typedef void (*free_callback_t)(void * ptr);
void set_free_callback(free_callback_t callback);

} // namespace detail
} // namespace safepasswords


namespace
{


bool is_zero(char const * ptr, std::size_t size)
{
    for(std::size_t idx(0); idx < size; ++idx)
    {
        if(ptr[idx] != '\0')
        {
            std::cerr << "--- bad character at " << idx
                << ": '0x" << std::hex << static_cast<int>(ptr[idx] & 0xFF)
                << std::dec
                << "' (ptr: " << static_cast<void const *>(ptr) << ")"
                << "\n";
            return false;
        }
    }

    return true;
}


void free_callback(void * ptr)
{
    std::size_t const size(malloc_usable_size(ptr));
    is_zero(static_cast<char const *>(ptr), size);
    ::free(ptr);
}


}
// no name namespace



CATCH_TEST_CASE("string", "[string]")
{
    safepasswords::detail::set_free_callback(free_callback);

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
        safepasswords::string simple("password1");
        CATCH_REQUIRE_FALSE(simple.empty());
        CATCH_REQUIRE(simple.length() == 9);
        char const * ptr(simple.data());
        CATCH_REQUIRE(ptr != nullptr);
        CATCH_REQUIRE(memcmp(ptr, "password1", 9) == 0);
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("string: verify constructor (char const * + length)")
    {
        safepasswords::string full("password1-and-length", 13);
        CATCH_REQUIRE_FALSE(full.empty());
        CATCH_REQUIRE(full.length() == 13);
        char const * ptr(full.data());
        CATCH_REQUIRE(ptr != nullptr);
        CATCH_REQUIRE(memcmp(ptr, "password1-and", 13) == 0);
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
            safepasswords::string simple(secrets[idx]);
            CATCH_REQUIRE_FALSE(simple.empty());
            CATCH_REQUIRE(simple.length() == len);
            CATCH_REQUIRE(simple.to_std_string() == secrets[idx]);
            char const * ptr(simple.data());
            CATCH_REQUIRE(ptr != nullptr);
            CATCH_REQUIRE(memcmp(ptr, secrets[idx], len) == 0);
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
            safepasswords::string p(secrets[idx]);
            CATCH_REQUIRE_FALSE(p.empty());
            CATCH_REQUIRE(p.length() == len);
            CATCH_REQUIRE(p.to_std_string() == secrets[idx]);
            char const * ptr(p.data());
            CATCH_REQUIRE(ptr != nullptr);
            CATCH_REQUIRE(memcmp(p.data(), secrets[idx], len) == 0);
            p.clear();
            CATCH_REQUIRE(is_zero(ptr, len));
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
            safepasswords::string p;
            CATCH_REQUIRE(p.empty());
            for(std::size_t pos(0); pos < len; ++pos)
            {
                p += secrets[idx][pos];
            }
            CATCH_REQUIRE(p.length() == len);
            CATCH_REQUIRE(p.to_std_string() == secrets[idx]);
            char const * ptr(p.data());
            CATCH_REQUIRE(ptr != nullptr);
            CATCH_REQUIRE(memcmp(p.data(), secrets[idx], len) == 0);
            p.clear();
            CATCH_REQUIRE(is_zero(ptr, len));

            // try, but this time transform the character in a char32_t
            //
            p.clear();
            CATCH_REQUIRE(p.empty());
            for(std::size_t pos(0); pos < len; ++pos)
            {
                char32_t c(secrets[idx][pos]);
                p += c;
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

        std::string concatenation;

        safepasswords::string p;
        CATCH_REQUIRE(p.empty());

        for(std::size_t idx(0); idx < std::size(secrets); ++idx)
        {
            safepasswords::string end(secrets[idx], strlen(secrets[idx]));
            p += end;
            concatenation += secrets[idx];

            CATCH_REQUIRE(p.to_std_string() == concatenation);
        }
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("string: append passwords to new ones")
    {
        char const * secrets[] = {
            "A longer password is better here",
            "because we want to add two halves",
            "and then make sure that it worked as expected",
            "plus the smallest password should be 8 chars.",
            "This time we want an even number of passwords",
            "so we can pair them into one",
        };
        CATCH_REQUIRE((std::size(secrets) & 1) == 0);

        safepasswords::string p;
        CATCH_REQUIRE(p.empty());

        for(std::size_t idx(0); idx < std::size(secrets); idx += 2)
        {
            safepasswords::string b(secrets[idx], strlen(secrets[idx]));
            safepasswords::string c(secrets[idx + 1], strlen(secrets[idx + 1]));
            safepasswords::string a;
            a = b + c;

            std::string concatenation(secrets[idx]);
            concatenation += secrets[idx + 1];

            CATCH_REQUIRE(a.to_std_string() == concatenation);
            CATCH_REQUIRE(b.to_std_string() == std::string(secrets[idx]));
            CATCH_REQUIRE(c.to_std_string() == std::string(secrets[idx + 1]));

            safepasswords::string d(b + "string");
            concatenation = secrets[idx];
            concatenation += "string";
            CATCH_REQUIRE(d.to_std_string() == concatenation);

            safepasswords::string e(c + '!');
            concatenation = secrets[idx + 1];
            concatenation += "!";
            CATCH_REQUIRE(e.to_std_string() == concatenation);

            char32_t wc(SNAP_CATCH2_NAMESPACE::random_char(SNAP_CATCH2_NAMESPACE::character_t::CHARACTER_UNICODE));
            safepasswords::string f(b + wc);
            concatenation = secrets[idx];
            concatenation += libutf8::to_u8string(wc);
            CATCH_REQUIRE(f.to_std_string() == concatenation);
        }
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("string: compare")
    {
        char const * secrets[] = {
            "A longer password is better here",
            "because we want to add two halves",
            "and then make sure that it worked as expected",
            "plus the smallest password should be 8 chars.",
            "This time we want an even number of passwords",
            "so we can pair them into one",
        };

        for(std::size_t idx(0); idx < std::size(secrets) - 1; ++idx)
        {
            safepasswords::string a(secrets[idx], strlen(secrets[idx]));
            safepasswords::string b(secrets[idx + 1], strlen(secrets[idx + 1]));

            auto const r(a <=> b);
            auto const q(std::string(secrets[idx]) <=> std::string(secrets[idx + 1]));

            CATCH_REQUIRE(r == q);
            CATCH_REQUIRE(a != b);

            auto const s(a <=> a);
            CATCH_REQUIRE(s == std::strong_ordering::equal);
            CATCH_REQUIRE(a == a);

            safepasswords::string p;
            for(std::size_t pos(0); pos < a.length() - 1; ++pos)
            {
                p += a.data()[pos];

                auto const t(a <=> p);
                CATCH_REQUIRE(t == std::strong_ordering::greater);

                auto const u(p <=> a);
                CATCH_REQUIRE(u == std::strong_ordering::less);

                safepasswords::string c(a);
                c.resize(pos);

                auto const v(a <=> c);
                CATCH_REQUIRE(v == std::strong_ordering::greater);

                auto const w(c <=> a);
                CATCH_REQUIRE(w == std::strong_ordering::less);
            }
        }
    }
    CATCH_END_SECTION()
}


CATCH_TEST_CASE("large_string", "[string]")
{
    safepasswords::detail::set_free_callback(free_callback);

    CATCH_START_SECTION("large_string: create a very large string spanning multiple pages")
    {
        long const page_size(sysconf(_SC_PAGESIZE));
        std::size_t const max_size(page_size * 5 + 100);
        safepasswords::string large;
        std::string copy;
        while(large.length() < max_size)
        {
            char32_t const wc(SNAP_CATCH2_NAMESPACE::random_char(SNAP_CATCH2_NAMESPACE::character_t::CHARACTER_UNICODE));
            large += wc;
            copy += libutf8::to_u8string(wc);

            CATCH_REQUIRE_FALSE(large.empty());
            CATCH_REQUIRE(large.to_std_string() == copy);
        }
    }
    CATCH_END_SECTION()
}


CATCH_TEST_CASE("string_with_errors", "[string][error]")
{
    CATCH_START_SECTION("string_with_errors: verify invalid unicode character")
    {
        safepasswords::string p;
        char32_t wc(0x2022);        // valid
        p += wc;
        wc = 0xD999;                // surrogate not valid in char32_t
        CATCH_REQUIRE_THROWS_MATCHES(
                  p += wc
                , safepasswords::invalid_parameter
                , Catch::Matchers::ExceptionMessage(
                          "safepasswords_exception: wc passed to this function does not represent a"
                          " valid Unicode character."));
    }
    CATCH_END_SECTION()
}



// vim: ts=4 sw=4 et
