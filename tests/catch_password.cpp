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
#include    <safepasswords/password.h>

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



CATCH_TEST_CASE("password", "[password]")
{
    CATCH_START_SECTION("password: verify constructor (empty)")
    {
        safepasswords::password p;
        CATCH_REQUIRE(p.get_digest() == "sha512");  // digest has a default
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_salt().empty());

        // the get_encrypted() actually generates a password if none is
        // defined, so it is not going to be empty ever and then the
        // plain & salt strings are also not empty after this call
        //
        CATCH_REQUIRE_FALSE(p.get_encrypted().empty());

        CATCH_REQUIRE_FALSE(p.get_plain().empty());
        CATCH_REQUIRE_FALSE(p.get_salt().empty());

        // try setting it back, this clears the plain password
        //
        safepasswords::string encrypted(p.get_encrypted());
        safepasswords::string salt(p.get_salt());
        p.set_encrypted(encrypted, salt);

        CATCH_REQUIRE(p.get_encrypted() == encrypted);
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_salt() == salt);

        // test the clear() function
        //
        p.clear();
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_salt().empty());
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("password: compare passwords with varying digests")
    {
        // try the following command to get a list of existing digests:
        //
        //   generate-password --list-digests
        //
        char const * const digests[] = {
            "sha256",
            "sha512",
            "md5",
            "2.16.840.1.101.3.4.2.11", // SHAKE-128
            "sha1",
            "ssl3-md5",
            "sha384",
            "sha224",
            "sm3",
            "blake2s256",
        };
        for(std::size_t idx(0); idx < std::size(digests); ++idx)
        {
            std::string const p1(SNAP_CATCH2_NAMESPACE::random_string(1, 100));
            std::string const p2(SNAP_CATCH2_NAMESPACE::random_string(1, 100));

            safepasswords::password password1;
            password1.set_digest(digests[idx]);
            password1.set_plain(safepasswords::string(p1.c_str(), p1.length()));
            safepasswords::password password2;
            password2.set_digest(digests[(idx + rand() % 20) % std::size(digests)]);
            password2.set_plain(safepasswords::string(p2.c_str(), p2.length()));

            auto r(password1 <=> password2);
            auto q(password1.get_encrypted().to_std_string() <=> password2.get_encrypted().to_std_string());
            CATCH_REQUIRE(r == q);
        }
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("password: generate short passwords")
    {
        for(int idx(0); idx < 10; ++idx)
        {
            int const min_len(rand() % 16 + 16);
            int const max_len(min_len + rand() % 10);

            safepasswords::password p;
            p.generate(min_len, max_len);

            CATCH_REQUIRE(p.get_plain().length() >= static_cast<std::size_t>(min_len));
            CATCH_REQUIRE(p.get_plain().length() <= static_cast<std::size_t>(max_len));

            // try again with equal min/max
            //
            p.generate(min_len, min_len);
            CATCH_REQUIRE(p.get_plain().length() == static_cast<std::size_t>(min_len));
        }
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("password: generate passwords with negative max. length")
    {
        for(int idx(0); idx < 10; ++idx)
        {
            int const min_len(rand() % 16 + 16);
            int const max_len(-min_len - rand() % 10);

            safepasswords::password p;
            p.generate(min_len, max_len);

            CATCH_REQUIRE(p.get_plain().length() >= static_cast<std::size_t>(min_len));
            CATCH_REQUIRE(p.get_plain().length() <= safepasswords::PASSWORD_DEFAULT_MAX_LENGTH);
        }
    }
    CATCH_END_SECTION()
}


CATCH_TEST_CASE("password_invalid", "[password][error]")
{
    CATCH_START_SECTION("password_invalid: unknown digest")
    {
        safepasswords::password bad_digest;

        CATCH_REQUIRE_THROWS_MATCHES(
                  bad_digest.set_digest("bad-digest")
                , safepasswords::digest_not_available
                , Catch::Matchers::ExceptionMessage(
                          "safepasswords_exception: the specified digest (bad-digest) was not found."));

        CATCH_REQUIRE(bad_digest.get_digest() == "sha512");

        // the get_encrypted() still works, it just uses the default digest
        //
        bad_digest.get_encrypted();
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("password_invalid: invalid salt length")
    {
        safepasswords::password bad_salt;
        safepasswords::string p("test", 4);
        safepasswords::string s("bad", 3);

        CATCH_REQUIRE_THROWS_MATCHES(
                  bad_salt.set_plain(p, s)
                , safepasswords::invalid_parameter
                , Catch::Matchers::ExceptionMessage(
                          "safepasswords_exception: if defined, the salt must be exactly 32 bytes."));
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("password_invalid: generate passwords where min > max")
    {
        for(int idx(0); idx < 10; ++idx)
        {
            int const min_len(rand() % 16 + 16);
            int const max_len(min_len + rand() % 10 + 1);

            safepasswords::password p;

            CATCH_REQUIRE_THROWS_MATCHES(
                      p.generate(max_len, min_len)
                    , safepasswords::invalid_parameter
                    , Catch::Matchers::ExceptionMessage(
                              "safepasswords_exception: adjusted minimum and"
                              " maximum lengths are improperly sorted; minimum "
                            + std::to_string(max_len)  // it is swapped above, so swapped here too
                            + " is larger than maximum "
                            + std::to_string(min_len)
                            + '.'));
        }
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("password_invalid: generate passwords where max < 8")
    {
        for(int max_len(0); max_len < safepasswords::PASSWORD_MIN_LENGTH; ++max_len)
        {
            safepasswords::password p;

            // minimum gets adjusted to safepasswords::PASSWORD_MIN_LENGTH
            // so any maximum that is smaller than that value will generate
            // an error
            //
            CATCH_REQUIRE_THROWS_MATCHES(
                      p.generate(0, max_len)
                    , safepasswords::invalid_parameter
                    , Catch::Matchers::ExceptionMessage(
                              "safepasswords_exception: adjusted minimum and "
                              "maximum lengths are improperly sorted; minimum "
                            + std::to_string(safepasswords::PASSWORD_MIN_LENGTH)  // the adjusted minimum
                            + " is larger than maximum "
                            + std::to_string(max_len)
                            + '.'));
        }
    }
    CATCH_END_SECTION()
}



// vim: ts=4 sw=4 et
