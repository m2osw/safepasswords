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
#include    <safepasswords/file.h>

#include    <safepasswords/exception.h>


// snapdev
//
#include    <snapdev/hexadecimal_string.h>
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



namespace
{


std::string get_tmp_dir(char const * filename)
{
    return SNAP_CATCH2_NAMESPACE::g_tmp_dir() + '/' + filename;
}


}
// no name namespace



CATCH_TEST_CASE("file_load", "[file][load][save]")
{
    CATCH_START_SECTION("file_load: create file with a few entries")
    {
        std::string const filename(get_tmp_dir("entries.pwd"));
        {
            std::ofstream out;
            out.open(filename);
            CATCH_REQUIRE(out.is_open());

            // valid entries
            //
            out << "name:sha512:"
                << snapdev::bin_to_hex("salt--0123456789")
                << ':'
                << snapdev::bin_to_hex("encrypted-password")
                << '\n';
            out << "user:sha3-224:"
                << snapdev::bin_to_hex("the-salt-is-1234")
                << ':'
                << snapdev::bin_to_hex("another-secret-password")
                << '\n';
            out << "walker:sha3-256:"
                << snapdev::bin_to_hex("salt-is-16bytes!")
                << ':'
                << snapdev::bin_to_hex("you'll never find this_passworD1")
                << '\n';
            out << "alexa:md5:"
                << snapdev::bin_to_hex("more salt here..")
                << ':'
                << snapdev::bin_to_hex("wonder what the password is?")
                << '\n';
            out << "lexa:sha1:"
                << snapdev::bin_to_hex("salt is randomiz")
                << ':'
                << snapdev::bin_to_hex("and SHA1 is really bad, don't use it")
                << '\n';
            out << "lex:sha3-256:"
                << snapdev::bin_to_hex("short name here!")
                << ':'
                << snapdev::bin_to_hex("old version would not find \"lex\" when we have \"alexa\" and \"lexa\" before...")
                << '\n';

            // invalid entries
            //
            out << "no-password:sha3-256:"
                << snapdev::bin_to_hex("salt-is-16bytes!")
                << '\n';
            out << "missing-salt:sha3-256"
                << '\n';
            out << "without-digest"     // this means we do not find that user
                << '\n';

            // MUST BE LAST -- ADD MORE BEFORE THIS ENTRY
            // invalid entry -- the "\n" is missing
            //
            out << "missing:newline:character:here";
        }
        safepasswords::file f(filename);
        safepasswords::password p;

        // first try one which does not exist
        //
        CATCH_REQUIRE_FALSE(f.find("anyone", p));

        CATCH_REQUIRE(f.find("name", p));
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "sha512");
        CATCH_REQUIRE(p.get_salt() == "salt--0123456789");
        CATCH_REQUIRE(p.get_encrypted() == "encrypted-password");

        CATCH_REQUIRE(f.find("user", p));
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "sha3-224");
        CATCH_REQUIRE(p.get_salt() == "the-salt-is-1234");
        CATCH_REQUIRE(p.get_encrypted() == "another-secret-password");

        CATCH_REQUIRE(f.find("walker", p));
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "sha3-256");
        CATCH_REQUIRE(p.get_salt() == "salt-is-16bytes!");
        CATCH_REQUIRE(p.get_encrypted() == "you'll never find this_passworD1");

        CATCH_REQUIRE(f.find("alexa", p));
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "md5");
        CATCH_REQUIRE(p.get_salt() == "more salt here..");
        CATCH_REQUIRE(p.get_encrypted() == "wonder what the password is?");

        CATCH_REQUIRE(f.find("lexa", p));
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "sha1");
        CATCH_REQUIRE(p.get_salt() == "salt is randomiz");
        CATCH_REQUIRE(p.get_encrypted() == "and SHA1 is really bad, don't use it");

        CATCH_REQUIRE(f.find("lex", p));
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "sha3-256");
        CATCH_REQUIRE(p.get_salt() == "short name here!");
        CATCH_REQUIRE(p.get_encrypted() == "old version would not find \"lex\" when we have \"alexa\" and \"lexa\" before...");

        CATCH_REQUIRE_FALSE(f.find("no-password", p));
        CATCH_REQUIRE_FALSE(f.find("missing-salt", p));
        CATCH_REQUIRE_FALSE(f.find("without-digest", p));

        CATCH_REQUIRE_FALSE(f.find("missing", p)); // newline not in string

        // these reset the password
        //
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "sha3-256");
        CATCH_REQUIRE(p.get_salt().empty());

        CATCH_REQUIRE_FALSE(p.get_encrypted().empty()); // this regenerates a new password

        f.save("some_new_user", p);

        // also try replacing an existing user
        //
        safepasswords::password q;
        CATCH_REQUIRE_FALSE(q.get_encrypted().empty());
        f.save("user", q);
    }
    CATCH_END_SECTION()
}


CATCH_TEST_CASE("file_remove", "[file][save][load][remove]")
{
    CATCH_START_SECTION("file_remove: create file, close, re-load, remove, re-re-load, re-remove")
    {
        char const * user_names[] = {
            "charlie",
            "hubert",
            "julius",
            "pompom",
            "henri",
            "louis",
            "jesus",
        };
        std::string const filename(get_tmp_dir("removal.pwd"));

        std::vector<safepasswords::password> v;
        {
            safepasswords::file f(filename);

            for(std::size_t idx(0); idx < std::size(user_names); ++idx)
            {
                safepasswords::password p;
                p.generate(); // this regenerates a new password
                CATCH_REQUIRE(f.save(user_names[idx], p));
                v.push_back(p);
            }
        }

        {
            safepasswords::file f(filename);

            for(std::size_t idx(0); idx < std::size(user_names); ++idx)
            {
                safepasswords::password p;
                CATCH_REQUIRE(f.find(user_names[idx], p));

                // make sure it did not change between the save + load
                //
                CATCH_REQUIRE(v[idx].get_digest() == p.get_digest());
                CATCH_REQUIRE(v[idx].get_salt() == p.get_salt());
                CATCH_REQUIRE(v[idx].get_encrypted() == p.get_encrypted());

                // remove the odd ones
                //
                if((idx & 1) != 0)
                {
                    CATCH_REQUIRE(f.remove(user_names[idx]));
                }
            }
        }

        {
            safepasswords::file f(filename);

            for(std::size_t idx(0); idx < std::size(user_names); ++idx)
            {
                safepasswords::password p;
                if((idx & 1) != 0)
                {
                    // this one was removed, so we won't find it
                    //
                    CATCH_REQUIRE_FALSE(f.find(user_names[idx], p));

                    // we can re-remove, nothing happens
                    //
                    CATCH_REQUIRE(f.remove(user_names[idx]));
                }
                else
                {
                    CATCH_REQUIRE(f.find(user_names[idx], p));

                    // make sure it's still there
                    //
                    CATCH_REQUIRE(v[idx].get_digest() == p.get_digest());
                    CATCH_REQUIRE(v[idx].get_salt() == p.get_salt());
                    CATCH_REQUIRE(v[idx].get_encrypted() == p.get_encrypted());
                }
            }
        }

    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("file_remove: missing '\\n'")
    {
        std::string const filename(get_tmp_dir("missing-nl.pwd"));
        {
            std::ofstream out;
            out.open(filename);
            CATCH_REQUIRE(out.is_open());

            // valid entry
            //
            out << "correct:md5:"
                << snapdev::bin_to_hex("salt--0123456789")
                << ':'
                << snapdev::bin_to_hex("entry for once")
                << '\n';

            // invalid entry
            //
            out << "missing-nl:sha512:"     // missing '\n' at the end
                << snapdev::bin_to_hex("even more salt!!")
                << ':'
                << snapdev::bin_to_hex("entry for once");
        }

        {
            safepasswords::file f(filename);
            safepasswords::password p;

            CATCH_REQUIRE(f.next(p) == "correct");
            CATCH_REQUIRE(f.next(p).empty()); // we already cannot load "missing-nl" in this case

            CATCH_REQUIRE(f.remove("missing-nl"));
        }

        {
            safepasswords::file f(filename);
            safepasswords::password p;

            CATCH_REQUIRE(f.next(p) == "correct");
            CATCH_REQUIRE(f.next(p).empty()); // so this tests nothing since it was already not loadable before the remove...

            // but I could verify by hand and it works...
            //
            // TODO:
            // what we would have to do is create a memory version of what
            // is expected in the file and reload with file_contents to
            // make sure it is equal to what's expected
        }
    }
    CATCH_END_SECTION()
}


CATCH_TEST_CASE("file_iterate", "[file][iterate][load]")
{
    CATCH_START_SECTION("file_iterate: create file, close, load, go through with next()")
    {
        char const * user_names[] = {
            "charlotte",
            "henriette",
            "julia",
            "ponpon",
            "theo",
            "louisa",
            "angel",
        };
        std::string const filename(get_tmp_dir("iterate.pwd"));

        std::vector<safepasswords::password> v;
        {
            safepasswords::file f(filename);

            for(std::size_t idx(0); idx < std::size(user_names); ++idx)
            {
                safepasswords::password p;
                p.generate(); // this regenerates a new password
                CATCH_REQUIRE(f.save(user_names[idx], p));
                v.push_back(p);
            }
        }

        {
            safepasswords::file f(filename);

            for(std::size_t idx(0);; ++idx)
            {
                safepasswords::password p;
                std::string const username(f.next(p));
                if(username.empty())
                {
                    std::string const still_empty(f.next(p));
                    CATCH_REQUIRE(still_empty.empty());
                    break;
                }

                // make sure it did not change between the save + load
                //
                CATCH_REQUIRE(idx < std::size(user_names));
                CATCH_REQUIRE(username == user_names[idx]);
                CATCH_REQUIRE(v[idx].get_digest() == p.get_digest());
                CATCH_REQUIRE(v[idx].get_salt() == p.get_salt());
                CATCH_REQUIRE(v[idx].get_encrypted() == p.get_encrypted());
            }

            // do it a second time after a rewind
            //
            f.rewind();

            for(std::size_t idx(0);; ++idx)
            {
                safepasswords::password p;
                std::string const username(f.next(p));
                if(username.empty())
                {
                    std::string const still_empty(f.next(p));
                    CATCH_REQUIRE(still_empty.empty());
                    break;
                }

                // make sure it did not change between the save + load
                //
                CATCH_REQUIRE(idx < std::size(user_names));
                CATCH_REQUIRE(username == user_names[idx]);
                CATCH_REQUIRE(v[idx].get_digest() == p.get_digest());
                CATCH_REQUIRE(v[idx].get_salt() == p.get_salt());
                CATCH_REQUIRE(v[idx].get_encrypted() == p.get_encrypted());
            }
        }
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("file_iterate: name not followed by ':'")
    {
        std::string const filename(get_tmp_dir("entries.pwd"));
        {
            std::ofstream out;
            out.open(filename);
            CATCH_REQUIRE(out.is_open());

            // valid entry
            //
            out << "valid:sha512:"
                << snapdev::bin_to_hex("salt--0123456789")
                << ':'
                << snapdev::bin_to_hex("entry for once")
                << '\n';

            // invalid entry
            //
            out << "without-digest"     // no ':' after user name
                << '\n';
        }
        safepasswords::file f(filename);
        safepasswords::password p;

        // first is valid
        //
        CATCH_REQUIRE(f.next(p) == "valid");
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "sha512");
        CATCH_REQUIRE(p.get_salt() == "salt--0123456789");
        CATCH_REQUIRE(p.get_encrypted() == "entry for once");

        CATCH_REQUIRE(f.next(p).empty());
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "sha512");
        CATCH_REQUIRE(p.get_salt().empty());
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("file_iterate: empty name not valid")
    {
        std::string const filename(get_tmp_dir("entries.pwd"));
        {
            std::ofstream out;
            out.open(filename);
            CATCH_REQUIRE(out.is_open());

            // valid entry
            //
            out << "correct:md5:"
                << snapdev::bin_to_hex("salt--0123456789")
                << ':'
                << snapdev::bin_to_hex("entry for once")
                << '\n';

            // invalid entry
            //
            out << ":sha512:"     // no name before ':'
                << snapdev::bin_to_hex("even more salt!!")
                << ':'
                << snapdev::bin_to_hex("name is missing")
                << '\n';
        }
        safepasswords::file f(filename);
        safepasswords::password p;

        // first is valid
        //
        CATCH_REQUIRE(f.next(p) == "correct");
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "md5");
        CATCH_REQUIRE(p.get_salt() == "salt--0123456789");
        CATCH_REQUIRE(p.get_encrypted() == "entry for once");

        CATCH_REQUIRE(f.next(p).empty());
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "md5");
        CATCH_REQUIRE(p.get_salt().empty());
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("file_iterate: missing encrypted value")
    {
        std::string const filename(get_tmp_dir("entries.pwd"));
        {
            std::ofstream out;
            out.open(filename);
            CATCH_REQUIRE(out.is_open());

            // valid entry
            //
            out << "correct:md5:"
                << snapdev::bin_to_hex("salt--0123456789")
                << ':'
                << snapdev::bin_to_hex("entry for once")
                << '\n';

            // invalid entry
            //
            out << "missing-stuff:sha512:"     // missing encrypted value
                << snapdev::bin_to_hex("even more salt!!")
                << '\n';
        }
        safepasswords::file f(filename);
        safepasswords::password p;

        // first is valid
        //
        CATCH_REQUIRE(f.next(p) == "correct");
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "md5");
        CATCH_REQUIRE(p.get_salt() == "salt--0123456789");
        CATCH_REQUIRE(p.get_encrypted() == "entry for once");

        CATCH_REQUIRE(f.next(p).empty());
        CATCH_REQUIRE(p.get_plain().empty());
        CATCH_REQUIRE(p.get_digest() == "md5");
        CATCH_REQUIRE(p.get_salt().empty());
    }
    CATCH_END_SECTION()
}


CATCH_TEST_CASE("file_missing", "[file][load][save]")
{
    CATCH_START_SECTION("file_missing: attempt to load missing file, find fails")
    {
        safepasswords::file f(get_tmp_dir("missing.pwd"));
        safepasswords::password p;
        CATCH_REQUIRE_FALSE(f.find("anyone", p));
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("file_missing: attempt to load missing file, next fails")
    {
        safepasswords::file f(get_tmp_dir("missing.pwd"));
        safepasswords::password p;
        CATCH_REQUIRE(f.next(p).empty());
    }
    CATCH_END_SECTION()
}


CATCH_TEST_CASE("file_with_errors", "[file][error]")
{
    CATCH_START_SECTION("file_with_errors: verify invalid find() call")
    {
        safepasswords::file f(get_tmp_dir("ignore.pwd"));
        safepasswords::password p;
        CATCH_REQUIRE_THROWS_MATCHES(
                  f.find(std::string(), p)
                , safepasswords::invalid_parameter
                , Catch::Matchers::ExceptionMessage(
                          "safepasswords_exception: the file::find()/file::save()/file::remove() functions"
                          " cannot be called with an empty string in 'name'."));
    }
    CATCH_END_SECTION()

    CATCH_START_SECTION("file_with_errors: verify invalid save() call")
    {
        safepasswords::file f(get_tmp_dir("ignore.pwd"));
        safepasswords::password p;
        CATCH_REQUIRE_THROWS_MATCHES(
                  f.save(std::string(), p)
                , safepasswords::invalid_parameter
                , Catch::Matchers::ExceptionMessage(
                          "safepasswords_exception: the file::find()/file::save()/file::remove() functions"
                          " cannot be called with an empty string in 'name'."));
    }
    CATCH_END_SECTION()
}



// vim: ts=4 sw=4 et
