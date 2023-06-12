// Copyright (c) 2011-2023  Made to Order Software Corp.  All Rights Reserved
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
#pragma once

// self
//
#include    <safepasswords/string.h>



namespace safepasswords
{



constexpr int const         PASSWORD_MIN_LENGTH =             8;
constexpr int const         PASSWORD_MAX_LENGTH =         4'000;
constexpr int const         PASSWORD_DEFAULT_MIN_LENGTH =    64;
constexpr int const         PASSWORD_DEFAULT_MAX_LENGTH =   200;


class password
{
public:
                            password();
                            ~password();

    void                    clear();

    void                    set_digest(std::string const & digest);
    std::string const &     get_digest() const;

    void                    generate(int min_length = PASSWORD_DEFAULT_MIN_LENGTH, int max_length = PASSWORD_DEFAULT_MAX_LENGTH);
    void                    set_plain(string const & plain, string const & salt = string());
    string const &          get_plain() const;
    bool                    get_from_console(string const & salt = string());

    string const &          get_salt() const;

    void                    set_encrypted(string const & encrypted, string const & salt);
    string const &          get_encrypted() const;

    std::strong_ordering    operator <=> (password const & rhs) const;

private:
    void                    generate_salt();
    void                    encrypt();

    std::string             f_digest = std::string("sha512");
    string                  f_plain = string();
    string                  f_salt = string();
    string                  f_encrypted = string();
};



} // namespace safepasswords
// vim: ts=4 sw=4 et
