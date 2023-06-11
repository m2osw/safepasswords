// Copyright (c) 2011-2023  Made to Order Software Corp.  All Rights Reserved
//
// https://snapwebsites.org/project/passwordstring
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
#include    <safepasswords/password.h>


// snapdev
//
#include    <snapdev/file_contents.h>



namespace safepasswords
{



class file
{
public:
                            file(std::string const & password_filename);
                            ~file();

    bool                    find(std::string const & name, password & p);
    bool                    save(std::string const & name, password const & p);
    bool                    remove(std::string const & name);
    std::string             next(password & p);
    void                    rewind();

private:
    bool                    load_passwords();

    bool                    f_file_loaded = false;
    std::string::size_type  f_next = 0;
    snapdev::file_contents  f_passwords;
};



} // namespace safepasswords
// vim: ts=4 sw=4 et
