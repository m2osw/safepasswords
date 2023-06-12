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

// C++
//
#include    <memory>
#include    <string>



namespace safepasswords
{



namespace detail
{
class buffer;
}


class string
{
public:
                            string(char const * s = nullptr, std::size_t l = static_cast<std::size_t>(-1));
                            string(string const & rhs);
                            ~string();

    string &                operator = (string const & rhs);

    std::size_t             length() const;
    bool                    empty() const;
    char const *            data() const;
    std::string             to_std_string() const;

    void                    clear();
    void                    resize(std::size_t size);

    string &                operator += (string const & rhs);
    string &                operator += (char c);
    string &                operator += (char const * s);
    string &                operator += (char32_t wc);

    string                  operator + (string const & rhs) const;
    string                  operator + (char c) const;
    string                  operator + (char const * s) const;
    string                  operator + (char32_t wc) const;

    std::strong_ordering    operator <=> (string const & rhs) const;
    bool                    operator == (string const & rhs) const;
    bool                    operator != (string const & rhs) const;

private:
    std::shared_ptr<detail::buffer>
                            f_buffer = std::shared_ptr<detail::buffer>();
};



} // namespace safepasswords
// vim: ts=4 sw=4 et
