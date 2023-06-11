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


// self
//
#include    "safepasswords/string.h"

#include    "safepasswords/exception.h"
//#include    "safepasswords/utils.h"


// snapdev
//
#include    <snapdev/not_used.h>


// libutf8
//
#include    <libutf8/base.h>
#include    <libutf8/libutf8.h>


// C++
//
#include    <compare>
#include    <iostream>


// C
//
#include    <string.h>
#include    <sys/mman.h>


// last include
//
#include    <snapdev/poison.h>



namespace safepasswords
{



namespace detail
{



class buffer
{
public:
                            buffer();
                            ~buffer();
                            buffer(buffer const & rhs) = delete;
    buffer &                operator = (buffer const & rhs) = delete;

    void                    set_size(std::size_t size);
    std::size_t             get_size() const;

    char *                  data() const;

private:
    static std::size_t      get_page_size();
    static std::size_t      adjusted_size(std::size_t size);
    static void *           allocate_buffer(std::size_t size);

    void *                  f_data = nullptr;
    std::size_t             f_size = 0;
    std::size_t             f_available = 0;        // available size
};


buffer::buffer()
{
}


buffer::~buffer()
{
    if(f_data != nullptr)
    {
        memset(f_data, 0, f_size);
        snapdev::NOT_USED(munlock(f_data, f_available));
        free(f_data);
    }
}


void buffer::set_size(std::size_t size)
{
    if(size > f_available)
    {
        std::size_t const new_size(adjusted_size(size));
        void * new_data(allocate_buffer(new_size));
        if(f_data != nullptr)
        {
            // size is too large for the existing buffer
            //
            memcpy(new_data, f_data, f_size);
            memset(f_data, 0, f_size);
            munlock(f_data, f_available);
            free(f_data);
        }
        f_data = new_data;
        f_available = new_size;
    }

    if(size < f_size)
    {
        // clear part being removed
        //
        memset(static_cast<char *>(f_data) + size, 0, f_size - size);
    }

    f_size = size;
}


std::size_t buffer::get_size() const
{
    return f_size;
}


char * buffer::data() const
{
    return static_cast<char *>(f_data);
}


std::size_t buffer::get_page_size()
{
    static long g_page_size = 0;

    if(g_page_size == 0)
    {
        errno = 0;
        g_page_size = sysconf(_SC_PAGESIZE);
        if(g_page_size == -1)
        {
            if(errno == 0)
            {
                throw value_unavailable("_SC_PAGESIZE is not available.");
            }
            if(errno == EINVAL)
            {
                throw value_unavailable("_SC_PAGESIZE is not a known name to sysconf(3).");
            }

            throw value_unavailable("sysconf(3) return an unknown error requesting _SC_PAGESIZE.");
        }
    }

    return g_page_size;
}


std::size_t buffer::adjusted_size(std::size_t size)
{
    std::size_t const page_size(get_page_size());
    return (size + page_size - 1) & ~(page_size - 1);
}


void * buffer::allocate_buffer(std::size_t size)
{
    void * data(nullptr);
    int r(0);

    r = posix_memalign(&data, get_page_size(), size);
    if(r != 0)
    {
        if(errno == EINVAL)
        {
            throw invalid_parameter("allocation with invalid memory alignment.");
        }

        // otherwise, we assume "out of memory"
        //
        throw std::bad_alloc();
    }

    r = mlock(data, size);
    if(r != 0)
    {
        free(data);

        switch(r)
        {
        case ENOMEM:
            throw not_enough_resources("mlock() of password buffer memory failed because we reached this process limit.");

        case EPERM:
            throw not_enough_privileges("mlock() cannot be used by this process (see CAP_IPC_LOCK).");

        case EAGAIN:
            throw not_enough_resources("mlock() could not lock the requested memory block.");

        case EINVAL:
            throw invalid_parameter("mlock() address or size were invalid.");

        }
    }

    return data;
}




}



string::string(char const * s, std::size_t l)
    : f_buffer(std::make_shared<detail::buffer>())
{
    if(s != nullptr)
    {
        if(l == static_cast<std::size_t>(-1))
        {
            l = strlen(s);
        }
        f_buffer->set_size(l);
        memcpy(f_buffer->data(), s, l);
    }
}


string::~string()
{
}


std::size_t string::length() const
{
    return f_buffer->get_size();
}


bool string::empty() const
{
    return length() == 0;
}


/** \brief Return a point to the string characters.
 *
 * \warning
 * The returned string is not null terminated. Make sure to also use the
 * length() function to know how many characters are found in this string.
 *
 * \note
 * This function is not called c_str() because it does not return a C-string.
 * i.e. C-strings are null terminated, this one is not. It only has a size.
 *
 * \return A direct pointer to the string character buffer.
 */
char const * string::data() const
{
    return f_buffer->data();
}


std::string string::to_std_string() const
{
    return std::string(f_buffer->data(), length());
}


void string::clear()
{
    f_buffer->set_size(0);
}


void string::resize(std::size_t size)
{
    f_buffer->set_size(size);
}


string & string::operator += (string const & rhs)
{
    std::size_t const ll(length());
    f_buffer->set_size(ll + rhs.length());
    memcpy(f_buffer->data() + ll, rhs.f_buffer->data(), rhs.length());
    return *this;
}


string & string::operator += (char c)
{
    std::size_t const len(length());
    f_buffer->set_size(len + 1);
    f_buffer->data()[len] = c;
    return *this;
}


string & string::operator += (char const * s)
{
    std::size_t const ll(length());
    std::size_t const rl(strlen(s));
    f_buffer->set_size(ll + rl);
    memcpy(f_buffer->data() + ll, s, rl);
    return *this;
}


string & string::operator += (char32_t wc)
{
    if(!libutf8::is_valid_unicode(wc))
    {
        throw invalid_parameter("wc passed to this function does not represent a valid Unicode character.");
    }

    char buf[libutf8::MBS_MIN_BUFFER_LENGTH];
    int const rl(libutf8::wctombs(buf, wc, sizeof(buf)));
    if(rl <= 0)
    {
        throw invalid_parameter("wc passed to this function does not represent a valid Unicode character.");
    }

    std::size_t const ll(length());
    f_buffer->set_size(ll + rl);
    memcpy(f_buffer->data() + ll, buf, rl);
    return *this;
}


string string::operator + (string const & rhs) const
{
    string result(*this);
    result += rhs;
    return result;
}


string string::operator + (char c) const
{
    string result(*this);
    result += c;
    return result;
}


string string::operator + (char const * s) const
{
    string result(*this);
    result += s;
    return result;
}


string string::operator + (char32_t wc) const
{
    string result(*this);
    result += wc;
    return result;
}


std::strong_ordering string::operator <=> (string const & rhs) const
{
    std::size_t const ll(length());
    std::size_t const rl(rhs.length());
    int const r(memcmp(f_buffer->data(), rhs.f_buffer->data(), std::min(ll, rl)));
    if(r == 0)
    {
        if(ll != rl)
        {
            return ll > rl ? std::strong_ordering::greater : std::strong_ordering::less;
        }
        return std::strong_ordering::equal;
    }
    return r > 0 ? std::strong_ordering::greater : std::strong_ordering::less;
}




} // namespace safepasswords
// vim: ts=4 sw=4 et
