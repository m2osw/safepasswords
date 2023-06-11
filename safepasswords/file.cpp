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
#include    <safepasswords/file.h>

#include    <safepasswords/exception.h>
#include    <safepasswords/utils.h>


// snapdev
//
#include <snapdev/hexadecimal_string.h>
//#include <snapdev/not_used.h>


// C++
//
//#include <memory>
//#include <iostream>


// C
//
//#include <fcntl.h>
//#include <termios.h>


// last include
//
#include <snapdev/poison.h>



namespace safepasswords
{



namespace
{



/** \brief Delete an MD context.
 *
 * We allocate an EVP MD context in order to compute the hash according to
 * the digest specified by the programmer (or "sha512" by default.)
 *
 * The function using the \p mdctx may raise an exception on an error so
 * we save the context in a shared pointer which auto-deletes the context
 * once we are done with it by calling this very function.
 *
 * \note
 * The mdctx buffer is NOT allocated. It's created on the stack, but it
 * still needs cleanup and the digest may allocate buffers that need to
 * be released.
 *
 * \param[in] mdctx  The pointer to the MD context.
 */
//void evp_md_ctx_deleter(EVP_MD_CTX * mdctx)
//{
//    // clean up the context
//    // (note: the return value is not documented so we ignore it)
//#if __cplusplus >= 201700
//    EVP_MD_CTX_free(mdctx);
//#else
//    EVP_MD_CTX_cleanup(mdctx);
//    delete mdctx;
//#endif
//}


//EVP_MD_CTX * evp_md_ctx_allocate()
//{
//    EVP_MD_CTX * mdctx(nullptr);
//#if __cplusplus >= 201700
//    mdctx = EVP_MD_CTX_new();
//#else
//    mdctx = new EVP_MD_CTX;
//    EVP_MD_CTX_init(mdctx);
//#endif
//    return mdctx;
//}


/** \brief Close a file descriptor.
 *
 * This function will close the file descriptor pointer by fd.
 *
 * \param[in] fd  Pointer to the file descriptor to close.
 */
//void close_file(int * fd)
//{
//    close(*fd);
//}


}




/** \brief Handle a password file.
 *
 * This constructor creates an object that knows how to handle a password
 * file.
 *
 * We only support our own format as follow:
 *
 * \li we support 4 fields (4 columns)
 * \li the fields are separated by colons
 * \li the first field is the user name
 * \li the second field is the digest used to hash the password
 * \li the third field is the password salt written in hexadecimal
 * \li the forth field is the password itself
 * \li lines are separated by '\\n'
 *
 * IMPORTANT NOTE: the password may include the ':' character.
 *
 * \warning
 * The password file will be loaded once and cached. If you are running
 * an application which sits around for a long time and other applications
 * may modify the password file, you want to use this class only
 * temporarilly (i.e. use it on your stack, make the necessary find/save
 * calls, then lose it.)
 *
 * \param[in] filename  The path and name of the password file.
 */
file::file(std::string const & filename)
    : f_passwords(filename)
{
}


/** \brief Clean up the file.
 *
 * This function makes sure to clean up the file.
 */
file::~file()
{
    clear_string(f_passwords.contents());
}


/** \brief Search for the specified user in this password file.
 *
 * This function scans the password file for the specified user
 * name (i.e. a line that starts with "name + ':'".)
 *
 * \exception password_exception_invalid_parameter
 * If the \p name parameter is an empty string, then this exception is raised.
 *
 * \param[in] name  The name of the user to search.
 * \param[out] password  The password if found.
 *
 * \return true if the password was found in the file.
 */
bool file::find(std::string const & name, password & p)
{
    p.clear();

    if(name.empty())
    {
        throw invalid_parameter("the password_file::find() function cannot be called with an empty string in 'name'.");
    }

    // read the whole file at once
    //
    if(!load_passwords())
    {
        return false;
    }

    // search the user
    //
    std::string const & passwords(f_passwords.contents());
    std::string::size_type const user_pos(passwords.find(name + ":"));

    // did we find it?
    //
    // Note: if npos, obviously we did not find it at all
    //       if not npos, the character before must be a '\n', unless pos == 0
    //
    if(user_pos == std::string::npos
    || (user_pos != 0 && passwords[user_pos - 1] != '\n'))
    {
        return false;
    }

    // get the end of the line
    //
    // we use the end of line as the boundary of future searches
    //
    std::string::size_type const digest_position(user_pos + name.length() + 1);
    std::string::size_type const end_position(passwords.find("\n", digest_position));
    if(end_position == std::string::npos)
    {
        return false;
    }

    // search for the second ":"
    //
    std::string::size_type const salt_position(passwords.find(":", digest_position));
    if(salt_position == std::string::npos
    || digest_position == salt_position
    || salt_position >= end_position)
    {
        // either we did not find the next ":"
        // or the digest is an empty string, which is not considered valid
        //
        return false;
    }

    // search for the third ":"
    //
    std::string::size_type const password_position(passwords.find(":", salt_position + 1));
    if(password_position == std::string::npos
    || salt_position + 1 == password_position
    || password_position + 1 >= end_position)
    {
        // either we did not find the next ":"
        // or the salt is an empty string
        // or the password is empty
        //
        return false;
    }

    char const * ptr(passwords.c_str());

    // setup the digest
    //
    std::string digest(ptr + digest_position, salt_position - digest_position);
    p.set_digest(digest);
    clear_string(digest);

    // save the encrypted password and salt
    //
    std::string password_hex_salt(ptr + salt_position + 1, password_position - salt_position - 1);
    std::string password_bin_salt(snapdev::hex_to_bin(password_hex_salt));
    string password_salt(password_bin_salt.c_str(), password_bin_salt.length());
    clear_string(password_hex_salt);
    clear_string(password_bin_salt);

    std::string encrypted_hex_password(ptr + password_position + 1, end_position - password_position - 1);
    std::string encrypted_bin_password(snapdev::hex_to_bin(encrypted_hex_password));
    string encrypted_password(encrypted_bin_password.c_str(), encrypted_bin_password.length());
    clear_string(encrypted_hex_password);
    clear_string(encrypted_bin_password);

    p.set_encrypted(encrypted_password, password_salt);

    // done with success
    //
    return true;
}


/** \brief Save a password in this password_file.
 *
 * This function saves the specified password for the named user in
 * this password_file. This function updates the content of the
 * file so a future find() will find the new information as expected.
 * However, if another application can make changes to the file, those
 * will not be caught.
 *
 * If the named user already has a password defined in this file, then
 * it gets replaced. Otherwise the new entry is added at the end.
 *
 * \warning
 * This function has the side effect of calling rewind() so the next
 * time you call the next() function, you will get the first user
 * again.
 *
 * \param[in] name  The name of the user.
 * \param[in] p  The password to save in this file.
 *
 * \return true if the passwords were saved successfully.
 */
bool file::save(std::string const & name, password const & p)
{
    if(name.empty())
    {
        throw invalid_parameter("the password_file::save() function cannot be called with an empty string in 'name'");
    }

    // read the while file at once
    //
    if(!load_passwords())
    {
        // ... we are about to create the file if it does not exist yet ...
    }

    string const & salt(p.get_salt());
    string const & encrypted(p.get_encrypted());
    std::string const new_line(
              name
            + ":"
            + p.get_digest()
            + ":"
            + snapdev::bin_to_hex(std::string(salt.data(), salt.length()))
            + ":"
            + snapdev::bin_to_hex(std::string(encrypted.data(), encrypted.length()))
            + "\n");

    // search the user
    //
    std::string const & passwords(f_passwords.contents());
    std::string::size_type const user_pos(passwords.find(name + ":"));

    std::string new_content;

    // did we find it?
    //
    // Note: if npos, obviously we did not find it at all
    //       if not npos, the character before must be a '\n', unless pos == 0
    //
    if(user_pos == std::string::npos
    || (user_pos != 0 && passwords[user_pos - 1] != '\n'))
    {
        // not found, append at the end
        //
        new_content = passwords + new_line;
    }
    else
    {
        // get the end of the line
        //
        // we will have 3 parts:
        //
        //    . what comes before 'user_pos'
        //    . the line defining that user password
        //    . what comas after the 'user_pos'
        //
        std::string::size_type const digest_position(user_pos + name.length() + 1);
        std::string::size_type const end(passwords.find("\n", digest_position));
        if(end == std::string::npos)
        {
            return false;
        }

        char const * s(passwords.c_str());
        std::string before(s, user_pos);
        std::string after(s + end + 1, passwords.length() - end - 1);
        // XXX: in regard to security, the + operator creates temporary buffers
        //      (i.e. we would need to allocate our own buffer and copy there.)
        new_content = before
                    + new_line
                    + after;
        clear_string(before);
        clear_string(after);
    }

    // we are about to change the file so the f_next pointer is not unlikely
    // to be invalidated, so we rewind it
    //
    rewind();

    // save the new content in the file_content object
    //
    f_passwords.contents(new_content);

    clear_string(new_content);

    // write the new file to disk
    //
    f_passwords.write_all();

    // done with success
    //
    return true;
}


/** \brief Delete a user and his password from password_file.
 *
 * This function searches for the specified user, if found, then it gets
 * removed from the password file. If that user is not defined in the
 * password file, nothing happens.
 *
 * \warning
 * This function has the side effect of calling rewind() so the next
 * time you call the next() function, you will get the first user
 * again.
 *
 * \param[in] name  The name of the user.
 */
bool file::remove(std::string const & name)
{
    if(name.empty())
    {
        throw invalid_parameter("the password_file::delete_user() function cannot be called with an empty string in 'name'");
    }

    // read the while file at once
    //
    if(!load_passwords())
    {
        return false;
    }

    // search the user
    //
    std::string const & passwords(f_passwords.contents());
    std::string::size_type const user_pos(passwords.find(name + ":"));

    // did we find it?
    //
    // Note: if npos, obviously we did not find it at all
    //       if not npos, the character before must be a '\n', unless pos == 0
    //
    if(user_pos == std::string::npos
    || (user_pos != 0 && passwords[user_pos - 1] != '\n'))
    {
        // not found, done
        //
        return true;
    }

    // get the end of the line
    //
    // we will have 3 parts:
    //
    //    . what comes before 'user_pos'
    //    . the line defining that user password
    //    . what comas after the 'user_pos'
    //
    std::string::size_type const digest_position(user_pos + name.length() + 1);
    std::string::size_type const end(passwords.find("\n", digest_position));
    if(end == std::string::npos)
    {
        return false;
    }

    char const * s(passwords.c_str());
    std::string before(s, user_pos);
    std::string after(s + end + 1, passwords.length() - end - 1);
    // XXX: in regard to security, the + operator creates temporary buffers
    //      (i.e. we would need to allocate our own buffer and copy there.)
    std::string new_content(before + after);
    clear_string(before);
    clear_string(after);

    // we are about to change the file so the f_next pointer is not unlikely
    // to be invalidated, so we rewind it
    //
    rewind();

    // save the new content in the file_content object
    //
    f_passwords.contents(new_content);

    clear_string(new_content);

    // write the new file to disk
    //
    f_passwords.write_all();

    // done with success
    //
    return true;
}


/** \brief Read the next entry.
 *
 * This function can be used to read all the usernames one by one.
 *
 * The function returns the name of the user, which cannot be defined in
 * the password object. Once the end of the file is reached, the function
 * returns an empty string and does not modify \p password.
 *
 * \note
 * The function may hit invalid input data, in which case it will return
 * an empty string as if the end of the file was reached.
 *
 * \param[in,out] p  The password object where data gets saved.
 *
 * \return The username or an empty string once the end of the file is reached.
 */
std::string file::next(password & p)
{
    if(!load_passwords())
    {
        return std::string();
    }

    // get the end of the line
    //
    std::string const & passwords(f_passwords.contents());
    std::string::size_type const next_user_pos(passwords.find("\n", f_next));
    if(next_user_pos == std::string::npos)
    {
        return std::string();
    }

    // retrieve the position of the end of the user name
    //
    std::string::size_type const end_name_pos(passwords.find(":", f_next, next_user_pos - f_next));
    if(end_name_pos == std::string::npos)
    {
        return std::string();
    }

    if(f_next == end_name_pos)
    {
        return std::string();
    }

    // the find() function does all the parsing of the elements, use it
    // instead of rewriting that code here (although we search for the
    // user again... we could have a sub-function to avoid the double
    // search!)
    //
    std::string const username(passwords.c_str(), end_name_pos - f_next);
    find(username, p);

    // the next user will be found on the next line
    //
    f_next = next_user_pos + 1;

    return username;
}


/** \brief Reset the next pointer to the start of the file.
 *
 * This function allows you to restart the next() function to the beginning
 * of the file.
 */
void file::rewind()
{
    f_next = 0;
}


/** \brief Load the password file once.
 *
 * This function loads the password file. It makes sure to not re-load
 * it if it was already loaded.
 */
bool file::load_passwords()
{
    if(!f_file_loaded)
    {
        if(!f_passwords.read_all())
        {
            return false;
        }
        f_file_loaded = true;
    }

    return true;
}



} // namespace safepasswords
// vim: ts=4 sw=4 et
