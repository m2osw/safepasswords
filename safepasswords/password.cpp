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
#include    "safepasswords/password.h"

#include    "safepasswords/exception.h"
#include    "safepasswords/utils.h"


// snapdev
//
#include    <snapdev/not_used.h>


// C++
//
#include    <cstdint>
#include    <iostream>
#include    <memory>


// OpenSSL
//
#include    <openssl/err.h>
#include    <openssl/evp.h>
#include    <openssl/rand.h>


// C
//
#include    <fcntl.h>
#include    <termios.h>
#include    <unistd.h>


// last include
//
#include    <snapdev/poison.h>



namespace safepasswords
{



namespace
{



/** \brief Size of the salt for a password.
 *
 * Whenever we encrypt a password, we use a corresponding salt.
 *
 * The salt is used to further encrypt the password so two users who
 * decided to use the exact same password will not be seen as having
 * the same password because of the salt since the salt renders any
 * password unique.
 *
 * \note
 * In the current implementation we do not in any way attempt to
 * make sure that each user gets a unique salt so it is always
 * possible for two users to end up with the exact same salt. However,
 * it is really very unlikely that those two users would also choose
 * the exact same password. Now, with a salt of 32 bytes, the real
 * likelihood for two people to end up with the same salt is really
 * very low (32 bytes is 256 bits, so one chance in 2 power 256, which
 * is a very small number, a little under 10 power -77.)
 *
 * \todo
 * We may want to offer the programmer a way to enter his own salt
 * size. Right now, this is fixed and cannot ever be changed since
 * the input of existing password will have a salt string of that
 * size exactly.
 */
constexpr int const         SALT_SIZE = 32;

// to be worth something, the salt must be at least 6 bytes
static_assert(SALT_SIZE >= 6, "SALT_SIZE must be at least 6 bytes");

// also the salt size must be even
static_assert((SALT_SIZE & 1) == 0, "SALT_SIZE must be even");


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
void evp_md_ctx_deleter(EVP_MD_CTX * mdctx)
{
    // clean up the context
    // (note: the return value is not documented so we ignore it)
#if __cplusplus >= 201700
    EVP_MD_CTX_free(mdctx);
#else
    EVP_MD_CTX_cleanup(mdctx);
    delete mdctx;
#endif
}


EVP_MD_CTX * evp_md_ctx_allocate()
{
    EVP_MD_CTX * mdctx(nullptr);
#if __cplusplus >= 201700
    mdctx = EVP_MD_CTX_new();
#else
    mdctx = new EVP_MD_CTX;
    EVP_MD_CTX_init(mdctx);
#endif
    return mdctx;
}


/** \brief Close a file descriptor.
 *
 * This function will close the file descriptor pointer by fd.
 *
 * \param[in] fd  Pointer to the file descriptor to close.
 */
// LCOV_EXCL_START
void close_file(int * fd)
{
    close(*fd);
}
// LCOV_EXCL_STOP


}


/** \brief Initialize the password object.
 *
 * This function does nothing at this time. By default a password object
 * is empty.
 *
 * There are several ways the password object is used:
 *
 * \li To generate a new password automatically.
 *
 * \code
 *      password p;
 *      p.set_digest("sha512");   // always required in this case
 *      p.generate(10);           // necessary if you want to specify the size
 *      std::string hash(p.get_encrypted();
 *      std::string salt(p.get_salt());
 * \endcode
 *
 * The hash variable is the encypted password. Note that you will want to
 * also save the salt otherwise you won't be able to do anything with the
 * hash alone.
 *
 * \li To encrypt a password entered by a user.
 *
 * \code
 *      password p;
 *      p.set_digest("sha512");
 *      p.set_plain(user_entered_password);
 *      std::string hash(p.get_encrypted());
 *      std::string salt(p.get_salt());
 * \endcode
 *
 * \li To compare an already encrypted password against a password entered
 *     by a user.
 *
 * \code
 *      password p;
 *      p.set_digest(digest_of_existing_password);
 *      p.set_plain(user_entered_password, existing_password_salt);
 *      std::string hash(p.get_encrypted());
 *      if(hash == existing_password_hash) // ...got it right...
 * \endcode
 *
 * You may also defined two password objects and compare them against each
 * others to know whether the new login password is the same as the database
 * password:
 *
 * \code
 *      // or use two password objects:
 *      password p;
 *      p.set_digest(digest_of_existing_password);
 *      p.set_plain(user_entered_password, existing_password_salt);
 *      password op;  // old password
 *      op.set_encrypted(existing_password);
 *      if(op == p) // ...got it right...
 * \endcode
 *
 * \warning
 * In the current implementation, the salt string must be exactly SALT_SIZE
 * in length. Although we use an std::string, the bytes can be any value
 * from '\0' to '\xFF'.
 */
password::password()
{
}


/** \brief Clean up a password object.
 *
 * This function cleans up the strings held by the password object.
 * That way they do not lay around in memory.
 */
password::~password()
{
}


/** \brief Clear the password strings explicitly.
 *
 * This function can be used to explicitly clear all the password related
 * strings.
 *
 * \note
 * The digest is not cleared or reset to the default.
 */
void password::clear()
{
    f_plain.clear();
    f_salt.clear();
    f_encrypted.clear();
}


/** \brief Define the OpenSSL function to use to encrypt the password.
 *
 * This function saves the digest to use to encrypt the password. Until
 * this is done, trying to retrieve an encrypted password from a plain
 * password will fail.
 *
 * For now, we use "sha512" as the default. We may also want to look
 * into using the bcrypt() function instead. However, Blowfish uses
 * only 64 bits and suffers from birthday attacks (guessing of words).
 *
 * \warning
 * This function has the side effect of clearing the cached encrypted
 * password.
 *
 * \todo
 * The test needs to verify that "sha512" exists so the default works.
 *
 * \exception digest_not_available
 * If the digest is not defined in OpenSSL, then this exception is raised.
 *
 * \param[in] digest  The digest name.
 */
void password::set_digest(std::string const & digest)
{
    // Initialize so we gain access to all the necessary digests
    //
    OpenSSL_add_all_digests();

    // Make sure the digest actually exists
    //
    EVP_MD const * md(EVP_get_digestbyname(digest.c_str()));
    if(md == nullptr)
    {
        throw digest_not_available(
              "the specified digest ("
            + digest
            + ") was not found.");
    }

    f_digest = digest;

    f_encrypted.clear();
}


/** \brief Retrieve the name of the current OpenSSL digest.
 *
 * This function returns the digest to use to encrypt the password.
 *
 * \return The name of the digest currently in use in this password.
 */
std::string const & password::get_digest() const
{
    return f_digest;
}


/** \brief Generate the password.
 *
 * In some cases an administrator may want to create an account for a user
 * which should then have a valid, albeit unknown, password.
 *
 * This function can be used to create that password.
 *
 * It is strongly advised to NOT send such passwords to the user via email
 * because they may contain "strange" characters and emails are notoriously
 * not safe.
 *
 * \note
 * The function verifies that the min_length parameter is at least 8. Note
 * that a safe password is more like 10 or more totally random characters.
 *
 * \note
 * The \p min_length parameter represent the minimum length, it is very
 * likely that the result will be longer. To limit a password, make sure
 * to set the \p max_length parameter to a number other than -1. If not
 * -1, \p max_length must be larger or equal to \p min_length.
 *
 * \warning
 * The function is not likely to generate a user friendly password. It is
 * expected to be used when a password is required but the user cannot
 * enter one and the user will have to run a Change Password procedure.
 *
 * \warning
 * Calling this functions also generates a new salt.
 *
 * \todo
 * Look into creating a genearte_human_password() with sets of characters
 * in each language instead of just basic ASCII and a length that makes
 * more sense (here the default is 64 because it is a "computer password").
 *
 * \todo
 * Also remove characters that can cause problems for users (i.e. spaces,
 * ampersand, look alike characters, etc.)
 *
 * \todo
 * Look in the RAND_seed() or maybe RAND_status() and RAND_load_file()
 * functions and whether the OpenSSL RAND_*() interface requires an
 * initialization because cURL does have such and it could be that we
 * need it too. In that case, I would suggest we create a separate
 * contrib library for random numbers. That library would be responsible
 * for generating the numbers automatically for us.
 *
 * \param[in] min_length  The minimum length of the password.
 * \param[in] max_length  The maximum length of the password.
 */
void password::generate(int min_length, int max_length)
{
    // restart from scratch
    //
    f_plain.clear();
    f_encrypted.clear();
    f_salt.clear();

    // make sure the minimum length requested is at least 8 characters
    //
    min_length = std::max(min_length, PASSWORD_MIN_LENGTH);
    if(max_length < 0)
    {
        max_length = PASSWORD_MAX_LENGTH;
    }
    max_length = std::min(max_length, PASSWORD_MAX_LENGTH);
    if(min_length > max_length)
    {
        throw invalid_parameter(
              "adjusted minimum and maximum lengths are improperly sorted; minimum "
            + std::to_string(min_length)
            + " is larger than maximum "
            + std::to_string(max_length)
            + '.');
    }

    // a "large" set of random bytes
    //
    constexpr std::size_t const PASSWORD_SIZE(256);
    unsigned char buf[PASSWORD_SIZE];
    do
    {
        // get the random bytes
        //
        int const r(RAND_bytes(buf, sizeof(buf)));
        if(r != 1)
        {
            // LCOV_EXCL_START
            // something happened, RAND_bytes() failed!
            char err[256];
            ERR_error_string_n(ERR_peek_last_error(), err, sizeof(err));
            f_plain.clear();
            throw function_failure(
                  "RAND_bytes() error, it could not properly fill the salt buffer ("
                + std::to_string(ERR_peek_last_error())
                + ": "
                + err
                + ")");
            // LCOV_EXCL_STOP
        }

        for(std::size_t i(0); i < PASSWORD_SIZE; ++i)
        {
            // only but all ASCII characters are accepted for now
            //
            if(buf[i] >= ' ' && buf[i] < 0x7F)
            {
                f_plain += static_cast<char>(buf[i]);
                if(f_plain.length() >= static_cast<std::size_t>(max_length))
                {
                    return;
                }
                buf[i] = 0;
            }
            //else -- skip any other character
        }
    }
    while(f_plain.length() < static_cast<std::size_t>(min_length));
    // make sure it is long enough
}


/** \brief Define the password from a plain password.
 *
 * This function defines a password starting from a plain password.
 *
 * If this password comes from a log in screen, then you will need to
 * specify the existing salt. Otherwise, leave the salt string empty.
 * The password object will randomly generate a buffer of bytes
 * automatically for it.
 *
 * \note
 * Calling this function resets the encrypted password.
 *
 * \note
 * Although it is expected that the password is a valid C string,
 * this object does not check such. The password can include any
 * character, including '\0', and it can even be invalid UTF-8.
 * It is the caller's responsibility to verify the string if it
 * can be tainted in any special way.
 *
 * \param[in] plain_password  The plain password to encrypt.
 * \param[in] salt  The salt to use with the password encryption system.
 */
void password::set_plain(string const & plain, string const & salt)
{
    // the salt must be of the right length (or unspecified)
    //
    if(!salt.empty()
    && salt.length() != SALT_SIZE)
    {
        throw invalid_parameter(
              "if defined, the salt must be exactly "
            + std::to_string(SALT_SIZE)
            + " bytes.");
    }

    f_plain = plain;
    f_salt = salt;

    // that means the encrypted password is not going to be valid anymore
    //
    f_encrypted.clear();
}


/** \brief Ask the user to enter a password in his console.
 *
 * This function opens the process TTY ("/dev/tty") and reads a password.
 *
 * The function is responsible for cancel ECHO-ing in the console before
 * getting characters.
 *
 * This function accepts a \p salt parameter like the set_plain(),
 * it may be used to check the password of an existing user and not just to
 * create a new user entry so the salt is required.
 *
 * \note
 * The existing password information is cleared on entry. It is set to the
 * new password the user enters only if a valid password is entered. The
 * \p salt parameter is also used only if the new password is considered
 * valid.
 *
 * \todo
 * Add a minimum size for the password.
 *
 * \todo
 * Make it testable in a unit test.
 *
 * \param[in] salt  The salt to encrypt the password.
 *
 * \return true if the password was properly entered, false otherwise.
 */
// LCOV_EXCL_START
bool password::get_from_console(string const & salt)
{
    // read the new f_plain_password from the console
    //
    f_plain.clear();
    f_encrypted.clear();
    f_salt.clear();

    // the process must have a terminal
    //
    if(!isatty(STDIN_FILENO))
    {
        std::cerr << "safepasswords:error: input file is not a TTY, cancel add with a --password option but no password." << std::endl;
        return 1;
    }

    // open process terminal
    //
    int tty(open("/dev/tty", O_RDONLY));
    if(tty == -1)
    {
        std::cerr << "safepasswords:error: could not access process TTY." << std::endl;
        return 1;
    }
    std::unique_ptr<int, decltype(&close_file)> raii_tty(&tty, close_file);

    // get current termios flags
    //
    struct safe_termios
    {
        safe_termios(int tty)
            : f_tty(tty)
        {
            // save the original termios flags
            //
            if(tcgetattr(f_tty, &f_original) != 0)
            {
                return;
            }

            // setup termios to not echo input characters
            // and return characters one by one (avoid buffering)
            //
            // TODO: tcsetattr() returns 0 on success of any attribute changes
            //       meaning that we should call it once per change!
            //
            struct termios t(f_original);
            t.c_lflag &= ~(ICANON | ECHO);
            t.c_cc[VMIN] = 1;
            t.c_cc[VTIME] = 0;
            f_valid = tcsetattr(f_tty, TCSAFLUSH, &t) == 0;
        }

        ~safe_termios()
        {
            // restore the termios flags
            // ignore failures... it is likely to work since we did not
            // change the original data, but who knows.
            //
            snapdev::NOT_USED(tcsetattr(f_tty, TCSAFLUSH, &f_original));
        }

        bool is_valid() const
        {
            return f_valid;
        }

    private:
        bool f_valid = false;
        int f_tty = -1;
        struct termios f_original = termios();
    };

    safe_termios st(tty);
    if(!st.is_valid())
    {
        std::cerr << "safepasswords:error: could not change terminal attributes to make it safe to read a password." << std::endl;
        return false;
    }

    string new_password;

    std::cout << "Password: " << std::flush;
    for(;;)
    {
        char c;
        if(read(tty, &c, 1) != 1)
        {
            std::cout << std::endl << std::flush;
            std::cerr << "safepasswords:error: I/O error while reading from TTY." << std::endl;
            return false;
        }
        switch(c)
        {
        case '\b': // backspace
            if(!new_password.empty())
            {
                // the following loop ensures all the bytes of a UTF-8
                // multibyte sequence get removed
                //
                for(std::size_t len(new_password.length() - 1); len > 0; --len)
                {
                    std::uint8_t const o(new_password.data()[len]);
                    if(o < 0x80 || o > 0xBF)
                    {
                        new_password.resize(len);
                        break;
                    }
                }
            }
            break;

        case '\n': // enter
            std::cout << std::endl << std::flush;
            if(new_password.empty())
            {
                // we could allow empty passwords at some point?
                //
                std::cerr << "safepasswords:error: password cannot be empty." << std::endl;
                return false;
            }
            f_plain = new_password;
            f_salt = salt;
            return true;

        default:
            if(c >= ' ')
            {
                new_password += c;
            }
            break;

        }
    }
}
// LCOV_EXCL_STOP


/** \brief Retrieve the plain password.
 *
 * This function returns a copy of the plain password.
 *
 * Note that the plain password is not available if the password object
 * was just set to an encrypted password (i.e. the "encryption" is a one
 * way hashing so we cannot get the password back out.) So you can get
 * the pain password only if the \p set_plain() was called earlier.
 *
 * \return The plain password.
 */
string const & password::get_plain() const
{
    return f_plain;
}


/** \brief Retrieve the salt of this password.
 *
 * When generating or encrypting a new password, the password object
 * also generates a new salt value. This salt has to be saved along
 * the encrypted password in order to be able to re-encrypt the same
 * password to the same value.
 *
 * \note
 * There is no set_salt() function. Instead, we expect you will call
 * the set_plain() including the salt parameter.
 *
 * \warning
 * The salt is not a printable string. It is a buffer of binary codes,
 * which may include '\0' bytes at any location. You must make sure to
 * use the length() function to know the exact size of the salt.
 *
 * \return The current salt key or an empty string if not defined.
 */
string const & password::get_salt() const
{
    return f_salt;
}


/** \brief Define the encrypted password.
 *
 * You may use this function to define the password object as an encrypted
 * password. This is used to one can compare two password for equality.
 *
 * This function let you set the salt. This is generally used when reading
 * the password from a file or a database. That way it can be read with
 * the get_salt() function and used with the plain password to encrypt it.
 *
 * \param[in] encrypted  The already encrypted password.
 * \param[in] salt  Set the password salt.
 */
void password::set_encrypted(string const & encrypted, string const & salt)
{
    // plain would have nothing to do with this new data, get rid of it
    //
    f_plain.clear();

    f_encrypted = encrypted;
    f_salt = salt;
}


/** \brief Retrieve a copy of the encrypted password.
 *
 * In most cases this function is used to retrieve the resulting encrypted
 * password and then save it in a database.
 *
 * \note
 * The function caches the encrypted password so calling this function
 * multiple times is considered fast. However, if you change various
 * parameters, it is expected to recompute the new corresponding value.
 *
 * \return The encrypted password.
 */
string const & password::get_encrypted() const
{
    if(f_encrypted.empty())
    {
        // encrypt() changes f_encrypted and
        // if required generates the password and salt strings
        // so we have to cast our the "const" parameter
        //
        const_cast<password *>(this)->encrypt();
    }

    return f_encrypted;
}


/** \brief Compare the encrypted passwords.
 *
 * This function calls the get_encrypted() of this password object
 * and of the rhs password object and compares them against each others.
 *
 * The function returns a negative number if this is smaller than \p rhs.
 * The function returns a positive number if this is larger than \p rhs.
 * The function returns 0 if both strings are equal.
 *
 * \param[in] rhs  The right hand side password to compare with this.
 *
 * \return A negative, zero, or positive representing the order.
 */
std::strong_ordering password::operator <=> (password const & rhs) const
{
    return get_encrypted() <=> rhs.get_encrypted();
}


/** \brief Generate a new salt for a password.
 *
 * Every time you get to encrypt a new password, call this function to
 * get a new salt. This is important to avoid having the same hash for
 * the same password for multiple users.
 *
 * Imagine a user creating 3 accounts and each time using the exact same
 * password. Just using an md5sum it would encrypt that password to
 * exactly the same 16 bytes. In other words, if you crack one, you
 * crack all 3 (assuming you have access to the database you can
 * immediately see that all those accounts have the exact same password.)
 *
 * The salt prevents such problems. Plus we add 256 bits of completely
 * random entropy to the digest used to encrypt the passwords. This
 * in itself makes it for a much harder to decrypt hash.
 *
 * The salt is expected to be saved in the database along the password.
 */
void password::generate_salt()
{
    f_salt.clear();

    // we use 16 bytes before and 16 bytes after the password
    // so create a salt of SALT_SIZE bytes (256 bits at time of writing)
    //
    unsigned char buf[SALT_SIZE];
    int const r(RAND_bytes(buf, sizeof(buf)));
    if(r != 1)
    {
        // LCOV_EXCL_START
        // something happened, RAND_bytes() failed!
        //
        char err[256];
        ERR_error_string_n(ERR_peek_last_error(), err, sizeof(err));
        throw function_failure(
              "RAND_bytes() error, it could not properly fill the salt buffer ("
            + std::to_string(ERR_peek_last_error())
            + ": "
            + err
            + ")");
        // LCOV_EXCL_STOP
    }

    f_salt = string(reinterpret_cast<char *>(buf), sizeof(buf));
}


/** \brief Encrypt a password.
 *
 * This function generates a strong hash of a user password to prevent
 * easy brute force "decryption" of the password. (i.e. an MD5 can be
 * decrypted in 6 hours, and a SHA1 password, in about 1 day, with a
 * $100 GPU as of 2012.)
 *
 * Here we use 2 random salts (using RAND_bytes() which is expected to
 * be random enough for encryption like algorithms) and the specified
 * digest to encrypt (okay, hash--a one way "encryption") the password.
 *
 * Read more about hash functions on
 * http://ehash.iaik.tugraz.at/wiki/The_Hash_Function_Zoo
 *
 * \exception encryption_failed
 * This exception is raised if any of the parameters fails and/or the
 * password or salt cannot be properly generated.
 */
void password::encrypt()
{
    // make sure we reset by default, if it fails, we get an empty string
    //
    f_encrypted.clear();

    if(f_plain.empty())
    {
        generate();
    }

    if(f_salt.empty())
    {
        generate_salt();
    }

    // Initialize so we gain access to all the necessary digests
    //
    OpenSSL_add_all_digests();

    // retrieve the digest we want to use
    //
    EVP_MD const * md(EVP_get_digestbyname(f_digest.c_str()));
    if(md == nullptr)
    {
        // the set_digest() prevents this from happening here
        // although if the default ("sha512") becomes unavailable,
        // then it could happen
        //
        throw logic_error("the specified digest was not found."); // LCOV_EXCL_LINE
    }

    // initialize the digest context
    //
    std::unique_ptr<EVP_MD_CTX, decltype(&evp_md_ctx_deleter)> mdctx(evp_md_ctx_allocate(), evp_md_ctx_deleter);
    if(EVP_DigestInit_ex(mdctx.get(), md, nullptr) != 1)
    {
        throw encryption_failed("EVP_DigestInit_ex() failed digest initialization."); // LCOV_EXCL_LINE
    }

    // add first salt
    //
    if(EVP_DigestUpdate(mdctx.get(), f_salt.data(), SALT_SIZE / 2) != 1)
    {
        throw encryption_failed("EVP_DigestUpdate() failed digest update (salt1)."); // LCOV_EXCL_LINE
    }

    // add password
    //
    if(EVP_DigestUpdate(mdctx.get(), f_plain.data(), f_plain.length()) != 1)
    {
        throw encryption_failed("EVP_DigestUpdate() failed digest update (password)."); // LCOV_EXCL_LINE
    }

    // add second salt
    //
    if(EVP_DigestUpdate(mdctx.get(), f_salt.data() + SALT_SIZE / 2, SALT_SIZE / 2) != 1)
    {
        throw encryption_failed("EVP_DigestUpdate() failed digest update (salt2)."); // LCOV_EXCL_LINE
    }

    // retrieve the result of the hash
    //
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len(EVP_MAX_MD_SIZE);
    if(EVP_DigestFinal_ex(mdctx.get(), md_value, &md_len) != 1)
    {
        throw encryption_failed("EVP_DigestFinal_ex() digest finalization failed."); // LCOV_EXCL_LINE
    }
    f_encrypted += string(reinterpret_cast<char *>(md_value), md_len);
}




} // namespace safepasswords
// vim: ts=4 sw=4 et
