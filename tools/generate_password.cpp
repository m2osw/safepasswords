// Copyright (c) 2012-2023  Made to Order Software Corp.  All Rights Reserved
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

/** \file
 * \brief A tool to generate a password.
 *
 * Many of our systems generate keys and once in a while we would like
 * to have a password (like to connect to a remote communicator daemon
 * or the snaprfs between clusters).
 *
 * Usage:
 *
 * 1. to generate a password, just define the digest or keep the
 *    default:
 *
 *        generate-password --digest sha512
 *
 * 2. to create a specific password from a specific plain string,
 *    use the `--password` and optionally the `--salt` options:
 *
 *        generate-password --digest sha512 --password password1 --salt "exactly-32-characters"
 *
 *    if you have a binary salt, use the --hex-salt instead. It will convert
 *    the hexadecimal digits to binary and use that buffer.
 */


// safepasswords
//
#include    <safepasswords/password.h>
#include    <safepasswords/version.h>


// eventdispatcher
//
#include    <eventdispatcher/signal_handler.h>


// snaplogger
//
#include    <snaplogger/logger.h>
#include    <snaplogger/options.h>


// libexcept
//
#include    <libexcept/file_inheritance.h>
#include    <libexcept/report_signal.h>


// advgetopt
//
#include    <advgetopt/advgetopt.h>
#include    <advgetopt/exception.h>


// snapdev
//
#include    <snapdev/hexadecimal_string.h>
#include    <snapdev/not_reached.h>
#include    <snapdev/not_used.h>
#include    <snapdev/stringize.h>


// C++
//
#include    <iomanip>


// C
//
#include    <math.h>
#include    <string.h>


// OpenSSL
//
#include    <openssl/err.h>
#include    <openssl/evp.h>
#include    <openssl/provider.h>
#include    <openssl/rand.h>


// last include
//
#include    <snapdev/poison.h>



namespace
{


const advgetopt::option g_options[] =
{
    advgetopt::define_option(
          advgetopt::Name("digest")
        , advgetopt::ShortName('d')
        , advgetopt::Flags(advgetopt::all_flags<
              advgetopt::GETOPT_FLAG_REQUIRED
            , advgetopt::GETOPT_FLAG_GROUP_OPTIONS>())
        , advgetopt::DefaultValue("sha512")
        , advgetopt::Help("specify the name of the digest to use to encrypt the password (i.e. \"sha512\").")
    ),
    advgetopt::define_option(
          advgetopt::Name("hex-salt")
        , advgetopt::ShortName('S')
        , advgetopt::Flags(advgetopt::all_flags<
              advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("salt in hexadecimal (i.e. A378ABC...) to use to generate the encrypted password.")
    ),
    advgetopt::define_option(
          advgetopt::Name("length")
        , advgetopt::ShortName('l')
        , advgetopt::Flags(advgetopt::all_flags<
              advgetopt::GETOPT_FLAG_REQUIRED
            , advgetopt::GETOPT_FLAG_GROUP_OPTIONS>())
        , advgetopt::Validator("integer(8...4000)")
        , advgetopt::Help("specify a minimum password length (smallest minimum is 8).")
    ),
    advgetopt::define_option(
          advgetopt::Name("list-digests")
        , advgetopt::ShortName('L')
        , advgetopt::Flags(advgetopt::all_flags<
              advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("list the name of all the available digests.")
    ),
    advgetopt::define_option(
          advgetopt::Name("max-length")
        , advgetopt::ShortName('m')
        , advgetopt::Flags(advgetopt::all_flags<
              advgetopt::GETOPT_FLAG_REQUIRED
            , advgetopt::GETOPT_FLAG_GROUP_OPTIONS>())
        , advgetopt::Validator("integer(8...4000)")
        , advgetopt::Help("specify a maximum password length (maximum must be larger or equal to minimum; default is 4,000).")
    ),
    advgetopt::define_option(
          advgetopt::Name("password")
        , advgetopt::ShortName('p')
        , advgetopt::Flags(advgetopt::all_flags<
              advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("plain password to use to generate the encrypted password.")
    ),
    advgetopt::define_option(
          advgetopt::Name("salt")
        , advgetopt::ShortName('s')
        , advgetopt::Flags(advgetopt::all_flags<
              advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("salt to use to generate the encrypted password.")
    ),
    advgetopt::end_options()
};

advgetopt::group_description const g_group_descriptions[] =
{
    advgetopt::define_group(
          advgetopt::GroupNumber(advgetopt::GETOPT_FLAG_GROUP_COMMANDS)
        , advgetopt::GroupName("command")
        , advgetopt::GroupDescription("Commands:")
    ),
    advgetopt::define_group(
          advgetopt::GroupNumber(advgetopt::GETOPT_FLAG_GROUP_OPTIONS)
        , advgetopt::GroupName("option")
        , advgetopt::GroupDescription("Options:")
    ),
    advgetopt::end_groups()
};

constexpr char const * const g_configuration_files[] =
{
    "/etc/safepasswords/generate-password.conf",
    nullptr
};

// TODO: once we have stdc++20, remove all defaults & pragma
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
advgetopt::options_environment const g_options_environment =
{
    .f_project_name = "generate-password",
    .f_group_name = "safepasswords",
    .f_options = g_options,
    .f_options_files_directory = nullptr,
    .f_environment_variable_name = "GENERATE_PASSWORD",
    .f_environment_variable_intro = nullptr,
    .f_section_variables_name = nullptr,
    .f_configuration_files = g_configuration_files,
    .f_configuration_filename = nullptr,
    .f_configuration_directories = nullptr,
    .f_environment_flags = advgetopt::GETOPT_ENVIRONMENT_FLAG_PROCESS_SYSTEM_PARAMETERS,
    .f_help_header = "Usage: %p [-<opt>]\n"
                     "where -<opt> is one or more of:",
    .f_help_footer = "%c",
    .f_version = SAFEPASSWORDS_VERSION_STRING,
    .f_license = "GNU GPL v3 or newer",
    .f_copyright = "Copyright (c) 2011-"
                   SNAPDEV_STRINGIZE(UTC_BUILD_YEAR)
                   " by Made to Order Software Corporation -- All Rights Reserved",
    .f_build_date = UTC_BUILD_DATE,
    .f_build_time = UTC_BUILD_TIME,
    .f_groups = g_group_descriptions
};
#pragma GCC diagnostic pop



int md_cmp(EVP_MD const * const * a, EVP_MD const * const * b)
{
    return strcmp(OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(*a)),
                  OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(*b)));
}



OSSL_LIB_CTX * g_app_libctx = nullptr;
const char * g_app_propq = nullptr;

int app_set_propq(char const * arg)
{
    g_app_propq = arg;
    return 1;
}

char const * app_get0_propq()
{
    return g_app_propq;
}

OSSL_LIB_CTX *app_get0_libctx(void)
{
    return g_app_libctx;
}

int is_digest_fetchable(EVP_MD const * alg)
{
    EVP_MD * impl;
    char const * propq = app_get0_propq();
    OSSL_LIB_CTX * libctx = app_get0_libctx();
    const char *name = EVP_MD_get0_name(alg);

    ERR_set_mark();
    impl = EVP_MD_fetch(libctx, name, propq);
    ERR_pop_to_mark();
    if (impl == NULL)
        return 0;
    EVP_MD_free(impl);
    return 1;
}


void collect_digests(EVP_MD * digest, void * data)
{
    std::list<EVP_MD *> * digests = static_cast<std::list<EVP_MD *> *>(data);

    if(is_digest_fetchable(digest))
    {
        digests->push_back(digest);
        EVP_MD_up_ref(digest);
    }
}


int name_cmp(char const * const * a, char const * const * b)
{
    return OPENSSL_strcasecmp(*a, *b);
}


void collect_names(char const * name, void * data)
{
    std::list<std::string> * names = static_cast<std::list<std::string> *>(data);

    names->push_back(name);
}



}
// noname namespace



class generate_password
{
public:
                            generate_password(int argc, char * argv[]);

    int                     run();

private:
    int                     list_digest();
    int                     encrypt();
    int                     generate();

    advgetopt::getopt       f_opts;
};


generate_password::generate_password(int argc, char * argv[])
    : f_opts(g_options_environment)
{
    snaplogger::add_logger_options(f_opts);
    f_opts.finish_parsing(argc, argv);
    if(!snaplogger::process_logger_options(f_opts, "/etc/safepasswords/logger", std::cout, false))
    {
        // exit on any error
        //
        throw advgetopt::getopt_exit("logger options generated an error.", 1);
    }
}


int generate_password::run()
{
    if(f_opts.is_defined("list-digests"))
    {
        return list_digest();
    }
    if(f_opts.is_defined("password"))
    {
        return encrypt();
    }

    return generate();
}


int generate_password::list_digest()
{
    std::list<EVP_MD *> digests;
    EVP_MD_do_all_provided(app_get0_libctx(), collect_digests, &digests);

    int const index_width(log10(digests.size()) + 1);
    int idx(0);
    for(auto m : digests)
    {
        // we could add filtering
        //if(select_name != nullptr
        //&& !EVP_MD_is_a(m, select_name))
        //{
        //    continue;
        //}

        std::list<std::string> names;
        if(EVP_MD_names_do_all(m, collect_names, &names))
        {
            ++idx;
            std::cout
                << std::setw(index_width) << idx
                << ". "
                << snapdev::join_strings(names, ", ")
                << " @ "
                << OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(m))
                << "\n";

            //if(verbose)
            //{
            //    char const * desc(EVP_MD_get0_description(m));
            //    if(desc != nullptr)
            //    {
            //        BIO_printf(bio_out, "    description: %s\n", desc);
            //    }
            //
            //    print_param_types("retrievable algorithm parameters",
            //                    EVP_MD_gettable_params(m), 4);
            //    print_param_types("retrievable operation parameters",
            //                    EVP_MD_gettable_ctx_params(m), 4);
            //    print_param_types("settable operation parameters",
            //                    EVP_MD_settable_ctx_params(m), 4);
            //}
        }
    }
    for(auto d : digests)
    {
        EVP_MD_free(d);
    }

    return 0;
}


int generate_password::encrypt()
{
    safepasswords::password p;

    p.set_digest(f_opts.get_string("digest"));

    int length(safepasswords::PASSWORD_DEFAULT_MIN_LENGTH);
    if(f_opts.is_defined("length"))
    {
        length = f_opts.get_long("length");
    }

    int max_length(safepasswords::PASSWORD_DEFAULT_MAX_LENGTH);
    if(f_opts.is_defined("max-length"))
    {
        max_length = f_opts.get_long("max-length");
    }

    std::string const & plain(f_opts.get_string("password"));
    safepasswords::string const pwd(plain.c_str(), plain.length());

    safepasswords::string salt;
    if(f_opts.is_defined("salt"))
    {
        std::string const & plain_salt(f_opts.get_string("salt"));
        salt = safepasswords::string(plain_salt.c_str(), plain_salt.length());
    }
    else if(f_opts.is_defined("hex-salt"))
    {
        std::string const & binary_salt(snapdev::hex_to_bin(f_opts.get_string("hex-salt")));
        salt = safepasswords::string(binary_salt.c_str(), binary_salt.length());
    }

    p.set_plain(pwd, salt);

    safepasswords::string const result(p.get_encrypted());
    std::string const encrypted(snapdev::bin_to_hex(std::string(result.data(), result.length())));

    std::cout << encrypted << "\n";

    return 0;
}


int generate_password::generate()
{
    safepasswords::password p;

    p.set_digest(f_opts.get_string("digest"));

    int length(safepasswords::PASSWORD_DEFAULT_MIN_LENGTH);
    if(f_opts.is_defined("length"))
    {
        length = f_opts.get_long("length");
    }

    int max_length(safepasswords::PASSWORD_DEFAULT_MAX_LENGTH);
    if(f_opts.is_defined("max-length"))
    {
        max_length = f_opts.get_long("max-length");
    }

    p.generate(length, max_length);

    safepasswords::string const plain(p.get_plain());

    std::cout << plain.to_std_string() << "\n";

    return 0;
}


int main(int argc, char * argv[])
{
    libexcept::init_report_signal();
    libexcept::verify_inherited_files();
    ed::signal_handler::create_instance();

    try
    {
        generate_password fp(argc, argv);
        return fp.run();
    }
    catch(advgetopt::getopt_exit const & e)
    {
        exit(e.code());
    }
    catch(std::exception const & e)
    {
        std::cerr << "error: an exception occurred (1): " << e.what() << std::endl;
        SNAP_LOG_FATAL
            << "an exception occurred (1): "
            << e.what()
            << SNAP_LOG_SEND;
        exit(1);
    }
    catch(...)
    {
        std::cerr << "error: an unknown exception occurred (2)." << std::endl;
        SNAP_LOG_FATAL
            << "an unknown exception occurred (2)."
            << SNAP_LOG_SEND;
        exit(2);
    }
    snapdev::NOT_REACHED();
}


// vim: ts=4 sw=4 et
