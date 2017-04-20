# Copyright (c) 2010, 2012-2013 Aalto University and RWTH Aachen University.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

AC_PREREQ([2.53])
AC_INIT([HIP for Linux], [1.0.8], [hipl-users@freelists.org], [hipl])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# This needs to be placed before AM_INIT_AUTOMAKE, otherwise $@ is modified.
# Note that the value of $@ changes if configure is rerun automatically during
# a rebuild. In this case "--no-create --no-recursion" appear to get passed to
# configure in addition to the stored command line options. Since this is a
# harmless sideeffect, it is ignored. Clean release builds should be made from
# a pristine tree.
AC_DEFINE_UNQUOTED(HIPL_CONFIGURATION, "$@")
AH_TEMPLATE(HIPL_CONFIGURATION, [options passed to configure])

AM_INIT_AUTOMAKE([foreign subdir-objects])

# program checks

AC_PROG_CC
AC_PROG_INSTALL
# AC_PROG_LIBTOOL() could be replaced with LT_INIT(disable-shared) but
# OpenWrt (Mar 2010) is running too old version of libtool
# LT_INIT(disable-shared)
AC_PROG_LIBTOOL(disable-shared)

AC_CHECK_PROG(have_xmlto, xmlto, yes)
AM_CONDITIONAL(HAVE_XMLTO, test x"$have_xmlto" = x"yes")

AC_CHECK_PROG(have_w3m, w3m, yes)
AM_CONDITIONAL(HAVE_W3M, test x"$have_w3m" = x"yes")

# Enable silent rules only when available (automake 1.11 or later).
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Check for Python for build-system and tools directory
AM_PATH_PYTHON([2.4.3],, [AC_MSG_ERROR([Minimum required Python version not found.])])



# library checks

AC_CHECK_LIB(crypto, DSA_generate_key,, AC_MSG_ERROR(OpenSSL not found.))
# Check for ellyptic curve crypto in OpenSSL.
AC_CHECK_FUNC(EC_KEY_new,
              AC_DEFINE(HAVE_EC_CRYPTO) AH_TEMPLATE(HAVE_EC_CRYPTO,
              [Defined to 1 if elliptic curve crypto is enabled.]))
# We need the math lib in the registration extension.
AC_CHECK_LIB(m, pow,, AC_MSG_ERROR(Math library not found.))
# The unit tests depend on 'check' (http://check.sourceforge.net/)
AC_CHECK_LIB(check, suite_create,,
             AC_MSG_WARN(libcheck not found: unit tests not available))
AM_CONDITIONAL(HIP_UNITTESTS, test x"$ac_cv_lib_check_suite_create" = xyes)



# If no --prefix option is passed to configure, $prefix is empty. But we want
# to expand $sysconfdir, which defaults to ${prefix}/etc. So set $prefix.
if test "x$prefix" = "xNONE"; then
    prefix="$ac_default_prefix"
fi

AC_DEFINE_UNQUOTED(HIPL_DEFAULT_PREFIX, "$(eval echo ${prefix})")
AH_TEMPLATE(HIPL_DEFAULT_PREFIX, [default prefix])

# Our configuration files should be located in a subdirectory of their own.
# The variable is evaluated and echoed to produce a string that can be
# substituted for references to configuration files throughout the codebase.
AC_SUBST(sysconfdir, $(eval echo ${sysconfdir}/hip))

# Default sysconf and lockfile directory
AC_DEFINE_UNQUOTED(HIPL_SYSCONFDIR, "$(eval echo $sysconfdir)")
AH_TEMPLATE(HIPL_SYSCONFDIR, [default configuration file location])

AC_SUBST(lockdir, /var/lock/)
AC_DEFINE_UNQUOTED(HIPL_LOCKDIR, "$(eval echo $lockdir)")
AH_TEMPLATE(HIPL_LOCKDIR, [default lock file location])

AC_DEFINE_UNQUOTED(HIPL_SOURCEDIR, "$(eval echo $srcdir)")
AH_TEMPLATE(HIPL_SOURCEDIR, [HIPL source directory location])
# Make sure that pythondir does not contain ${prefix} or similar so that it
# can be substituted into our Python scripts.
AC_SUBST(pythondir, $(eval echo $pythondir))



# Set default AM_CFLAGS for the complete project.
AC_SUBST(AM_CFLAGS, "-std=c99 -Wall -Wextra -Werror")
AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -Wredundant-decls -Wdisabled-optimization")
AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -Wundef -Wstrict-prototypes -Wmissing-prototypes")
AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -Wno-deprecated-declarations -Wpointer-arith")
AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -Wwrite-strings -Wshadow -Winline -Wcast-qual")
AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -Wno-missing-field-initializers -Wformat=2")
#TODO fix the code and get rid of this exception
AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -Wno-error=strict-aliasing")

# Set the preprocessor flags for the entire project
AC_SUBST(AM_CPPFLAGS, "-D_POSIX_C_SOURCE=200112L -D_XOPEN_SOURCE=500")


# configure options

AC_ARG_ENABLE(android,
               AS_HELP_STRING([--enable-android],
                              [Enable android (default is NO)]),
               [ac_cv_use_android=$enableval],
               [ac_cv_use_android=no])
AC_CACHE_CHECK([whether to build for Android],
               [ac_cv_use_android],
               [ac_cv_use_android=no])
if test x"$ac_cv_use_android" = x"yes"; then
    AC_DEFINE(CONFIG_HIP_ANDROID)
    AC_SUBST(AM_CFLAGS, "-std=c99 -mbionic -fPIC -fno-exceptions")
    AC_SUBST(AM_CFLAGS, "$AM_CFLAGS --sysroot=${ANDROID_SYSROOT}")
    AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -I android")
    AH_TEMPLATE(CONFIG_HIP_ANDROID, [Defined to 1 if android build is enabled.])
fi
AM_CONDITIONAL(HIP_ANDROID, test x"$ac_cv_use_android" = x"yes")

AC_ARG_ENABLE(android-pie,
               AS_HELP_STRING([--disable-android-pie],
                              [Don't compile as PIE (Position Independent Executable)]),
               [ac_cv_use_android_pie=$enableval],
               [ac_cv_use_android_pie=yes])
AC_CACHE_CHECK([whether to build as PIE],
               [ac_cv_use_android_pie],
               [ac_cv_use_android_pie=yes])
if test x"$ac_cv_use_android" = x"yes"; then
    if test x"$ac_cv_use_android_pie" = x"yes"; then
        AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -pie")
    fi
fi

AC_ARG_ENABLE(firewall,
               AS_HELP_STRING([--disable-firewall],
                              [HIP firewall daemon (default is YES)]),
               [ac_cv_use_firewall=$enableval],
               [ac_cv_use_firewall=yes])
AC_CACHE_CHECK([whether to use firewall],
               [ac_cv_use_firewall],
               [ac_cv_use_firewall=yes])
if test x"$ac_cv_use_firewall" = x"yes"; then
    AC_CHECK_LIB(netfilter_queue, nfq_create_queue,, [AC_MSG_ERROR([libnetfilter_queue not found])])
    AC_CHECK_LIB(nfnetlink, nlif_query,, [AC_MSG_ERROR([libnfnetlink not found])])
    AC_CHECK_LIB(config, config_setting_index,,
                 [AC_MSG_WARN([libconfig not found, using default config])])
    AC_DEFINE(CONFIG_HIP_FIREWALL)
    AH_TEMPLATE(CONFIG_HIP_FIREWALL, [Defined to 1 if firewall is enabled.])
fi
AM_CONDITIONAL(HIP_FIREWALL, test x"$ac_cv_use_firewall" = x"yes")

AC_ARG_ENABLE(rvs,
               AS_HELP_STRING([--disable-rvs],
                              [HIP Rendezvous extensions (default is YES)]),
               [ac_cv_use_rvs=$enableval],
               [ac_cv_use_rvs=yes])
AC_CACHE_CHECK([whether to use RVS],
               [ac_cv_use_rvs],
               [ac_cv_use_rvs=yes])
if test x"$ac_cv_use_rvs" = x"yes"; then
    AC_DEFINE(CONFIG_HIP_RVS)
    AH_TEMPLATE(CONFIG_HIP_RVS, [Defined to 1 if RVS is enabled.])
fi

AC_ARG_ENABLE(profiling,
               AS_HELP_STRING([--enable-profiling],
                              [gprof profiling support (default is NO)]),
               [ac_cv_use_profiling=$enableval],
               [ac_cv_use_profiling=no])
AC_CACHE_CHECK([whether to use grof support],
               [ac_cv_use_profiling],
               [ac_cv_use_profiling=no])
if test x"$ac_cv_use_profiling" = x"yes"; then
    AC_SUBST(AM_CFLAGS, "$AM_CFLAGS -pg")
fi

AC_ARG_ENABLE(debug,
               AS_HELP_STRING([--disable-debug],
                              [Enable debug (default is YES)]),
               [ac_cv_use_debug=$enableval],
               [ac_cv_use_debug=yes])
AC_CACHE_CHECK([whether to have verbose debug],
               [ac_cv_use_debug],
               [ac_cv_use_debug=yes])
if test x"$ac_cv_use_debug" = x"yes"; then
    AC_DEFINE(HIP_LOGFMT_LONG)
    AH_TEMPLATE(HIP_LOGFMT_LONG, [Defined to 1 if long log format output is enabled.])
    AC_DEFINE(CONFIG_HIP_DEBUG)
    AH_TEMPLATE(CONFIG_HIP_DEBUG, [Defined to 1 if debug output is enabled.])
fi

AC_ARG_ENABLE(performance,
               AS_HELP_STRING([--enable-performance],
                              [Performance measurement support (default is NO)]),
               [ac_cv_use_performance=$enableval],
               [ac_cv_use_performance=no])
AC_CACHE_CHECK([whether to use performance measurement],
               [ac_cv_use_performance],
               [ac_cv_use_performance=no])
if test x"$ac_cv_use_performance" = x"yes"; then
    AC_DEFINE(CONFIG_HIP_PERFORMANCE)
    AH_TEMPLATE(CONFIG_HIP_PERFORMANCE,
                [Defined to 1 if performance measurements are enabled.])
fi
AM_CONDITIONAL(HIP_PERFORMANCE, test x"$ac_cv_use_performance" = x"yes")

AC_ARG_WITH(nomodules,
            AS_HELP_STRING([--with-nomodules=list],
                           [comma-separated list of disabled modules]))



# Parse modules directory
echo ""
echo "+-----------------------------------------------";
echo "| processing modules...";
echo "|";
$PYTHON "${srcdir}/process_modules.py" -s "${srcdir}" -d "${with_nomodules}"
if [[ "$?" != "0" ]]; then
    echo "configure: error: Module processing failed"
    exit 1
fi
echo "|";
echo "+-----------------------------------------------"
echo ""



# Do not forget to remove files added here in the dist-hook in Makefile.am.
AC_CONFIG_FILES([Makefile
                 debian/hipl-dnsproxy.install
                 doc/Doxyfile
                 doc/HOWTO.xml
                 packaging/openwrt/hipl/Makefile])
AC_CONFIG_FILES([tools/hipdnskeyparse/hipdnskeyparse],
                [chmod +x tools/hipdnskeyparse/hipdnskeyparse])
AC_CONFIG_FILES([tools/hipdnsproxy/hipdnsproxy],
                [chmod +x tools/hipdnsproxy/hipdnsproxy])
AC_CONFIG_FILES([tools/nsupdate/nsupdate],
                [chmod +x tools/nsupdate/nsupdate])

AC_OUTPUT
