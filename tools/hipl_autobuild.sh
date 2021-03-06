#!/bin/sh
#
# Script for compiling and testing HIPL in various configurations.
# Errors encountered during operation are logged and sent off by email.
# The email address to send to is retrieved from Bazaar metadata.
#
# This script has a few extra features if the directory layout conforms
# to a certain structure:
# - $HOME/tmp/autobuild/ - directory for log files
# - $HOME/tmp/autobuild/openwrt - working OpenWrt tree
#
# OpenWrt tests will only be run if the respective directories exist. If the
# log file directory is available, the Bazaar revision of the code from the
# last run of this script is stored there. Subsequent runs check the revision
# and bail out early if the revision was already tested.
#
# This comes in handy when running this script from cron in order to provide
# basic continuous integration. A suitable crontab entry could be:
# m   h dom mon dow    command
# 31  *  *   *   *     cd $HOME/src/hipl/trunk && bzr up -q &&
#                          sh -l tools/hipl_autobuild.sh
#
#
# Copyright (c) 2010-2012 Aalto University and RWTH Aachen University.
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

PROGRAM_NAME=$(basename $0)

if test "$1" = "-h" || test "$1" = "--help"; then
    echo "$PROGRAM_NAME is a script to test HIPL in various configurations."
    echo "usage: $PROGRAM_NAME"
    exit 1
fi

BRANCH_NAME=$(bzr nick)
EMAIL_ADDRESS=$(bzr whoami)

BUILD_DIR=$(mktemp -d --tmpdir ${PROGRAM_NAME}.XXXXXXXX)
AUTOBUILD_DIR=$HOME/tmp/autobuild
OPENWRT_DIR=$AUTOBUILD_DIR/openwrt

BRANCH_URL=$(bzr info | grep -E "repository branch|checkout root" | cut -d: -f2)
CHECKOUT_DIR=$BUILD_DIR/$(date +"%Y-%m-%d-%H%M")_$BRANCH_NAME
BRANCH_REVISION=$(bzr revno -q $BRANCH_URL)
AUTOBUILD_REVISION_FILE=$AUTOBUILD_DIR/HIPL_REVISION_$BRANCH_NAME
AUTOBUILD_REVISION=$(cat $AUTOBUILD_REVISION_FILE 2> /dev/null)

MAKEOPTS="-j -l 6"

# helper functions
run_program()
{
    $@ > log.txt 2>&1
    if [ $? -eq 0 ] ; then
        rm -f log.txt
        return 0
    else
        mail_notify "$1"
        cleanup 1
    fi
}

mail_notify()
{
    COMMAND="$1"
    cat > $CHECKOUT_DIR/msg.txt <<EOF
branch: $BRANCH_NAME
revision: $BRANCH_REVISION
configuration: $CONFIGURATION
command: $COMMAND
command output:

EOF
    cat log.txt >> $CHECKOUT_DIR/msg.txt
    SUBJECT="[autobuild] ($BRANCH_NAME) ERROR checking revision $BRANCH_REVISION"
    mailx -s "$SUBJECT" "$EMAIL_ADDRESS" < $CHECKOUT_DIR/msg.txt
    rm -f log.txt
}

mail_success()
{
    cat > $CHECKOUT_DIR/msg.txt <<EOF
branch: $BRANCH_NAME
revision: $BRANCH_REVISION

All performed checks completed successfully!

EOF
    SUBJECT="[autobuild] ($BRANCH_NAME) SUCCESS checking revision $BRANCH_REVISION"
    mailx -s "$SUBJECT" "$EMAIL_ADDRESS" < $CHECKOUT_DIR/msg.txt
}

cleanup()
{
    echo $BRANCH_REVISION > $AUTOBUILD_REVISION_FILE
    # The build directory created by make distcheck is read-only.
    chmod -R u+rwX "$BUILD_DIR"
    rm -rf "$BUILD_DIR"
    exit $1
}

# Check if 'make dist' contains all files that are under version control.
check_dist_tarball()
{
    # Remove autogenerated, Bazaar-related and similar files from the list.
    find -L . | sed -e 1d -e 's:./::' -e '/\.bzr/d' -e '/autom4te.cache/d' -e '/file_list_checkout/d' |
        sort > file_list_checkout
    ./configure > /dev/null && make dist > /dev/null
    tar -tzf hipl-*.tar.gz |
        sed -e 1d -e "s:hipl-[0-9.]*/::" -e 's:/$::' -e '/file_list_checkout/d' -e '/version.h/d' |
        sort > file_list_tarball
    run_program diff -u file_list_checkout file_list_tarball
}

# There should be no Doxygen warnings.
check_doxygen()
{
    make doxygen | sed -e 1d > doxygen_output
    run_program diff -u /dev/null doxygen_output
}

compile()
{
    # Run compile and install tests for a certain configuration, in-tree.
    CONFIGURATION="--prefix=$(pwd)/local_install $@"
    run_program "./configure" $CONFIGURATION        &&
        run_program "make $MAKEOPTS"                &&
        run_program "make $MAKEOPTS checkheaders"   &&
        run_program "make install"
}

# only run the autobuilder for newer revisions than the last one checked
test "$BRANCH_REVISION" = "$AUTOBUILD_REVISION" && cleanup 0

bzr checkout -q --lightweight $BRANCH_URL $CHECKOUT_DIR || cleanup 1

cd "$CHECKOUT_DIR" || cleanup 1

# Bootstrap the autotools build system.
run_program autoreconf --install

CONFIGURATION="distribution tarball completeness"
check_dist_tarball

CONFIGURATION="Doxygen documentation"
check_doxygen

# Compile HIPL in different configurations
# vanilla configuration
compile

# internal autoconf tests, bootstrap the dist tarball, build out-of-tree, etc
run_program "make $MAKEOPTS distcheck"

# run unit tests (needs to run after HIPL has been configured)
run_program "make $MAKEOPTS check"

# minimal configuration
compile --enable-firewall --disable-rvs --disable-profiling --disable-debug --disable-performance --with-nomodules=heartbeat,update,heartbeat_update,midauth,cert

# Max compile coverage configuration
FEATURES_ALL="--enable-firewall --enable-rvs --enable-profiling --disable-debug --enable-performance"
compile $FEATURES_ALL

# Max compile coverage configuration without optimization
compile $FEATURES_ALL CFLAGS="-O0"

# Max compile coverage configuration optimized for size
compile $FEATURES_ALL CFLAGS="-Os"

# Max compile coverage configuration with full optimization
# FIXME: Disabled until the tree compiles with this optimization level.
#compile $FEATURES_ALL CFLAGS="-O3"

# test binary distribution packages
# This is run as the last test because it can have sideeffects on the
# other standard configurations.
run_program "make $MAKEOPTS bin"

# Disabled until OpenWRT build works again
#if test -d $OPENWRT_DIR; then
#    # Compile HIPL within an OpenWrt checkout
#    CONFIGURATION="OpenWrt ARM crosscompile"
#    cd $OPENWRT_DIR || cleanup 1
#    run_program "rm -f dl/hipl-*.tar.gz"
#    run_program "cp $CHECKOUT_DIR/hipl-*.tar.gz dl/"
#    run_program "rm -rf package/hipl"
#    run_program "cp -r $CHECKOUT_DIR/packaging/openwrt/hipl package/"
#    run_program "make $MAKEOPTS package/hipl/clean V=99"
#    run_program "make $MAKEOPTS package/hipl/install V=99"
#else
#    echo No OpenWrt directory found, skipping OpenWrt check.
#fi

mail_success

cleanup 0
