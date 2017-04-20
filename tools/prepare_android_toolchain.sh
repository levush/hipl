#!/bin/bash
# Script is for building an Android cross-compilation environment on linux.

# If you want to change the install folder, do it here.
TOOLCHAIN_INSTALL_FOLDER=${HOME}/android_tools
NDK_VERSION=r9
SYSTEM=linux-x86_64

OPENSSL_VERSION='1.0.1g'
LIBMNL_VERSION='1.0.3'
LIBNFNETLINK_VERSION='1.0.1'
LIBNFQUEUE_VERSION='1.0.2'

# These are for the script's internals
PATCHES_DIR=$(dirname $(readlink -f ${0}))/../patches/android
NDK_PACKAGE=android-ndk-${NDK_VERSION}-${SYSTEM}
NDK_ROOT=${TOOLCHAIN_INSTALL_FOLDER}/android-ndk-${NDK_VERSION}
ANDROID_TOOLCHAIN=${TOOLCHAIN_INSTALL_FOLDER}/toolchain
ANDROID_SYSROOT=${ANDROID_TOOLCHAIN}/sysroot

# Functions
make_install_folder()
{
    if [ ! -d ${TOOLCHAIN_INSTALL_FOLDER} ]; then
        if ! mkdir -p ${TOOLCHAIN_INSTALL_FOLDER}; then
            echo "Install failed. Could not create folder for toolchain."
            exit
        fi
    fi
}

insert_vars_to_bashrc()
{
    echo "Inserting the following to .bashrc"
    echo "export NDK_ROOT=${NDK_ROOT}"
    echo "export ANDROID_TOOLCHAIN=${ANDROID_TOOLCHAIN}"
    echo "export ANDROID_SYSROOT=${ANDROID_SYSROOT}"

    if ! grep ~/.bashrc -q -e "NDK_ROOT"; then
        echo "export NDK_ROOT=${NDK_ROOT}" >> ${HOME}/.bashrc
    fi
    if ! grep ~/.bashrc -q -e "ANDROID_TOOLCHAIN"; then
        echo "export ANDROID_TOOLCHAIN=${ANDROID_TOOLCHAIN}" >> ${HOME}/.bashrc
    fi
    if ! grep ~/.bashrc -q -e "ANDROID_SYSROOT"; then
        echo "export ANDROID_SYSROOT=${ANDROID_SYSROOT}" >> ${HOME}/.bashrc
    fi
}

get_package()
{
    PACKAGENAME=$1
    URI=$2
    FILENAME=$(basename $2)
    TARGET=$3

    if [ ! -d ${TARGET} ]; then
        echo "$PACKAGENAME not found."
        if [ ! -f ${FILENAME} ]; then
            echo "$PACKAGENAME package not found, downloading.."
            wget $URI
        else
            echo "$PACKAGENAME package found, using that."
        fi
        echo "Extracting $PACKAGENAME.."
        tar xf $FILENAME
    else
    echo "$PACKAGENAME found, using that."
    fi
}

install_sdk_platform_tools()
{
    cd ${TOOLCHAIN_INSTALL_FOLDER}/android-sdk-linux/
        if [ ! -f platform-tools/adb ]; then
        echo "Installing android platform tools"
        tools/android update sdk --no-ui -t platform-tool
    fi;
    cd ..
}

build_ndk_toolchain()
{
    echo "Building Android standalone toolchain."
    ${NDK_ROOT}/build/tools/make-standalone-toolchain.sh \
    --toolchain=arm-linux-androideabi-4.6 \
    --platform=android-9 \
    --arch=arm \
    --ndk-dir=${NDK_ROOT} \
    --system=${SYSTEM} \
    --install-dir=${ANDROID_TOOLCHAIN}
}

patch_toolchain()
{

# ---- Add definition for __fswab64 needed by libnetfilter_queue ---- #
# ---- https://code.google.com/p/android/issues/detail?id=14475  ---- #
patch -N ${ANDROID_SYSROOT}/usr/include/linux/byteorder/swab.h < ${PATCHES_DIR}/ndk/swab.h.patch

# --------- Add some deprecated stuff back to netinet/ip.h ---------- #
patch -N ${ANDROID_SYSROOT}/usr/include/netinet/ip.h < ${PATCHES_DIR}/ndk/ip.h.patch

# --------- Add the icmphdr definition to netinet/ip_icmp.h --------- #
patch -N ${ANDROID_SYSROOT}/usr/include/netinet/ip_icmp.h < ${PATCHES_DIR}/ndk/ip_icmp.h.patch

}


build_openssl()
{
    # Configure and install OpenSSL in the toolchain
    cd ${TOOLCHAIN_INSTALL_FOLDER}/openssl-${OPENSSL_VERSION}
    ./config no-asm shared --prefix=${ANDROID_SYSROOT}/usr
    sed 's/-m64//g' -i Makefile    # The arm compiler doesn't support -m64
    make
    make install_sw
    cd ${TOOLCHAIN_INSTALL_FOLDER}
}

build_libmnl()
{
    cd ${TOOLCHAIN_INSTALL_FOLDER}/libmnl-${LIBMNL_VERSION}
    ./configure  --prefix=${ANDROID_SYSROOT}/usr --host=arm-linux CFLAGS="-mbionic -fPIC -fno-exceptions -I${ANDROID_SYSROOT}/usr/include" LDFLAGS="-Wl,-rpath-link=${ANDROID_SYSROOT}/usr/lib,-L${ANDROID_SYSROOT}/usr/lib"
    make install
    cd ${TOOLCHAIN_INSTALL_FOLDER}
}

build_libnfnetlink()
{
    cd ${TOOLCHAIN_INSTALL_FOLDER}/libnfnetlink-${LIBNFNETLINK_VERSION}
    ./configure  --prefix=${ANDROID_SYSROOT}/usr --host=arm-linux CFLAGS="-mbionic -fPIC -fno-exceptions -I${ANDROID_SYSROOT}/usr/include" LDFLAGS="-Wl,-rpath-link=${ANDROID_SYSROOT}/usr/lib,-L${ANDROID_SYSROOT}/usr/lib"
    make install
    cd ${TOOLCHAIN_INSTALL_FOLDER}
}

build_libnetfilter_queue()
{
    cd ${TOOLCHAIN_INSTALL_FOLDER}/libnetfilter_queue-${LIBNFQUEUE_VERSION}

    # --------  Remove duplicate definition for tcp_word_hdr  -------- #
    patch -N src/extra/tcp.c < ${PATCHES_DIR}/libnetfilter_queue/tcp.c.patch

    ./configure  --prefix=${ANDROID_SYSROOT}/usr --host=arm-linux CFLAGS="-mbionic -fPIC -fno-exceptions -I${ANDROID_SYSROOT}/usr/include" LDFLAGS="-Wl,-rpath-link=${ANDROID_SYSROOT}/usr/lib,-L${ANDROID_SYSROOT}/usr/lib"
    make install
    cd ${TOOLCHAIN_INSTALL_FOLDER}
}

set_build_env_vars()
{
    export CC=${ANDROID_TOOLCHAIN}/bin/arm-linux-androideabi-gcc
    export AR=${ANDROID_TOOLCHAIN}/bin/arm-linux-androideabi-ar r
    export RANLIB=${ANDROID_TOOLCHAIN}/bin/arm-linux-androideabi-ranlib
    export NM=${ANDROID_TOOLCHAIN}/bin/arm-linux-androideabi-nm
    export CFLAG="-DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H  \
                  -DOPENSSL_N -DL_ENDIAN -DTERMIO -O3 -fomit-frame-pointer   \
                  -Wall -fPIC"
    export PLATFORM="arm-linux"
    export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${ANDROID_SYSROOT}/usr/lib/pkgconfig
}

print_instructions()
{
    # Print instructions
    echo ""
    echo ""
    echo "The tools are now installed under $TOOLCHAIN_INSTALL_FOLDER"
    echo "Path to the toolchain is ${ANDROID_TOOLCHAIN}"
    echo ""
    echo "To configure HIPL for Android compilation, run:"
    echo "For Android >= 4.1: "                                  \
          ./configure --enable-android --host=arm-linux          \
                      --prefix=/usr    --sysconfdir=/etc         \
          CC="${ANDROID_TOOLCHAIN}/bin/arm-linux-androideabi-gcc"
    echo ""
    echo "For Android < 4.1, add --disable-android-pie"

    # It is important that there are no spaces after commas in LDFLAGS.
}

print_invocation_help()
{
    echo "Invocation: $0 [--auto-insert-bashrc|--install-sdk]"
    echo "--auto-insert-bashrc  adds the NDK toolchain paths to .bashrc automatically."
    echo "--install-sdk         Downloads the Android SDK platform tools (adb, fastboot etc.)."
}


####################
#   Main script
####################
make_install_folder
cd ${TOOLCHAIN_INSTALL_FOLDER}

if [ ! "${1}xxx" = "xxx" ]; then
    if [ "$1" = "--auto-insert-bashrc" ]; then
        insert_vars_to_bashrc
    elif [ "$1" = "--install-sdk" ]; then
        get_package "Android SDK" http://dl.google.com/android/android-sdk_r22.6.2-linux.tgz android-sdk-linux
        install_sdk_platform_tools
        echo "To add adb etc. to your path, run:"
        echo "export PATH=${PATH}:${TOOLCHAIN_INSTALL_FOLDER}/android-sdk-linux/platform-tools"
        exit
    else
        print_invocation_help
        exit
    fi # if $1 known
fi # if $1 defined

get_package "Android NDK" http://dl.google.com/android/ndk/${NDK_PACKAGE}.tar.bz2 ${NDK_ROOT}
build_ndk_toolchain
patch_toolchain

set_build_env_vars

get_package "OpenSSL" http://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz openssl-${OPENSSL_VERSION}
build_openssl

get_package "libmnl" http://netfilter.org/projects/libmnl/files/libmnl-${LIBMNL_VERSION}.tar.bz2 libmnl-${LIBMNL_VERSION}
build_libmnl

get_package "libnfnetlink" http://netfilter.org/projects/libnfnetlink/files/libnfnetlink-${LIBNFNETLINK_VERSION}.tar.bz2 libnfnetlink-${LIBNFNETLINK_VERSION}
build_libnfnetlink

get_package "libnetfilter_queue" http://netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-${LIBNFQUEUE_VERSION}.tar.bz2 libnetfilter_queue-${LIBNFQUEUE_VERSION}
build_libnetfilter_queue

print_instructions
