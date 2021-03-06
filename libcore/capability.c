/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
 * @brief Functionality to lower the privileges of a daemon
 *
 * This file contains functionality to lower the privileges (or
 * capabilities) of hipd and hipfw. It is important to restrict
 * the damage of a exploit to the software. The code is Linux
 * specific.
 *
 * This code causes problems with valgrind, because of setpwent(3).
 */

#define _BSD_SOURCE

#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>

#include "config.h"
#include "debug.h"
#include "ife.h"
#include "capability.h"


/**
 * map a user name such as "nobody" to the corresponding UID number
 *
 * @param name the name to map
 * @return the UID or -1 on error
 */
static int user_to_uid(const char *name)
{
    int            uid = -1;
    int            i;
    struct passwd *pwp = NULL, pw;
    char           buf[4096];

    setpwent();
    while (1) {
        i = getpwent_r(&pw, buf, sizeof(buf), &pwp);
        if (i) {
            break;
        }
        if (!strcmp(pwp->pw_name, name)) {
            uid = pwp->pw_uid;
            break;
        }
    }
    endpwent();
    return uid;
}

/**
 * Wrapper for the capget system call.
 * @param hdrp  pointer to a __user_cap_header_struct
 * @param datap pointer to a __user_cap_data_struct
 * @return      0 on success, negative otherwise.
 */
static inline int capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
    return syscall(__NR_capget, hdrp, datap);
}

/**
 * Wrapper for the capset system call.
 * @param hdrp  pointer to a __user_cap_header_struct
 * @param datap pointer to a __user_cap_data_struct
 * @return      0 on success, negative otherwise.
 */
static inline int capset(cap_user_header_t hdrp, cap_user_data_t datap)
{
    return syscall(__NR_capset, hdrp, datap);
}

/**
 * Lower the privileges of the currently running process.
 *
 * @return zero on success and negative on error
 */
int hip_set_lowcapability(void)
{
    int err = 0;
    int uid = -1;

    struct __user_cap_header_struct header;
    struct __user_cap_data_struct   data;

    header.pid     = 0;
    header.version = _LINUX_CAPABILITY_VERSION;
    data.effective = data.permitted = data.inheritable = 0;

    HIP_IFEL(prctl(PR_SET_KEEPCAPS, 1), -1, "prctl err\n");

    HIP_DEBUG("Now PR_SET_KEEPCAPS=%d\n", prctl(PR_GET_KEEPCAPS));

    uid = user_to_uid("nobody");
    if (uid == -1) {
        HIP_ERROR("User 'nodoby' could not be found\n");
        goto out_err;
    }

    HIP_IFEL(capget(&header, &data), -1,
             "error while retrieving capabilities through capget()\n");
    HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
              data.effective, data.permitted, data.inheritable);

    HIP_DEBUG("Before setreuid(,) UID=%d and EFF_UID=%d\n",
              getuid(), geteuid());

    HIP_IFEL(setreuid(uid, uid), -1, "setruid failed\n");

    HIP_DEBUG("After setreuid(,) UID=%d and EFF_UID=%d\n",
              getuid(), geteuid());
    HIP_IFEL(capget(&header, &data), -1,
             "error while retrieving capabilities through 'capget()'\n");

    HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
              data.effective, data.permitted, data.inheritable);
    HIP_DEBUG("Going to clear all capabilities except the ones needed\n");
    data.effective = data.permitted = data.inheritable = 0;
    /* for CAP_NET_RAW capability */
    data.effective |= 1 << CAP_NET_RAW;
    data.permitted |= 1 << CAP_NET_RAW;
    /* for CAP_NET_ADMIN capability */
    data.effective |= 1 << CAP_NET_ADMIN;
    data.permitted |= 1 << CAP_NET_ADMIN;
    /* kernel module loading and removal capability */
    data.effective |= 1 << CAP_SYS_MODULE;
    data.permitted |= 1 << CAP_SYS_MODULE;

    HIP_IFEL(capset(&header, &data), -1,
             "error in capset (do you have capabilities kernel module?)");
    HIP_DEBUG("UID=%d EFF_UID=%d\n", getuid(), geteuid());
    HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
              data.effective, data.permitted, data.inheritable);

out_err:
    return err;
}
