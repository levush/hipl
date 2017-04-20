#ifndef HIPL_LIBCORE_GPL_PK_H
#define HIPL_LIBCORE_GPL_PK_H

#include <openssl/bn.h>

#include "libcore/protodefs.h"

int hip_dsa_verify(void *priv_key, struct hip_common *msg);
int hip_dsa_sign(void *peer_pub, struct hip_common *msg);
int hip_rsa_verify(void *priv_key, struct hip_common *msg);
int hip_rsa_sign(void *peer_pub, struct hip_common *msg);
int hip_ecdsa_verify(void *const peer_pub, struct hip_common *const msg);
int hip_ecdsa_sign(void *const peer_pub, struct hip_common *const msg);
int bn2bin_safe(const BIGNUM *a, unsigned char *to, int len);

#endif /* HIPL_LIBCORE_GPL_PK_H */
