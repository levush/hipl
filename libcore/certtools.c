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
 * certificate building and verification functions to use with HIP
 */

#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/safestack.h>

#include "crypto.h"
#include "debug.h"
#include "ife.h"
#include "message.h"
#include "prefix.h"
#include "straddr.h"
#include "certtools.h"

/*******************************************************************************
 * FUNCTIONS FOR SPKI                                                          *
 *******************************************************************************/

/**
 * Function that verifies the signature in
 * the given SPKI cert sent by the "client"
 *
 * @param cert points to hip_cert_spki_info that is going to be verified
 *
 * @return 0 if signature matches, -1 if error or signature did NOT match
 *
 * @note see hip_cert_spki_char2certinfo to convert from wire to hip_cert_spki_info
 */
int hip_cert_spki_lib_verify(struct hip_cert_spki_info *cert)
{
    int  err = 0, start = 0, stop = 0, evpret = 0, keylen = 0, algo = 0;
    char buf[200];

    unsigned char  sha_digest[21];
    unsigned char *sha_retval;
    unsigned char *signature_hash     = NULL;
    unsigned char *signature_hash_b64 = NULL;
    unsigned char *signature_b64      = NULL;

    unsigned char *signature = NULL;

    /** RSA */
    RSA           *rsa = NULL;
    unsigned long  e_code;
    char          *e_hex       = NULL;
    unsigned char *modulus_b64 = NULL;
    unsigned char *modulus     = NULL;

    /** DSA */
    DSA           *dsa   = NULL;
    unsigned char *p_bin = NULL, *q_bin = NULL, *g_bin = NULL, *y_bin = NULL;
    unsigned char *p_b64 = NULL, *q_b64 = NULL, *g_b64 = NULL, *y_b64 = NULL;
    DSA_SIG       *dsa_sig;

    /* rules for regular expressions */

    /*
     * Rule to get the info if we are using DSA
     */
    char dsa_rule[] = "[d][s][a][-][p][k][c][s][1][-][s][h][a][1]";

    /*
     * Rule to get the info if we are using RSA
     */
    char rsa_rule[] = "[r][s][a][-][p][k][c][s][1][-][s][h][a][1]";

    /*
     * Rule to get DSA p
     * Look for pattern "(p |" and stop when first "|"
     * anything in base 64 is accepted inbetween
     */
    char p_rule[] = "[(][p][ ][|][[A-Za-z0-9+/()#=-]*[|]";

    /*
     * Rule to get DSA q
     * Look for pattern "(q |" and stop when first "|"
     * anything in base 64 is accepted inbetween
     */
    char q_rule[] = "[(][q][ ][|][[A-Za-z0-9+/()#=-]*[|]";

    /*
     * Rule to get DSA g
     * Look for pattern "(g |" and stop when first "|"
     * anything in base 64 is accepted inbetween
     */
    char g_rule[] = "[(][g][ ][|][[A-Za-z0-9+/()#=-]*[|]";

    /*
     * Rule to get DSA y / pub_key
     * Look for pattern "(y |" and stop when first "|"
     * anything in base 64 is accepted inbetween
     */
    char y_rule[] = "[(][y][ ][|][[A-Za-z0-9+/()#=-]*[|]";

    /*
     * rule to get the public exponent RSA
     * Look for the part that says # and after that some hex blob and #
     */
    char e_rule[] = "[#][0-9A-Fa-f]*[#]";

    /*
     * rule to get the public modulus RSA
     * Look for the part that starts with '|' and after that anything
     * that is in base 64 char set and then '|' again
     */
    char n_rule[] = "[|][A-Za-z0-9+/()#=-]*[|]";

    /*
     * rule to get the signature hash
     * Look for the similar than the n_rule
     */
    char h_rule[] = "[|][A-Za-z0-9+/()#=-]*[|]";

    /*
     * rule to get the signature
     * Look for part that starts ")|" and base 64 blob after it
     * and stops to '|' char remember to add and subtract 2 from
     * the indexes below
     */
    char s_rule[] = "[)][|][A-Za-z0-9+/()#=-]*[|]";

    /* check the algo DSA or RSA  */
    HIP_DEBUG("Verifying\nRunning regexps to identify algo\n");
    start = stop = 0;
    algo  = hip_cert_regex(dsa_rule, cert->public_key, &start, &stop);
    if (algo != -1) {
        HIP_DEBUG("Public-key is DSA\n");
        algo = HIP_HI_DSA;
        goto algo_check_done;
    }
    start = stop = 0;
    algo  = hip_cert_regex(rsa_rule, cert->public_key, &start, &stop);
    if (algo != -1) {
        HIP_DEBUG("Public-key is RSA\n");
        algo = HIP_HI_RSA;
        goto algo_check_done;
    }
    HIP_DEBUG((1 != 1), -1, "Unknown algorithm\n");

algo_check_done:
    if (algo == HIP_HI_RSA) {
        /* malloc space for new rsa */
        rsa = RSA_new();
        HIP_IFEL(!rsa, -1, "Failed to malloc RSA\n");

        /* extract the public-key from cert to rsa */

        /* public exponent first */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(e_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex (exponent)\n");
        e_hex = malloc(stop - start);
        HIP_IFEL(!e_hex, -1, "Malloc for e_hex failed\n");
        snprintf((char *) e_hex, stop - start - 1, "%s",
                 &cert->public_key[start + 1]);

        /* public modulus */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(n_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex (modulus)\n");
        modulus_b64 = calloc(1, stop - start + 1);
        HIP_IFEL(!modulus_b64, -1, "calloc for modulus_b64 failed\n");
        modulus = calloc(1, stop - start + 1);
        HIP_IFEL(!modulus, -1, "calloc for modulus failed\n");
        snprintf((char *) modulus_b64, stop - start - 1, "%s",
                 &cert->public_key[start + 1]);

        /* put the stuff into the RSA struct */
        BN_hex2bn(&rsa->e, e_hex);
        evpret = EVP_DecodeBlock(modulus, modulus_b64,
                                 strlen((char *) modulus_b64));

        /* EVP returns a multiple of 3 octets, subtract any extra */
        keylen = evpret;
        if (keylen % 4 != 0) {
            --keylen;
            keylen = keylen - keylen % 2;
        }
        signature = malloc(keylen);
        HIP_IFEL(!signature, -1, "Malloc for signature failed.\n");
        rsa->n = BN_bin2bn(modulus, keylen, 0);
    } else if (algo == HIP_HI_DSA) {
        /* malloc space for new dsa */
        dsa = DSA_new();
        HIP_IFEL(!dsa, -1, "Failed to malloc DSA\n");

        /* Extract public key from the cert */

        /* dsa->p */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(p_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex dsa->p\n");
        p_b64 = calloc(1, stop - start + 1);
        HIP_IFEL(!p_b64, -1, "calloc for p_b64 failed\n");
        p_bin = calloc(1, stop - start + 1);
        HIP_IFEL(!p_bin, -1, "calloc for p_bin failed\n");
        snprintf((char *) p_b64, stop - start - 1, "%s",
                 &cert->public_key[start + 1]);
        evpret = EVP_DecodeBlock(p_bin, p_b64, strlen((char *) p_b64));

        /* dsa->q */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(q_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex dsa->q\n");
        q_b64 = calloc(1, stop - start + 1);
        HIP_IFEL(!q_b64, -1, "calloc for q_b64 failed\n");
        q_bin = calloc(1, stop - start + 1);
        HIP_IFEL(!q_bin, -1, "calloc for q_bin failed\n");
        snprintf((char *) q_b64, stop - start - 1, "%s",
                 &cert->public_key[start + 1]);
        evpret = EVP_DecodeBlock(q_bin, q_b64, strlen((char *) q_b64));

        /* dsa->g */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(g_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex dsa->g\n");
        g_b64 = calloc(1, stop - start + 1);
        HIP_IFEL(!g_b64, -1, "calloc for g_b64 failed\n");
        g_bin = calloc(1, stop - start + 1);
        HIP_IFEL(!g_bin, -1, "calloc for g_bin failed\n");
        snprintf((char *) g_b64, stop - start - 1, "%s",
                 &cert->public_key[start + 1]);
        evpret = EVP_DecodeBlock(g_bin, g_b64, strlen((char *) g_b64));

        /* dsa->y */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(y_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex dsa->y\n");
        y_b64 = calloc(1, stop - start + 1);
        HIP_IFEL(!y_b64, -1, "calloc for y_b64 failed\n");
        y_bin = calloc(1, stop - start + 1);
        HIP_IFEL(!y_bin, -1, "calloc for y_bin failed\n");
        snprintf((char *) y_b64, stop - start - 1, "%s",
                 &cert->public_key[start + 1]);
        evpret = EVP_DecodeBlock(y_bin, y_b64, strlen((char *) y_b64));
    } else if (algo == HIP_HI_ECDSA) {
        HIP_OUT_ERR(-1, "Call to unimplemented ECDSA case.\n");
    } else {
        HIP_OUT_ERR(-1, "Unknown algorithm\n");
    }

    /* build sha1 digest that will be signed */
    HIP_IFEL(!(sha_retval = SHA1((unsigned char *) cert->cert,
                                 strlen((char *) cert->cert), sha_digest)),
             -1, "SHA1 error when creating digest.\n");

    /* Get the signature hash and compare it to the sha_digest we just made */
    start = stop = 0;
    HIP_IFEL(hip_cert_regex(h_rule, cert->signature, &start, &stop), -1,
             "Failed to run hip_cert_regex (signature hash)\n");
    signature_hash_b64 = calloc(1, stop - start + 1);
    HIP_IFEL(!signature_hash_b64, -1, "Failed to calloc signature_hash_b64\n");
    signature_hash = malloc(stop - start + 1);
    HIP_IFEL(!signature_hash, -1, "Failed to malloc signature_hash\n");
    snprintf((char *) signature_hash_b64, stop - start - 1, "%s",
             &cert->signature[start + 1]);
    evpret = EVP_DecodeBlock(signature_hash, signature_hash_b64,
                             strlen((char *) signature_hash_b64));
    HIP_IFEL(memcmp(sha_digest, signature_hash, 20), -1,
             "Signature hash did not match of the one made from the"
             "cert sequence in the certificate\n");

    /* memset signature and put it into its place */
    start = stop = 0;
    HIP_IFEL(hip_cert_regex(s_rule, cert->signature, &start, &stop), -1,
             "Failed to run hip_cert_regex (signature)\n");
    signature_b64 = calloc(1, stop - start + 1);
    HIP_IFEL(!signature_b64, -1, "Failed to calloc signature_b64\n");
    snprintf((char *) signature_b64, stop - start - 2, "%s",
             &cert->signature[start + 2]);
    if (algo == HIP_HI_DSA) {
        signature = malloc(stop - start + 1);
        HIP_IFEL(!signature, -1, "Failed to malloc signature (dsa)\n");
    }
    evpret = EVP_DecodeBlock(signature, signature_b64,
                             strlen((char *) signature_b64));

    if (algo == HIP_HI_RSA) {
        /* do the verification */
        err = RSA_verify(NID_sha1, sha_digest, SHA_DIGEST_LENGTH,
                         signature, RSA_size(rsa), rsa);
        e_code = ERR_get_error();
        ERR_load_crypto_strings();
        ERR_error_string(e_code, buf);

        /* RSA_verify returns 1 if success. */
        cert->success = err == 1 ? 0 : -1;
        HIP_IFEL((err = err == 1 ? 0 : -1), -1, "RSA_verify error\n");
    } else if (algo == HIP_HI_DSA) {
        /* build the signature structure */
        dsa_sig = DSA_SIG_new();
        HIP_IFEL(!dsa_sig, 1, "Failed to allocate DSA_SIG\n");
        dsa_sig->r = BN_bin2bn(&signature[1], DSA_PRIV, NULL);
        dsa_sig->s = BN_bin2bn(&signature[1 + DSA_PRIV], DSA_PRIV, NULL);

        /* verify the DSA signature */
        err = DSA_do_verify(sha_digest, SHA_DIGEST_LENGTH,
                            dsa_sig, dsa) == 0 ? 1 : 0;

        /* DSA_do_verify returns 1 if success. */
        cert->success = err == 1 ? 0 : -1;
        HIP_IFEL((err = err == 1 ? 0 : -1), -1, "DSA_do_verify error\n");
    } else if (algo == HIP_HI_ECDSA) {
        HIP_OUT_ERR(-1, "Call to unimplemented ECDSA case.\n");
    } else {
        HIP_OUT_ERR(-1, "Unknown algorithm\n");
    }

out_err:
    free(signature_hash_b64);
    free(signature_hash);
    free(modulus_b64);
    free(modulus);
    free(e_hex);
    RSA_free(rsa);
    DSA_free(dsa);
    return err;
}

/**
 * Function to build the basic cert object of SPKI clears public-key
 * object and signature in hip_cert_spki_header
 *
 * @param minimal_content holds the struct hip_cert_spki_header
 *                        containing the minimal needed information for
 *                        cert object, also contains the char table where
 *                        the cert object is to be stored
 *
 * @return always 0
 */
static int cert_spki_build_cert(struct hip_cert_spki_info *minimal_content)
{
    char needed[] = "(cert )";
    memset(minimal_content->public_key, '\0', sizeof(minimal_content->public_key));
    memset(minimal_content->cert, '\0', sizeof(minimal_content->cert));
    memset(minimal_content->signature, '\0', sizeof(minimal_content->signature));
    sprintf(minimal_content->cert, "%s", needed);

    return 0;
}

/**
 * Function for injecting objects to cert object
 *
 * @param to hip_cert_spki_info containing the char table where to insert
 * @param after is a char pointer for the regcomp after which the inject happens
 * @param what is char pointer of what to
 *
 * @return 0 if ok and negative if error. -1 returned for example when after is NOT found
 */
static int cert_spki_inject(struct hip_cert_spki_info *to,
                            const char *after, const char *what)
{
    int        err = 0, status = 0;
    regex_t    re;
    regmatch_t pm[1];
    char      *tmp_cert;

    tmp_cert = calloc(1, strlen(to->cert) + strlen(what) + 1);
    if (!tmp_cert) {
        return -ENOMEM;
    }
    /* Compiling the regular expression */
    HIP_IFEL(regcomp(&re, after, REG_EXTENDED), -1,
             "Compilation of the regular expression failed\n");
    /* Running the regular expression */
    HIP_IFEL((status = regexec(&re, to->cert, 1, pm, 0)), -1,
             "Handling of regular expression failed\n");
    /* Using tmp char table to do the inject (remember the terminators)
     * first the beginning */
    snprintf(tmp_cert, pm[0].rm_eo + 2, "%s", to->cert);
    /* Then the middle part to be injected */
    snprintf(&tmp_cert[pm[0].rm_eo + 1], strlen(what) + 1, "%s", what);
    /* then glue back the rest of the original at the end */
    snprintf(&tmp_cert[(pm[0].rm_eo + strlen(what) + 1)],
             (strlen(to->cert) - pm[0].rm_eo), "%s", &to->cert[pm[0].rm_eo + 1]);
    /* move tmp to the result */
    sprintf(to->cert, "%s", tmp_cert);
out_err:
    free(tmp_cert);
    regfree(&re);
    return err;
}

/**
 * Function to build the create minimal SPKI cert (plus socket parameter)
 *
 * @param content holds the struct hip_cert_spki_info containing
 *                the minimal needed information for cert object,
 *                also contains the char table where the cert object
 *                is to be stored
 * @param issuer_type With HIP its HIT
 * @param issuer HIT in representation encoding 2001:001...
 * @param subject_type With HIP its HIT
 * @param subject HIT in representation encoding 2001:001...
 * @param not_before time in timeval before which the cert should not be used
 * @param not_after time in timeval after which the cert should not be used
 * @param hip_user_socket socket, already connected to hipd, to pass through to
 *                hip_send_recv_daemon_info
 * @return 0 if ok -1 if error
 */
static int cert_spki_create_cert_sock(struct hip_cert_spki_info *content,
                                      const char *issuer_type,
                                      struct in6_addr *issuer,
                                      const char *subject_type,
                                      struct in6_addr *subject,
                                      time_t *not_before,
                                      time_t *not_after,
                                      int hip_user_socket)
{
    int                              err         = 0;
    char                            *tmp_issuer  = NULL;
    char                            *tmp_subject = NULL;
    char                            *tmp_before  = NULL;
    char                            *tmp_after   = NULL;
    struct tm                       *ts          = NULL;
    char                             buf_before[80];
    char                             buf_after[80];
    char                             present_issuer[41]  = { 0 };
    char                             present_subject[41] = { 0 };
    struct hip_common               *msg                 = NULL;
    const struct hip_cert_spki_info *returned            = NULL;

    /* Malloc needed */
    tmp_issuer = calloc(1, 128);
    if (!tmp_issuer) {
        goto out_err;                  /* Why does this return 0? */
    }
    tmp_subject = calloc(1, 128);
    if (!tmp_subject) {
        goto out_err;
    }
    tmp_before = calloc(1, 128);
    if (!tmp_before) {
        goto out_err;
    }
    tmp_after = calloc(1, 128);
    if (!tmp_after) {
        goto out_err;
    }
    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1,
             "Malloc for msg failed\n");

    /* Make needed transforms to the date */
    /*  Format and print the time, "yyyy-mm-dd hh:mm:ss"
     * (not-after "1998-04-15_00:00:00") */
    ts = localtime(not_before);
    strftime(buf_before, sizeof(buf_before), "%Y-%m-%d_%H:%M:%S", ts);
    ts = localtime(not_after);
    strftime(buf_after, sizeof(buf_after), "%Y-%m-%d_%H:%M:%S", ts);

    sprintf(tmp_before, "(not-before \"%s\")", buf_before);
    sprintf(tmp_after, "(not-after \"%s\")", buf_after);

    ipv6_addr_copy(&content->issuer_hit, issuer);
    inet_ntop(AF_INET6, issuer, present_issuer, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, subject, present_subject, INET6_ADDRSTRLEN);

    sprintf(tmp_issuer, "(hash %s %s)", issuer_type, present_issuer);
    sprintf(tmp_subject, "(hash %s %s)", subject_type, present_subject);

    /* Create the cert sequence */
    HIP_IFEL(cert_spki_build_cert(content), -1,
             "cert_spki_build_cert failed\n");

    HIP_IFEL(cert_spki_inject(content, "cert", tmp_after), -1,
             "cert_spki_inject failed to inject\n");
    HIP_IFEL(cert_spki_inject(content, "cert", tmp_before), -1,
             "cert_spki_inject failed to inject\n");
    HIP_IFEL(cert_spki_inject(content, "cert", "(subject )"), -1,
             "cert_spki_inject failed to inject\n");
    HIP_IFEL(cert_spki_inject(content, "subject", tmp_subject), -1,
             "cert_spki_inject failed to inject\n");
    HIP_IFEL(cert_spki_inject(content, "cert", "(issuer )"), -1,
             "cert_spki_inject failed to inject\n");
    HIP_IFEL(cert_spki_inject(content, "issuer", tmp_issuer), -1,
             "cert_spki_inject failed to inject\n");

    /* Create the signature and the public-key sequences */

    /* Send the daemon the struct hip_cert_spki_header
     * containing the cert sequence in content->cert.
     * As a result you should get the struct back with
     * public-key and signature fields filled */

    /* build the msg to be sent to the daemon */
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_CERT_SPKI_SIGN, 0), -1,
             "Failed to build user header\n");
    HIP_IFEL(hip_build_param_cert_spki_info(msg, content), -1,
             "Failed to build cert_info\n");
    /* send and wait */
    HIP_DEBUG("Sending request to sign SPKI cert sequence to "
              "daemon and waiting for answer\n");
    hip_send_recv_daemon_info(msg, 0, hip_user_socket);

    /* get the struct from the message sent back by the daemon */
    HIP_IFEL(!(returned = hip_get_param(msg, HIP_PARAM_CERT_SPKI_INFO)),
             -1, "No hip_cert_spki_info struct found from daemons msg\n");

    memcpy(content, returned, sizeof(struct hip_cert_spki_info));

out_err:
    /* free everything malloced */
    free(tmp_before);
    free(tmp_after);
    free(tmp_issuer);
    free(tmp_subject);
    free(msg);
    return err;
}

/**
 * Function to build the create minimal SPKI cert
 *
 * @param content holds the struct hip_cert_spki_info containing
 *                the minimal needed information for cert object,
 *                also contains the char table where the cert object
 *                is to be stored
 * @param issuer_type With HIP its HIT
 * @param issuer HIT in representation encoding 2001:001...
 * @param subject_type With HIP its HIT
 * @param subject HIT in representation encoding 2001:001...
 * @param not_before time in timeval before which the cert should not be used
 * @param not_after time in timeval after which the cert should not be used
 * @return 0 if ok -1 if error
 */
int hip_cert_spki_create_cert(struct hip_cert_spki_info *content,
                              const char *issuer_type, struct in6_addr *issuer,
                              const char *subject_type, struct in6_addr *subject,
                              time_t *not_before, time_t *not_after)
{
    return cert_spki_create_cert_sock(content, issuer_type, issuer,
                                      subject_type, subject, not_before,
                                      not_after, 0);
}

/**
 * Function that takes the cert in single char table and constructs
 * hip_cert_spki_info from it
 *
 * @param from char pointer to the whole certificate
 * @param to hip_cert_spki_info containing the char table where to insert
 *
 * @return 0 if ok and negative if error.
 */
int hip_cert_spki_char2certinfo(char *from, struct hip_cert_spki_info *to)
{
    int start = 0, stop = 0;
    /*
     * p_rule looks for string "(public_key " after which there can be
     * pretty much anything until string "|)))" is encountered.
     * This is the public-key sequence.
     */
    char p_rule[] = "[(]public_key [ A-Za-z0-9+|/()#=-]*[|][)][)][)]";
    /*
     * c_rule looks for string "(cert " after which there can be
     * pretty much anything until string '"))' is encountered.
     * This is the cert sequence.
     */
    char c_rule[] = "[(]cert [ A-Za-z0-9+|/():=_\"-]*[\"][)][)]";     //\" is one char
    /*
     * s_rule looks for string "(signature " after which there can be
     * pretty much anything until string "|))" is encountered.
     * This is the signature sequence.
     */
    char s_rule[] = "[(]signature [ A-Za-z0-9+/|()=]*[|][)][)]";

    /* Look for the public key */
    if (hip_cert_regex(p_rule, from, &start, &stop)) {
        HIP_ERROR("Failed to run hip_cert_regex (public-key)\n");
        return -1;
    }
    snprintf(to->public_key, stop - start + 1, "%s", &from[start]);

    /* Look for the cert sequence */
    start = stop = 0;
    if (hip_cert_regex(c_rule, from, &start, &stop)) {
        HIP_ERROR("Failed to run hip_cert_regex (cert)\n");
        return -1;
    }
    snprintf(to->cert, stop - start + 1, "%s", &from[start]);

    /* look for the signature sequence */
    start = stop = 0;
    if (hip_cert_regex(s_rule, from, &start, &stop)) {
        HIP_ERROR("Failed to run hip_cert_regex (signature)\n");
        return -1;
    }
    snprintf(to->signature, stop - start + 1, "%s", &from[start]);

    return 0;
}

/**
 * Function that sends the given hip_cert_spki_info to the daemon to
 * verification
 *
 * @param to_verification is the cert to be verified
 *
 * @return 0 if ok and negative if error or unsuccessful.
 *
 * @note use hip_cert_spki_char2certinfo to build the hip_cert_spki_info
 */
int hip_cert_spki_send_to_verification(struct hip_cert_spki_info *to_verification)
{
    int                              err = 0;
    struct hip_common               *msg;
    const struct hip_cert_spki_info *returned;

    if (!(msg = malloc(HIP_MAX_PACKET))) {
        HIP_ERROR("Malloc for msg failed\n");
        return -ENOMEM;
    }
    hip_msg_init(msg);
    /* build the msg to be sent to the daemon */
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_CERT_SPKI_VERIFY, 0), -1,
             "Failed to build user header\n");
    HIP_IFEL(hip_build_param_cert_spki_info(msg, to_verification), -1,
             "Failed to build cert_info\n");

    /* send and wait */
    HIP_DEBUG("Sending request to verify SPKI cert to "
              "daemon and waiting for answer\n");
    hip_send_recv_daemon_info(msg, 0, 0);

    HIP_IFEL(!(returned = hip_get_param(msg, HIP_PARAM_CERT_SPKI_INFO)),
             -1, "No hip_cert_spki_info struct found from daemons msg\n");

    memcpy(to_verification, returned, sizeof(struct hip_cert_spki_info));

out_err:
    free(msg);
    return err;
}

/******************************************************************************
 * FUNCTIONS FOR x509v3                                                       *
 ******************************************************************************/

/**
 * Function that requests for a certificate from daemon and gives it back.
 *
 * @param subject is the subjects HIT
 *
 * @param certificate is pointer to a buffer to which this function writes the completed cert
 *
 * @return positive on success negative otherwise
 *
 * @note The certificate is given in DER encoding
 */
uint32_t hip_cert_x509v3_request_certificate(struct in6_addr *subject,
                                             unsigned char *certificate)
{
    uint32_t                         err = 0;
    struct hip_common               *msg;
    const struct hip_cert_x509_resp *p;

    if (!(msg = malloc(HIP_MAX_PACKET))) {
        HIP_ERROR("Malloc for msg failed\n");
        return -ENOMEM;
    }
    hip_msg_init(msg);
    /* build the msg to be sent to the daemon */

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_CERT_X509V3_SIGN, 0), -1,
             "Failed to build user header\n");
    HIP_IFEL(hip_build_param_cert_x509_req(msg, subject), -1,
             "Failed to build cert_info\n");
    /* send and wait */
    HIP_DEBUG("Sending request to sign x509 cert to "
              "daemon and waiting for answer\n");
    hip_send_recv_daemon_info(msg, 0, 0);
    /* get the struct from the message sent back by the daemon */
    HIP_IFEL(!(p = hip_get_param(msg, HIP_PARAM_CERT_X509_RESP)), -1,
             "No name x509 struct found\n");
    memcpy(certificate, p->der, ntohl(p->der_len));
    err = ntohl(p->der_len);

out_err:
    free(msg);
    return err;
}

/**
 * Function that requests for a verification of a certificate from
 * daemon and tells the result.
 *
 * @param certificate is pointer to a certificate to be verified
 * @param len is the length of the cert in certificate parameter in bytes
 *
 * @return 0 on success negative otherwise
 *
 * @note give the certificate in PEM encoding
 */
int hip_cert_x509v3_request_verification(unsigned char *certificate, uint32_t len)
{
    int                              err = 0;
    struct hip_common               *msg;
    const struct hip_cert_x509_resp *received;

    if (!(msg = malloc(HIP_MAX_PACKET))) {
        HIP_ERROR("Malloc for msg failed\n");
        return -ENOMEM;
    }
    hip_msg_init(msg);

    /* build the msg to be sent to the daemon */
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_CERT_X509V3_VERIFY, 0), -1,
             "Failed to build user header\n");
    HIP_IFEL(hip_build_param_cert_x509_ver(msg, (char *) certificate, len), -1,
             "Failed to build cert_info\n");

    /* send and wait */
    HIP_DEBUG("Sending request to verify x509  cert to "
              "daemon and waiting for answer\n");
    hip_send_recv_daemon_info(msg, 0, 0);

    /* get the struct from the message sent back by the daemon */
    HIP_IFEL(!(received = hip_get_param(msg, HIP_PARAM_CERT_X509_RESP)), -1,
             "No x509 struct found\n");
    err = hip_get_msg_err(msg);
    if (err == 0) {
        HIP_DEBUG("Verified successfully\n");
    } else {
        HIP_DEBUG("Verification failed\n");
    }

out_err:
    free(msg);
    return err;
}

/*****************************************************************************
 * UTILITY FUNCTIONS                                                         *
 *****************************************************************************/

/**
 * Read configuration section from loaded configuration file.
 *
 * @param section_name the name of the section to be retrieved
 * @param conf         the loaded configuration to read from
 *
 * @return STACK_OF(CONF_VALUE) pointer if OK, NULL on error
 *
 * @note Remember to open the configuration file with hip_cert_open_conf() and
 *       close it after processing with NCONF_free().
 */
STACK_OF(CONF_VALUE) *hip_read_conf_section(const char *section_name,
                                            CONF *conf)
{
    STACK_OF(CONF_VALUE) *sec;

    if (!(sec = NCONF_get_section(conf, section_name))) {
        HIP_ERROR("Section %s was not in the configuration (%s)\n",
                  section_name, HIP_CERT_CONF_PATH);
        return NULL;
    }

    return sec;
}

/**
 * Load the indicated configuration file.
 *
 * @return CONF pointer if OK, NULL on error
 */
CONF *hip_open_conf(const char *filename)
{
    CONF *conf;

    conf = NCONF_new(NCONF_default());
    if (!NCONF_load(conf, filename, NULL)) {
        HIP_ERROR("Error opening the configuration file");
        NCONF_free(conf);
        return NULL;
    }
    return conf;
}

/**
 * Function that wraps regular expression stuff and gives the answer :)
 *
 * @param what is a char pointer to the rule used in the search (POSIX)
 * @param from where are we looking for it char pointer
 * @param start will store the start point of the found substr
 * @param stop will store the end point of the found substr
 *
 * @return 0 if ok and negative if error.
 *
 * @note Be carefull with the what so you get what you want :)
 */
int hip_cert_regex(char *what, char *from, int *start, int *stop)
{
    int        err = 0, status = 0;
    regex_t    re;
    regmatch_t answer[1];

    *start = *stop = 0;

    /* Compiling the regular expression */
    if (regcomp(&re, what, REG_EXTENDED)) {
        HIP_ERROR("Compilation of the regular expression failed\n");
        return -1;
    }
    /* Running the regular expression */
    // TODO this might need to be an error!?
    // this needs to be separated to found, not found, and error -Samu
    if ((status = regexec(&re, from, 1, answer, 0))) {
        err = -1;
        goto out_err;
    }

    *start = answer[0].rm_so;
    *stop  = answer[0].rm_eo;

out_err:
    regfree(&re);
    return err;
}
