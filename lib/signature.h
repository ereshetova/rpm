#ifndef H_SIGNATURE
#define	H_SIGNATURE

/** \ingroup signature
 * \file lib/signature.h
 * Generate and verify signatures.
 */

#include <rpm/header.h>

/** \ingroup signature
 * Signature types stored in rpm lead.
 */
typedef	enum sigType_e {
    RPMSIGTYPE_HEADERSIG= 5	/*!< Header style signature */
} sigType;

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup signature
 * Return new, empty (signature) header instance.
 * @return		signature header
 */
Header rpmNewSignature(void);

/** \ingroup signature
 * Read (and verify header+payload size) signature header.
 * If an old-style signature is found, we emulate a new style one.
 * @param fd		file handle
 * @retval sighp	address of (signature) header (or NULL)
 * @param sig_type	type of signature header to read (from lead)
 * @retval msg		failure msg
 * @return		rpmRC return code
 */
rpmRC rpmReadSignature(FD_t fd, Header *sighp, sigType sig_type, char ** msg);

/** \ingroup signature
 * Write signature header.
 * @param fd		file handle
 * @param h		(signature) header
 * @return		0 on success, 1 on error
 */
int rpmWriteSignature(FD_t fd, Header h);

/** \ingroup signature
 * Generate digest(s) from a header+payload file, save in signature header.
 * @param sigh		signature header
 * @param file		header+payload file name
 * @param sigTag	type of digest(s) to add
 * @return		0 on success, -1 on failure
 */
int rpmGenDigest(Header sigh, const char * file, rpmTagVal sigTag);

/** \ingroup signature
 * Verify a signature from a package.
 *
 * @param keyring	keyring handle
 * @param sigtd		signature tag data container
 * @param sig		signature/pubkey parameters
 * @retval result	detailed text result of signature verification
 * 			(malloc'd)
 * @return		result of signature verification
 */
rpmRC rpmVerifySignature(rpmKeyring keyring, rpmtd sigtd, pgpDigParams sig,
			 DIGEST_CTX ctx, char ** result);

/** \ingroup signature
 * Destroy signature header from package.
 * @param h		signature header
 * @return		NULL always
 */
Header rpmFreeSignature(Header h);

/* Dumb wrapper around pgpPrtParams() to log some error messages on failure */
RPM_GNUC_INTERNAL
int parsePGPSig(rpmtd sigtd, const char *type, const char *fn,
		 pgpDigParams *sig);

#ifdef __cplusplus
}
#endif

#endif	/* H_SIGNATURE */
