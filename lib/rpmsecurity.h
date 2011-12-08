#ifndef _SECURITY_H
#define _SECURITY_H

#include <rpm/rpmtypes.h>
#include <rpm/rpmpgp.h>
#include <lib/fsm.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmsecurity
 *
 * General flow of code in rpm:
 *
 * The first hook SECURITYHOOK_INIT_FUNC is called right after keyring is
 * loaded and database indexes are opened.
 *
 * At the time rpm prepares packages for installation, it might call
 * SECURITYHOOK_FILE_CONFLICT_FUNC if some new package has conflicting files.
 * Security plugin can then decide if overwrite is allowed or not. After
 * conflict resolving rpm calls SECURITYHOOK_PRE_TSM_FUNC.
 *
 * The actual package processing starts by calling SECURITYHOOK_VERIFY_FUNC
 * where security plugin can verify the package signature (right after rpm
 * has done it's own signature verifying). 

 * Then SECURITYHOOK_PRE_PSM_FUNC is called to start installing/removing 
 * the package. In the beginning of installation process there may be call 
 * to SECURITYHOOK_SCRIPT_EXEC_FUNC if package spec has a pre installation
 * script. Then SECURITYHOOK_FSM_OPENED_FUNC, SECURITYHOOK_FSM_UPDATED_FUNC
 * and SECURITYHOOK_FSM_CLOSED_FUNC are called for each installed file to
 * make it possible to calculate hashes for the files (or use the sum
 * in rpm package). At the end of installation process there may be call 
 * to SECURITYHOOK_SCRIPT_EXEC_FUNC if package spec has a post installation
 * script. Finally SECURITYHOOK_POST_PSM_FUNC is called to wrap up package 
 * processing.
 * 
 * SECURITYHOOK_POST_TSM_FUNC is called when all packages have been processed.
 * 
 * Finally SECURITYHOOK_CLEANUP_FUNC is called to free used resources.
 */

/** \ingroup rpmsecurity
 * Add and open security plugin, calls SECURITYHOOK_INIT_FUNC.
 * This is the place for the plugin to initialize itself, load
 * possible configuration files etc.
 * @param ts		ts element
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
rpmRC rpmsecuritySetupPlugin(rpmts ts);

/** \ingroup rpmsecurity
 * Call the security file conflict plugin hook.
 * This hook is called whenever there is a file conflict.
 * @param ts		transaction set
 * @param te		transaction element
 * @param fi		new file
 * @param oldHeader	old header
 * @param oldFi		old file
 * @param rpmrc         success from RPM
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
rpmRC rpmsecurityCallFileConflict(rpmts ts, rpmte te, rpmfi fi,
				  Header oldHeader, rpmfi oldFi, int rpmrc);

/** \ingroup rpmsecurity
 * Call the security pre tsm plugin hook.
 * This hook is called before the transaction state machine is started.
 * @param ts		transaction set
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
rpmRC rpmsecurityCallPreTsm(rpmts ts);

/** \ingroup rpmsecurity
 * Call the security verify plugin hook.
 * This hook is called right after RPM has verified package signature.
 * @param keyring	RPM keyring
 * @param sigtd		signature tag
 * @param dig		PGP digest
 * @param rpmrc		success from RPM
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
rpmRC rpmsecurityCallVerify(rpmKeyring keyring, rpmtd sigtd, 
			    pgpDig dig, rpmRC rpmrc);

/** \ingroup rpmsecurity
 * Call the security pre psm plugin hook.
 * This hook is called before the package state machine is started.
 * @param te		transaction element in question
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
rpmRC rpmsecurityCallPrePsm(rpmte te);

/** \ingroup rpmsecurity
 * Call the security script exec plugin hook.
 * Script execution takes place in child process context.
 * @param argv		script command line arguments
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
rpmRC rpmsecurityCallScriptExec(ARGV_const_t argv);

/** \ingroup rpmsecurity
 * Call the security file opened plugin hook.
 * This hook is called before the file state machine is started.
 * @param fsm		fsm in question
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
rpmRC rpmsecurityCallFsmOpened(FSM_t fsm);

/** \ingroup rpmsecurity
 * Call the security file updated plugin hook.
 * This hook is called during the file state machine is running.
 * @param fsm		fsm in question
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
rpmRC rpmsecurityCallFsmUpdated(FSM_t fsm);

/** \ingroup rpmsecurity
 * Call the security file closed plugin hook.
 * This hook is called after the file state machine has finished.
 * @param fsm		fsm in question
 * @param rpmrc		success from RPM
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
rpmRC rpmsecurityCallFsmClosed(FSM_t fsm, int rpmrc);

/** \ingroup rpmsecurity
 * Call the security post psm plugin hook.
 * This hook is called after the package state machine has finished.
 * @param te		transaction element in question
 * @param rpmrc		success from RPM
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
rpmRC rpmsecurityCallPostPsm(rpmte te, int rpmrc);

/** \ingroup rpmsecurity
 * Call the security post tsm plugin hook.
 * This hook is called after the transaction state machine has finished.
 * @param ts		transaction set
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
rpmRC rpmsecurityCallPostTsm(rpmts ts);

/** \ingroup rpmsecurity
 * Destroy security plugin structure, calls SECURITYHOOK_CLEANUP_FUNC.
 * Plugin can save new state and new configuration in cleanup.
 * @return		NULL always
 */
rpmSecurity rpmsecurityFreePlugin(void);

/** \ingroup rpmsecurity
 * Determine if a security plugin has been added already.
 * @return		1 if security plugin has already been added, 0 otherwise
 */
int rpmsecurityPluginAdded(void);
#ifdef __cplusplus
}
#endif
#endif	/* _SECURITY_H */
