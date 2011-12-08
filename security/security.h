#include "system.h"

#include <rpm/rpmmacro.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmts.h>
#include <rpm/rpmte.h>

#include "rpmio/digest.h"
#include "lib/rpmsecurity.h"

rpmRC SECURITYHOOK_INIT_FUNC(rpmts ts, const char *opts);
rpmRC SECURITYHOOK_CLEANUP_FUNC(void);
rpmRC SECURITYHOOK_PRE_TSM_FUNC(rpmts _ts);
rpmRC SECURITYHOOK_POST_TSM_FUNC(rpmts _ts);
rpmRC SECURITYHOOK_PRE_PSM_FUNC(rpmte _te);
rpmRC SECURITYHOOK_POST_PSM_FUNC(rpmte _te, int rpmrc);
rpmRC SECURITYHOOK_SCRIPT_EXEC_FUNC(ARGV_const_t argv);
rpmRC SECURITYHOOK_FSM_OPENED_FUNC(const char* dirName, const char* baseName);
rpmRC SECURITYHOOK_FSM_UPDATED_FUNC(const struct stat * st, char *buf, size_t len);
rpmRC SECURITYHOOK_FSM_CLOSED_FUNC(int rpmrc);
rpmRC SECURITYHOOK_VERIFY_FUNC(rpmKeyring keyring, rpmtd sigtd, 
			       pgpDigParams sig, rpmRC rpmrc);
rpmRC SECURITYHOOK_FILE_CONFLICT_FUNC(rpmts ts, rpmte te, rpmfi fi,
				      Header oldHeader, rpmfi oldFi, int rpmrc);
