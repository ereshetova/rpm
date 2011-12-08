#include "system.h"

#include <rpm/rpmmacro.h>
#include <rpm/rpmtypes.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmts.h>

#include <rpm/rpmsecurity.h>

#define STR1(x) #x
#define STR(x) STR1(x)

struct rpmSecurity_s {
    void *handle;
    rpmRC (*SECURITYHOOK_INIT_FUNC)(rpmts, const char *);
    rpmRC (*SECURITYHOOK_FILE_CONFLICT_FUNC)(rpmts, rpmte, rpmfi, Header, rpmfi, int);
    rpmRC (*SECURITYHOOK_PRE_TSM_FUNC)(rpmts);
    rpmRC (*SECURITYHOOK_VERIFY_FUNC)(rpmKeyring, rpmtd, pgpDigParams, rpmRC);
    rpmRC (*SECURITYHOOK_PRE_PSM_FUNC)(rpmte);
    rpmRC (*SECURITYHOOK_SCRIPT_EXEC_FUNC)(ARGV_const_t);
    rpmRC (*SECURITYHOOK_FSM_OPENED_FUNC)(const char*, const char*);
    rpmRC (*SECURITYHOOK_FSM_UPDATED_FUNC)(const struct stat *, char *, size_t);
    rpmRC (*SECURITYHOOK_FSM_CLOSED_FUNC)(const char*, const char*, int);
    rpmRC (*SECURITYHOOK_POST_PSM_FUNC)(rpmte, int);
    rpmRC (*SECURITYHOOK_POST_TSM_FUNC)(rpmts);
    rpmRC (*SECURITYHOOK_CLEANUP_FUNC)(void);
    int count;
    rpmts ts;
};

static rpmSecurity securityPlugin = NULL;

rpmRC rpmsecurityCallInit(const char *opts);
rpmRC rpmsecurityCallCleanup(void);

#define RPMSECURITY_GET_HOOK_FUNC(hook)					\
    *(void **)(&securityPlugin->hook) = dlsym(securityPlugin->handle, STR(hook)); \
    if ((error = dlerror()) != NULL) {					\
	rpmlog(RPMLOG_ERR, _("Failed to resolve security plugin symbol %s: %s\n"), STR(hook), error); \
	goto fail;							\
    }

static rpmRC rpmsecurityAdd(const char *path, const char *opts, rpmts ts)
{
    char *error;

    void *handle = dlopen(path, RTLD_LAZY);
    if (!handle) {
	rpmlog(RPMLOG_DEBUG, _("Failed to dlopen %s %s\n"), path, dlerror());
	goto fail;
    }

    securityPlugin = xcalloc(1, sizeof(*securityPlugin));
    if (!securityPlugin) {
	rpmlog(RPMLOG_ERR, _("Failed to allocate security plugin %s\n"), path);
	goto fail;
    }

    securityPlugin->handle = handle;
    securityPlugin->count++;
    securityPlugin->ts = ts;

    /* Security plugin really has to have all the hooks. This means that */ 
    /* if the interface is changed, all plugins have to be changed which */
    /* in general is not nice. However, a security plugin must be aware of */
    /* all the hooks declaring empty functions if it doesn't need them. */
    RPMSECURITY_GET_HOOK_FUNC(SECURITYHOOK_INIT_FUNC);
    RPMSECURITY_GET_HOOK_FUNC(SECURITYHOOK_FILE_CONFLICT_FUNC);
    RPMSECURITY_GET_HOOK_FUNC(SECURITYHOOK_PRE_TSM_FUNC);
    RPMSECURITY_GET_HOOK_FUNC(SECURITYHOOK_VERIFY_FUNC);
    RPMSECURITY_GET_HOOK_FUNC(SECURITYHOOK_PRE_PSM_FUNC);
    RPMSECURITY_GET_HOOK_FUNC(SECURITYHOOK_SCRIPT_EXEC_FUNC);
    RPMSECURITY_GET_HOOK_FUNC(SECURITYHOOK_FSM_OPENED_FUNC);
    RPMSECURITY_GET_HOOK_FUNC(SECURITYHOOK_FSM_UPDATED_FUNC);
    RPMSECURITY_GET_HOOK_FUNC(SECURITYHOOK_FSM_CLOSED_FUNC);
    RPMSECURITY_GET_HOOK_FUNC(SECURITYHOOK_POST_PSM_FUNC);
    RPMSECURITY_GET_HOOK_FUNC(SECURITYHOOK_POST_TSM_FUNC);
    RPMSECURITY_GET_HOOK_FUNC(SECURITYHOOK_CLEANUP_FUNC);

    return rpmsecurityCallInit(opts);

 fail:
    if (handle) dlclose(handle);
    if (securityPlugin) free(securityPlugin);
    return RPMRC_FAIL;
}

rpmRC rpmsecuritySetupPlugin(rpmts ts)
{
    char *path;
    char *options;
    int rc = RPMRC_FAIL;

    if (securityPlugin) {
	securityPlugin->count++;
	return RPMRC_OK;
    }

    path = rpmExpand("%{?__security_plugin}", NULL);
    if (!path || rstreq(path, "")) {
/* enforce security by default #ifdef ENFORCE_SECURITY */
	rpmlog(RPMLOG_ERR, _("Failed to expand %%__security_plugin macro\n"));
/*#else
	rpmlog(RPMLOG_INFO, _("Failed to expand %%__security_plugin macro\n"));
#endif*/
	goto exit;
    }

    /* split the options from the path */
#define SKIPSPACE(s)    { while (*(s) &&  risspace(*(s))) (s)++; }
#define SKIPNONSPACE(s) { while (*(s) && !risspace(*(s))) (s)++; }
    options = path;
    SKIPNONSPACE(options);
    if (risspace(*options)) {
	*options = '\0';
	options++;
	SKIPSPACE(options);
    }
    if (*options == '\0') {
	options = NULL;
    }

    rc = rpmsecurityAdd(path, options, ts);
  exit:
    if (path) _free(path);
    return rc;
}

int rpmsecurityPluginAdded(void)
{
    return (securityPlugin != NULL);
}

rpmSecurity rpmsecurityFreePlugin()
{
    if (securityPlugin) {
	securityPlugin->count--;
	if (!securityPlugin->count) {
	    rpmsecurityCallCleanup();
	    dlclose(securityPlugin->handle);
	    securityPlugin = _free(securityPlugin);
	}
    }
    return securityPlugin;
}

#define RPMSECURITY_SET_HOOK_FUNC(hook)					\
    hookFunc = securityPlugin->hook;					\
    if (rpmtsFlags(securityPlugin->ts) & RPMTRANS_FLAG_TEST) {		\
	return RPMRC_OK;						\
    }									\
    rpmlog(RPMLOG_DEBUG, "Security: calling hook %s in security plugin\n", STR(hook));

rpmRC rpmsecurityCallInit(const char *opts)
{
    rpmRC (*hookFunc)(rpmts, const char *);
    RPMSECURITY_SET_HOOK_FUNC(SECURITYHOOK_INIT_FUNC);
    return hookFunc(securityPlugin->ts, opts);
}

rpmRC rpmsecurityCallCleanup(void)
{
    rpmRC (*hookFunc)(void);
    RPMSECURITY_SET_HOOK_FUNC(SECURITYHOOK_CLEANUP_FUNC);
    return hookFunc();
}

rpmRC rpmsecurityCallPreTsm(rpmts ts)
{
    if (securityPlugin) {
	rpmRC (*hookFunc)(rpmts);
	RPMSECURITY_SET_HOOK_FUNC(SECURITYHOOK_PRE_TSM_FUNC);
	return hookFunc(ts);
    }
    return RPMRC_OK;
}

rpmRC rpmsecurityCallPostTsm(rpmts ts)
{
    if (securityPlugin) {
	rpmRC (*hookFunc)(rpmts);
	RPMSECURITY_SET_HOOK_FUNC(SECURITYHOOK_POST_TSM_FUNC);
	return hookFunc(ts);
    }
    return RPMRC_OK;
}

rpmRC rpmsecurityCallPrePsm(rpmte te)
{
    if (securityPlugin) {
	rpmRC (*hookFunc)(rpmte);
	RPMSECURITY_SET_HOOK_FUNC(SECURITYHOOK_PRE_PSM_FUNC);
	return hookFunc(te);
    }
    return RPMRC_OK;
}

rpmRC rpmsecurityCallPostPsm(rpmte te, int rpmrc)
{
    if (securityPlugin) {
	rpmRC (*hookFunc)(rpmte, int);
	RPMSECURITY_SET_HOOK_FUNC(SECURITYHOOK_POST_PSM_FUNC);
	return hookFunc(te, rpmrc);
    }
    return rpmrc;
}

rpmRC rpmsecurityCallScriptExec(ARGV_const_t argv)
{
    if (securityPlugin) {
	rpmRC (*hookFunc)(ARGV_const_t);
	RPMSECURITY_SET_HOOK_FUNC(SECURITYHOOK_SCRIPT_EXEC_FUNC);
	return hookFunc(argv);
    }
    return execv(argv[0], argv);
}

rpmRC rpmsecurityCallFsmOpened(const char* dirName, const char* baseName)
{
    if (securityPlugin) {
	rpmRC (*hookFunc)(const char*, const char*);
	RPMSECURITY_SET_HOOK_FUNC(SECURITYHOOK_FSM_OPENED_FUNC);
	return hookFunc(dirName, baseName);
    }
    return RPMRC_OK;
}

rpmRC rpmsecurityCallFsmUpdated(const struct stat * st, char *buf, size_t len)
{
    if (securityPlugin) {
	rpmRC (*hookFunc)(const struct stat *, char *, size_t);
	RPMSECURITY_SET_HOOK_FUNC(SECURITYHOOK_FSM_UPDATED_FUNC);
	return hookFunc(st, buf, len);
    }
    return RPMRC_OK;
}

rpmRC rpmsecurityCallFsmClosed(const char* dirName, const char* baseName, int rpmrc)
{
    if (securityPlugin) {
	rpmRC (*hookFunc)(const char*, const char*, int);
	RPMSECURITY_SET_HOOK_FUNC(SECURITYHOOK_FSM_CLOSED_FUNC);
	return hookFunc(dirName, baseName, rpmrc);
    }
    return rpmrc;
}

rpmRC rpmsecurityCallVerify(rpmKeyring keyring, rpmtd sigtd, 
			    pgpDigParams sig, rpmRC rpmrc)
{
    if (securityPlugin) {
	rpmRC (*hookFunc)(rpmKeyring, rpmtd, pgpDigParams, rpmRC);
	RPMSECURITY_SET_HOOK_FUNC(SECURITYHOOK_VERIFY_FUNC);
	return hookFunc(keyring, sigtd, sig, rpmrc);
    }
    return rpmrc;
}

rpmRC rpmsecurityCallFileConflict(rpmts ts, rpmte te, rpmfi fi,
				  Header oldHeader, rpmfi oldFi, int rpmrc)
{
    if (securityPlugin) {
	rpmRC (*hookFunc)(rpmts, rpmte, rpmfi, Header, rpmfi, int);
	RPMSECURITY_SET_HOOK_FUNC(SECURITYHOOK_FILE_CONFLICT_FUNC);
	return hookFunc(ts, te, fi, oldHeader, oldFi, rpmrc);
    }
    return rpmrc;
}
