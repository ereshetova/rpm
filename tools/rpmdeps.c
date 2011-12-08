#include "system.h"
const char *__progname;

#include <rpm/rpmbuild.h>
#include <rpm/argv.h>
#include <rpm/rpmds.h>
#include <rpm/rpmfc.h>

#include "debug.h"

char *progname;

static int print_provides;

static int print_requires;

static void rpmdsPrint(const char * msg, rpmds ds, FILE * fp)
{
    if (fp == NULL) fp = stderr;

    if (msg)
	fprintf(fp, "===================================== %s\n", msg);

    ds = rpmdsInit(ds);
    while (rpmdsNext(ds) >= 0)
	fprintf(fp, "%s\n", rpmdsDNEVR(ds)+2);
}

static struct poptOption optionsTable[] = {

 { NULL, '\0', POPT_ARG_INCLUDE_TABLE, rpmcliAllPoptTable, 0,
	N_("Common options for all rpm modes and executables:"),
	NULL }, 

 { "provides", 'P', POPT_ARG_VAL, &print_provides, -1,
        NULL, NULL },
 { "requires", 'R', POPT_ARG_VAL, &print_requires, -1,
        NULL, NULL },

   POPT_AUTOALIAS
   POPT_AUTOHELP
   POPT_TABLEEND
};

int
main(int argc, char *argv[])
{
    poptContext optCon = NULL;
    ARGV_t av = NULL;
    rpmfc fc = NULL;
    int ec = 1;
    char buf[BUFSIZ];

    if ((progname = strrchr(argv[0], '/')) != NULL)
	progname++;
    else
	progname = argv[0];

    optCon = rpmcliInit(argc, argv, optionsTable);
    if (optCon == NULL)
	goto exit;

    while (fgets(buf, sizeof(buf), stdin) != NULL) {
	char *be = buf + strlen(buf) - 1;
	while (strchr("\r\n", *be) != NULL)
	    *be-- = '\0';
	argvAdd(&av, buf);
    }
    /* Make sure file names are sorted. */
    argvSort(av, NULL);

    /* Build file/package class and dependency dictionaries. */
    fc = rpmfcCreate(getenv("RPM_BUILD_ROOT"), 0);
    if (rpmfcClassify(fc, av, NULL) || rpmfcApply(fc))
	goto exit;

    if (_rpmfc_debug)
	rpmfcPrint(buf, fc, NULL);

    if (print_provides)
	rpmdsPrint(NULL, rpmfcProvides(fc), stdout);
    if (print_requires)
	rpmdsPrint(NULL, rpmfcRequires(fc), stdout);

    ec = 0;

exit:
    argvFree(av);
    rpmfcFree(fc);
    rpmcliFini(optCon);
    return ec;
}
