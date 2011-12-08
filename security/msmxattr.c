/*
 * This file is part of MSM security plugin
 * Greatly based on the code of MSSF security plugin
 *
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
 *
 * Contact: Tero Aho <ext-tero.aho@nokia.com>
 *
 * Copyright (C) 2011 Intel Corporation.
 *
 * Contact: Elena Reshetova <elena.reshetova@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/capability.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <attr/xattr.h>
#include <uthash.h>

#include "msm.h"

static ac_domain_x *all_ac_domains = NULL; /* hash of all provided ac domains */
static package_x *allpackages = NULL; /* hash of all installed packages */

void msmFreeInternalHashes(void)
{
    if (all_ac_domains) {
	HASH_CLEAR(hh,all_ac_domains);
    }

    if (allpackages) {
	HASH_CLEAR(hh,allpackages);
    }
}
static int msmCheckACDomainRules(ac_domain_x *ac_domain, 
				    sw_source_x *requested, sw_source_x *provided)
{
    sw_source_x *sw_source;


    /* go through sw source and its parents: ac domains must not match */
    /* deny or deny wildcards and must match allow or allow wildcards */
    /* in the whole path up to the level of the providing sw source */ 
    for (sw_source = requested; sw_source->parent && sw_source->parent != sw_source; sw_source = sw_source->parent) {
	ac_domain_x *denied;
	ac_domain_x *allowed;
	/* check first if requested ac domain is denied */
	HASH_FIND(hh, sw_source->denys, ac_domain->name, strlen(ac_domain->name), denied);
	if (denied) return 0; /* matched deny */
	for (denied = sw_source->denymatches; denied; denied = denied->prev)
	    if (!strwcmp(denied->match, ac_domain->name)) 
		return 0; /* matched deny wildcard */

	/* not denied, now check if it's in allows or allowmatches */
	HASH_FIND(hh, sw_source->allows, ac_domain->name, strlen(ac_domain->name), allowed);
	if (allowed) continue; /* matched allow */
	for (allowed = sw_source->allowmatches; allowed; allowed = allowed->prev)
	    if (!strwcmp(allowed->match, ac_domain->name)) 
		break; /* matched allow wildcard */
	if (allowed) continue; /* matched allow wildcard */

	if (strcmp(sw_source->rankkey, provided->rankkey) <= 0)
	    return 1; /* ranked higher (or same sw source), allow */
	return 0; /* not mentioned, deny */
    }
    return 1; /* still here, allow for root sw source */
}


static int msmSetSmackRules(struct smack_accesses *smack_accesses, ac_domain_x *ac_domains, const char *aid)
{
    ac_domain_x *ac_domain;
    int ret = 0;

    if (!smack_accesses) return ret;


    for (ac_domain = ac_domains; ac_domain; ac_domain = ac_domain->prev) {
	if (ac_domain->allowed) {
	    ret = smack_accesses_add(smack_accesses, aid, ac_domain->name, "rw");
	    if (ret < 0) {
		rpmlog(RPMLOG_ERR, "smack_add failed for %s %s\n", 
		       aid, ac_domain->name);
		return ret;
	    }
	}/* else if (!ac_domain->allowed && !ac_domain->newer) {
	    // remove not allowed rule in case something has changed 
	    smack_rule_set_remove(rule_set, aid, ac_domain->name, NULL);
	}*/
    }
    return ret;

}


static int msmIsProvideAllowed(ac_domain_x *provided, sw_source_x *sw_source, const char *origin)
{

    /* first check provided ac_domain attributes */
    if (provided->sw_source == sw_source) {
	/* allowed always if ac_domain is provided in the same sw source */
	return 1;
    } else if (origin && !strcmp(origin, "current")) {
	/* denied if ac_domain is only meant for current sw source */
	return 0;
    }
    if (origin && !strcmp(origin, "all")) {
	/* ac_domain is allowed for all sw sources */
	return 1;
    }
    if (!origin || !strcmp(origin, "trusted")) {
	if (strcmp(sw_source->rankkey, provided->sw_source->rankkey) < 0) {
	    /* higher ranked sw sources are allowed if ac_domain is trusted */
	    return 1;
	} /* else flow through to check denys and allows below */
    } else return 0;

    return msmCheckACDomainRules(provided, sw_source, provided->sw_source);
}


static int msmSetSmackProvide(struct smack_accesses *smack_accesses, provide_x *provide, sw_source_x *sw_source)
{
    ac_domain_x *ac_domain;
    sw_source_x *current = sw_source;
    int ret = -1;

    if (!provide || (!provide->ac_domains)) return 0;

    /* set smack rules for all sw sources */
    LISTHEAD(current, sw_source);
    for (; sw_source; sw_source = sw_source->next) {
	if (!sw_source->newer) {
	    for (ac_domain = provide->ac_domains; ac_domain; ac_domain = ac_domain->prev) {
		    ac_domain->allowed = msmIsProvideAllowed(ac_domain, sw_source, ac_domain->origin);
		    rpmlog(RPMLOG_INFO, "%s ac_domain %s provided in %s for %s\n", (ac_domain->allowed ? "allowing" : "not allowing"), 
							ac_domain->name, ac_domain->sw_source->name, sw_source->name);
	    }
	    if (smack_accesses)
	    	ret = msmSetSmackRules(smack_accesses, provide->ac_domains, sw_source->name);
	    else 
		ret = 0;
	}
    }
    return ret;
}

static int msmSetupZypperRepo(access_x *access, sw_source_x *sw_source)
{
    struct stat sb;
    char path[NAME_MAX+1];
    FILE *file = NULL;
    char data[512];
    int ret = -1;

    /* NOTE: Creating zypper repos manually here! */
    /* A library call would be the correct way, but calling c++ from c */
    /* is not nice. On the other hand, now there is no libzypp dependency. */
    char *sysconfdir = rpmExpand("%{?_sysconfdir}", NULL);
    if (!sysconfdir || !strcmp(sysconfdir, "")) {
	rpmlog(RPMLOG_ERR, "Failed to expand %%_sysconfdir macro\n");
	goto exit;
    }
    snprintf(path, sizeof(path), "%s/zypp", sysconfdir);
    if (stat(path, &sb) == -1) {
	rpmlog(RPMLOG_ERR, "Failed to stat %s: %s\n", 
	       path, strerror(errno));
	goto exit;
    }
    snprintf(path, sizeof(path), "%s/zypp/repos.d", sysconfdir);
    if (stat(path, &sb) == -1) {
	if (mkdir(path, 0755) == -1) {
	    rpmlog(RPMLOG_ERR, "Failed to create %s: %s\n", 
		   path, strerror(errno));
	    goto exit;
	}
    }
    snprintf(path, sizeof(path), "%s/zypp/repos.d/%s.repo", 
	     sysconfdir, sw_source->name);
    file = fopen(path, "w");
    if (!file) {
	rpmlog(RPMLOG_ERR, "Failed to open %s: %s\n", 
	       path, strerror(errno));
	goto exit;
    }
    snprintf(data, sizeof(data), 
	     "[%s]\n"
	     "name=%s\n"
	     "enabled=1\n"
	     "autorefresh=0\n"
	     "baseurl=%s\n"
	     "type=%s\n"
	     "keeppackages=0\n", 
	     sw_source->name, sw_source->name, access->data, 
	     (access->type ? access->type : "NONE"));

    if (fputs(data, file) == EOF) {
	rpmlog(RPMLOG_ERR, "Failed to write %s: %s\n", 
	       path, strerror(errno));
	goto exit;
    }
    rpmlog(RPMLOG_INFO, "added zypper repository %s for sw source %s\n", 
	   path, sw_source->name);

    ret = 0;
 exit:
    if (file) fclose(file);
    if (sysconfdir) free(sysconfdir);

    return ret;
}

static int msmSetSmackSWSource(struct smack_accesses *smack_accesses, sw_source_x *sw_source)
{
    package_x *package, *temp;
    provide_x *provide;

    if (!allpackages) return 0;

    if (sw_source->older) {
	ac_domain_x *ac_domain, *temp;
	/* remove old domain rules in case of upgrade */
	//smack_rule_set_remove_by_subject(rule_set, sw_source->name, NULL);
	/* make sure domain's credentials point to upgraded domain */
	HASH_ITER(hh, all_ac_domains, ac_domain, temp) {
	    if (ac_domain->sw_source == sw_source->older)
		ac_domain->sw_source = sw_source;
	}
    }

    /* iterate through all packages to create smack rules for the domain */
    HASH_ITER(hh, allpackages, package, temp) {
	if (sw_source->older) {
	    /* make sure domain's packages point to upgraded domain */
	    if (package->sw_source == sw_source->older)
		package->sw_source = sw_source;
	}
	if (!package->newer) {
	    for (provide = package->provides; provide; provide = provide->prev) {
		if (msmSetSmackProvide(smack_accesses, provide, package->sw_source))
		    return -1;
	    }
	}
    }
    return 0;
}

int msmSetupSWSources(struct smack_accesses *smack_accesses, manifest_x *mfx, rpmts ts) 
{
    sw_source_x *sw_source;
    origin_x *origin;
    keyinfo_x *keyinfo;
    access_x *access;
    ac_domain_x *allow;
    ac_domain_x *deny;
    ac_domain_x *ac_domain;
    int ret;
    rpmRC rc;

    LISTHEAD(mfx->sw_sources, sw_source);

    while (sw_source) {
	sw_source_x *next = sw_source->next;
	sw_source_x *parent = sw_source->parent;
	if (ts) {
	    for (origin = sw_source->origins; origin; origin = origin->prev) {
		for (keyinfo = origin->keyinfos; keyinfo; keyinfo = keyinfo->prev) {
		    rpmlog(RPMLOG_INFO, "setting keyinfo for sw source %s\n", 
			   sw_source->name);
		    rc = rpmtsImportPubkey(ts, keyinfo->keydata, keyinfo->keylen);
		    if (rc != RPMRC_OK) {
			rpmlog(RPMLOG_ERR, "Key import failed for sw source %s\n",
			       sw_source->name);
			return rc;
		    }
		}
		for (access = origin->accesses; access; access = access->prev) {
		    rpmlog(RPMLOG_INFO, "setting access %s for sw source %s\n", 
			   access->data, sw_source->name);
		    if (origin->type && !strcmp(origin->type, "ZYPPER")) {
			ret = msmSetupZypperRepo(access, sw_source);
			if (ret) {
			    rpmlog(RPMLOG_ERR, 
				   "Failed to set access %s for sw source %s\n",
				   access->data, sw_source->name);
			    return ret;
			}
		    }
		}
	    }
	} else {

	    /* config processing */
	    ret = msmSetupPackages(NULL, sw_source->packages, NULL);
	    if (ret) {
		rpmlog(RPMLOG_ERR, "Setup packages failed for sw source %s\n",
		       sw_source->name);
		return ret;
	    }
	}
	if (ts) {
	    for (allow = sw_source->allows; allow; allow = allow->hh.next) {
		HASH_FIND(hh, all_ac_domains, allow->name, strlen(allow->name), ac_domain);
		if (ac_domain) {
		    rpmlog(RPMLOG_INFO, "sw source %s allows access to ac domain %s\n", 
			   sw_source->name, allow->name);
		} else {
		    rpmlog(RPMLOG_WARNING, "sw source %s allows access to ac domain %s which doesn't exist\n", 
			   sw_source->name, allow->name);
		}
	    }
	    for (allow = sw_source->allowmatches; allow; allow = allow->prev)
		rpmlog(RPMLOG_INFO, "sw source %s allows access to ac domain match %s\n", 
		       sw_source->name, allow->match);

	    for (deny = sw_source->denys; deny; deny = deny->hh.next) {
		HASH_FIND(hh, all_ac_domains, deny->name, strlen(deny->name), ac_domain);
		if (ac_domain) {
		    rpmlog(RPMLOG_INFO, "sw source %s denies access to ac domain %s\n", 
			   sw_source->name, deny->name);
		} else {
		    rpmlog(RPMLOG_WARNING, "sw source %s denies access to ac domain %s which doesn't exist\n", 
			   sw_source->name, deny->name);
		}
	    }
	    for (deny = sw_source->denymatches; deny; deny = deny->prev)
		rpmlog(RPMLOG_INFO, "sw source %s denies access to ac domain match %s\n", 
		       sw_source->name, deny->match);

	    if (parent) {
		if (strcmp(parent->name, sw_source->name)) {
		    sw_source_x *older;
		    for (older = parent; older; older = older->next) {
			if (!strcmp(sw_source->name, older->name)) {
			    sw_source->older = older;
			    older->newer = sw_source;
			    break;
			}
		    }
		} else if (!parent->parent) {
		    /* root sw_source upgrade */
		    sw_source->older = parent;
		    parent->newer = sw_source;
		    sw_source->parent = NULL;
		} else return -1;

		LISTDEL(mfx->sw_sources, sw_source); /* take out from sw sources list */
		NODEADD(parent, sw_source); /* add to sw source tree */
	    }

	    /* set smack rules for the new/upgraded sw source */
	    ret = msmSetSmackSWSource(smack_accesses, sw_source);
	    if (ret) {
		rpmlog(RPMLOG_ERR, "Setting smack rules failed for sw source %s\n",
		       sw_source->name);
		return ret;
	    }

	}
	sw_source = next;
    }
    return 0;
}


static void msmRemoveDBusConfig(package_x *package, dbus_x *dbuss)
{
    dbus_x *dbus;

    for (dbus = dbuss; dbus; dbus = dbus->prev) {
	char path[NAME_MAX+1];
	snprintf(path, sizeof(path), "/etc/dbus-1/%s.d/manifest.%s.conf", 
		 dbus->bus, package->name);
	unlink(path);
    }
}

static int msmSetupDBusRule(FILE *file, const char *creds, int type, const char *service, const char *name, const char *parentType, const char *parentValue)
{
    char data[1024];

    if (creds && *creds) {
	switch (type) {
	case DBUS_SERVICE:
	    snprintf(data, sizeof(data), 
		     "  <policy context=\"default\">\n"
		     "    <deny send_destination=\"%s\"/>\n"
		     "  </policy>\n"
		     "  <policy smack=\"%s\">\n"
		     "    <allow send_destination=\"%s\"/>\n"
		     "  </policy>\n",
		     name, creds, name);
	    break;
	case DBUS_PATH:
	    snprintf(data, sizeof(data), 
		     "  <policy context=\"default\">\n"
		     "    <deny send_destination=\"%s\" send_path=\"%s\"/>\n"
		     "    <deny receive_sender=\"%s\" receive_path=\"%s\"/>\n"
		     "  </policy>\n"
		     "  <policy smack=\"%s\">\n"
		     "    <allow send_destination=\"%s\" send_path=\"%s\"/>\n"
		     "    <allow receive_sender=\"%s\" receive_path=\"%s\"/>\n"
		     "  </policy>\n",
		     service, name, service, name, creds,
		     service, name, service, name);
	    break;
	case DBUS_INTERFACE:
	    snprintf(data, sizeof(data), 
		     "  <policy context=\"default\">\n"
		     "    <deny send_destination=\"%s\" send_interface=\"%s\"/>\n"
		     "    <deny receive_sender=\"%s\" receive_interface=\"%s\"/>\n"
		     "  </policy>\n"
		     "  <policy smack=\"%s\">\n"
		     "    <allow send_destination=\"%s\" send_interface=\"%s\"/>\n"
		     "    <allow receive_sender=\"%s\" receive_interface=\"%s\"/>\n"
		     "  </policy>\n",
		     service, name, service, name, creds,
		     service, name, service, name);
	    break;
	case DBUS_METHOD:
	    snprintf(data, sizeof(data), 
		     "  <policy context=\"default\">\n"
		     "    <deny send_destination=\"%s\" send_%s=\"%s\" send_member=\"%s\"/>\n"
		     "  </policy>\n"
		     "  <policy smack=\"%s\">\n"
		     "    <allow send_destination=\"%s\" send_%s=\"%s\" send_member=\"%s\"/>\n"
		     "  </policy>\n",
		     service, parentType, parentValue, name, creds,
		     service, parentType, parentValue, name);
	    break;
	case DBUS_SIGNAL:
	    snprintf(data, sizeof(data), 
		     "  <policy context=\"default\">\n"
		     "    <deny receive_sender=\"%s\" receive_%s=\"%s\" receive_member=\"%s\"/>\n"
		     "  </policy>\n"
		     "  <policy smack=\"%s\">\n"
		     "    <allow receive_sender=\"%s\" receive_%s=\"%s\" receive_member=\"%s\"/>\n"
		     "  </policy>\n",
		     service, parentType, parentValue, name, creds,
		     service, parentType, parentValue, name);
	    break;
	default:
	    return -1;
	}
    } else {
	switch (type) {
	case DBUS_SERVICE:
	    snprintf(data, sizeof(data), 
		     "  <policy context=\"default\">\n"
		     "    <allow send_destination=\"%s\"/>\n"
		     "  </policy>\n",
		     name);
	    break;
	case DBUS_PATH:
	    snprintf(data, sizeof(data), 
		     "  <policy context=\"default\">\n"
		     "    <allow send_destination=\"%s\" send_path=\"%s\"/>\n"
		     "    <allow receive_sender=\"%s\" receive_path=\"%s\"/>\n"
		     "  </policy>\n",
		     service, name, service, name);
	    break;
	case DBUS_INTERFACE:
	    snprintf(data, sizeof(data), 
		     "  <policy context=\"default\">\n"
		     "    <allow send_destination=\"%s\" send_interface=\"%s\"/>\n"
		     "    <allow receive_sender=\"%s\" receive_interface=\"%s\"/>\n"
		     "  </policy>\n",
		     service, name, service, name);
	    break;
	case DBUS_METHOD:
	    snprintf(data, sizeof(data), 
		     "  <policy context=\"default\">\n"
		     "    <allow send_destination=\"%s\" send_%s=\"%s\" send_member=\"%s\"/>\n"
		     "  </policy>\n",
		     service, parentType, parentValue, name);
	    break;
	case DBUS_SIGNAL:
	    snprintf(data, sizeof(data), 
		     "  <policy context=\"default\">\n"
		     "    <allow receive_sender=\"%s\" receive_%s=\"%s\" receive_member=\"%s\"/>\n"
		     "  </policy>\n",
		     service, parentType, parentValue, name);
	    break;
	default:
	    return -1;
	}
    }
    if (fputs(data, file) == EOF) {
	rpmlog(RPMLOG_ERR, "Failed to write DBus rule %s: %s\n", 
	       data, strerror(errno));
	return -1;
    }
    return 0;
}


static int msmSetupDBusConfig(package_x *package, dbus_x *dbus, int phase)
{
    char path[NAME_MAX+1];
    FILE *file = NULL;
    char data[512];
    node_x *node;
    interface_x *interface;
    member_x *member;
    int ret = -1;

    char *sysconfdir = rpmExpand("%{?_sysconfdir}", NULL);
    if (!sysconfdir || !strcmp(sysconfdir, "")) {
	rpmlog(RPMLOG_ERR, "Failed to expand %%_sysconfdir macro\n");
	goto exit;
    }
    snprintf(path, sizeof(path), "%s/dbus-1/%s.d/manifest.%s.conf", 
	     sysconfdir, dbus->bus, package->name);

    file = fopen(path, phase ? "a" : "w");
    if (!file) {
	rpmlog(RPMLOG_ERR, "Cannot open %s: %s\n", path, strerror(errno));
	goto exit;
    }

    if (phase == 0) {
	snprintf(data, sizeof(data), 
		 "<!-- This configuration is automatically generated from Manifest by RPM %s security plugin -->\n"
		 "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n"
		 "<busconfig>\n",
		 rpmEVR);
	if (fputs(data, file) == EOF) {
	    rpmlog(RPMLOG_ERR, "Failed to write %s: %s\n", 
		   path, strerror(errno));
	    goto exit;
	}
    }

    if (phase >= 0) {
	if (dbus->own) {
		snprintf(data, sizeof(data), 
			 "  <policy context=\"default\">\n"
			 "    <deny own=\"%s\"/>\n"
			 "  </policy>\n"
			 "  <policy smack=\"%s\">\n"
			 "    <allow own=\"%s\"/>\n"
			 "  </policy>\n",
			 dbus->name, dbus->own, dbus->name);
		if (fputs(data, file) == EOF) {
		    rpmlog(RPMLOG_ERR, "Failed to write %s: %s\n", 
			   path, strerror(errno));
		    goto exit;
		}
	}
	if (dbus->annotation) {
		msmSetupDBusRule(file, dbus->annotation->value, DBUS_SERVICE, 
				  NULL, dbus->name, NULL, NULL);
	}
	for (node = dbus->nodes; node; node = node->prev) {
	    if (node->annotation) {
		    msmSetupDBusRule(file, node->annotation->value, DBUS_PATH,
				      dbus->name, node->name, NULL, NULL);
	    }
	    for (member = node->members; member; member = member->prev) {
		if (member->annotation) {
			msmSetupDBusRule(file, member->annotation->value, member->type, 
					  dbus->name, member->name, 
					  "path", node->name);
		}
	    }
	    for (interface = node->interfaces; interface; interface = interface->prev) {
		if (interface->annotation) {
			msmSetupDBusRule(file, interface->annotation->value, DBUS_INTERFACE, 
					  dbus->name, interface->name, NULL, NULL);
		}
		for (member = interface->members; member; member = member->prev) {
		    if (member->annotation) {
			    msmSetupDBusRule(file, member->annotation->value, member->type, 
					      dbus->name, member->name,
					      "interface", interface->name);
		    }
		}
	    }
	}
    }

    if (phase < 0) {
	snprintf(data, sizeof(data), "</busconfig>\n");
	if (fputs(data, file) == EOF) {
	    rpmlog(RPMLOG_ERR, "Failed to write %s: %s\n", 
		   path, strerror(errno));
	    goto exit;
	}
	rpmlog(RPMLOG_INFO, "wrote dbus config %s\n", path);	
    }
    ret = 0;

 exit:
    if (file) fclose(file);
    if (ret) unlink(path);
    if (sysconfdir) free(sysconfdir);

    return ret;
}

static int msmIsRequestAllowed(manifest_x *mfx, ac_domain_x *provided)
{
  
    if (mfx->sw_source == provided->sw_source) {
	/* allowed always if ac domain is provided in the same sw source */
	return 1;
    } else if (provided->origin && !strcmp(provided->origin, "current")) {
	/* denied if ac domain is only meant for current sw source */
	return 0;
    }
    if (provided->origin && !strcmp(provided->origin, "all")) {
	/* ac_domain is allowed for all sw sources */
	return 1;
    }
    if (!provided->origin || !strcmp(provided->origin, "trusted")) {
	if (strcmp(mfx->sw_source->rankkey, provided->sw_source->rankkey) < 0) {
	    /* higher ranked sw sources are allowed if ac domain is trusted */
	    return 1;
	} /* else flow through to check denys and allows below */
    } else return 0;

    return msmCheckACDomainRules(provided, mfx->sw_source, provided->sw_source);


}

int msmSetupRequests(manifest_x *mfx){

  	ac_domain_x *defined_ac_domain = NULL; 

	if (!mfx->request) 
		return 0;

	if (!mfx->request->ac_domain) 
		return 0;
	
	HASH_FIND(hh, all_ac_domains, mfx->request->ac_domain, strlen(mfx->request->ac_domain), defined_ac_domain);
	if (!defined_ac_domain){ // request for a undefined domain. 
		rpmlog(RPMLOG_ERR, "Request for a domain name %s that hasn't been yet defined by any package\n", mfx->request->ac_domain);
		return -1;
	}

	//now check that this ac_domain can be requested

        if (mfx->define){
		rpmlog(RPMLOG_DEBUG, "mfx->define->name %s mfx->request->ac_domain %s\n", mfx->define->name, mfx->request->ac_domain);
		if (strcmp(mfx->define->name, mfx->request->ac_domain) == 0)
			//ac domain is requested from the same package where it was define. this case is always allowed
			return 0;		
	} 
	//need to check if developer allowed other packages to request this domain
	if (defined_ac_domain->type) {
		if (strcmp(defined_ac_domain->type, "restricted") == 0) {
			if (defined_ac_domain->plist){
				unsigned int found = 0;
				char *tmp = calloc(strlen(defined_ac_domain->plist) + 1, sizeof(char));
				if (tmp) {
					strncpy(tmp, defined_ac_domain->plist, strlen(defined_ac_domain->plist));
					char *pch = strtok (tmp,", ");
					while (pch != NULL)
					  {
					    if (strcmp(pch,mfx->name) == 0) {
						found = 1; 
						break;
					    }					
					    pch = strtok(NULL, ", ");
					  }
					free(tmp);
				}
				if (found != 1) {
					rpmlog(RPMLOG_ERR, "Request for a domain name %s isn't allowed because ac domain is restricted\n", mfx->request->ac_domain);
					return -1;
				}
			} else {
				rpmlog(RPMLOG_ERR, "Request for a domain name %s isn't allowed because ac domain is restricted\n", mfx->request->ac_domain);
				return -1;
			}
		} else if (strcmp(defined_ac_domain->type, "shared") != 0) {
			// domain hasn't been marked as shared 
			rpmlog(RPMLOG_ERR, "Request for a domain name %s isn't allowed because ac domain is marked as private\n", mfx->request->ac_domain);
			return -1;
			
		}
	} else { 
		// by default ac domains are private
		rpmlog(RPMLOG_ERR, "Request for a domain name %s isn't allowed because ac domain is marked as private\n", mfx->request->ac_domain);
		return -1;
	}
	
	if (msmIsRequestAllowed(mfx, defined_ac_domain)) {
		// request is allowed by domain policy
	    rpmlog(RPMLOG_INFO, "Request for a domain name %s is allowed based on package sw source\n", mfx->request->ac_domain);
	    return 0;
		
	} else {
	    rpmlog(RPMLOG_ERR, "Request for a domain name %s isn't allowed based on package sw source\n", mfx->request->ac_domain);
	    return -1;
	}
}



static int msmSetupProvides(struct smack_accesses *smack_accesses, package_x *package)
{
    provide_x *provide;
    ac_domain_x *ac_domain;
	    
    for (provide = package->provides; provide; provide = provide->prev) {
	for (ac_domain = provide->ac_domains; ac_domain; ac_domain = ac_domain->prev) {
	    ac_domain_x *current;
	    ac_domain->origin = provide->origin;
	    HASH_FIND(hh, all_ac_domains, ac_domain->name, strlen(ac_domain->name), current);
	    if (current) { /* ac domain has been previously defined */
		if (strcmp(ac_domain->pkg_name, current->pkg_name) == 0) { /* check that it was provided by the same package */		
			HASH_DELETE(hh, all_ac_domains, current);
			HASH_ADD_KEYPTR(hh, all_ac_domains, ac_domain->name, strlen(ac_domain->name), ac_domain);
			current->newer = ac_domain;
			ac_domain->older = current;
			rpmlog(RPMLOG_INFO, "package %s upgraded ac domain %s\n", ac_domain->pkg_name, ac_domain->name);
		  
		} else {
		    rpmlog(RPMLOG_ERR, "package %s can't upgrade ac domain %s previously defined in package %s\n", 
									ac_domain->pkg_name, ac_domain->name, current->pkg_name);
		    return -1;
		}
	    } else {
		HASH_ADD_KEYPTR(hh, all_ac_domains, ac_domain->name, strlen(ac_domain->name), ac_domain);
		rpmlog(RPMLOG_INFO, "package %s defined ac domain %s\n", ac_domain->pkg_name, ac_domain->name);		
	    }
	}

	int ret = msmSetSmackProvide(smack_accesses, provide, package->sw_source);
	if (ret < 0) {
		rpmlog(RPMLOG_ERR, "Failed to set smack rules for provide\n");
		return -1;
	}

    }
    return 0;
}

int msmSetupDBusPolicies(package_x *package) {

	dbus_x *session = NULL;
	dbus_x *system = NULL;
    	provide_x *provide;
    	dbus_x *dbus;

    	for (provide = package->provides; provide; provide = provide->prev) {
		for (dbus = provide->dbuss; dbus; dbus = dbus->prev) {
			if (!strcmp(dbus->bus, "session")) {
			    msmSetupDBusConfig(package, dbus, session ? 1 : 0);
			    session = dbus;
			} else if (!strcmp(dbus->bus, "system")) {
			    msmSetupDBusConfig(package, dbus, system ? 1 : 0);
			    system = dbus;
			} else return -1;
		}
		if (session) msmSetupDBusConfig(package, session, -1);
		if (system) msmSetupDBusConfig(package, system, -1);
     	}

	return 0;

}


static int msmCheckDomainRequest(manifest_x *mfx, char* requested){

  	ac_domain_x *defined_ac_domain = NULL; 

	if (!mfx) 
		return -1;

	if (!requested) 
		return -1;
	
	HASH_FIND(hh, all_ac_domains, requested, strlen(requested), defined_ac_domain);
	if (!defined_ac_domain){ // request for a undefined domain. 
		rpmlog(RPMLOG_ERR, "A domain name %s that hasn't been yet defined by any package. Can't verify if request is allowed\n", requested);
		return -1;
	}

	//now check that this ac_domain can be requested

        if (mfx->define){
		rpmlog(RPMLOG_DEBUG, "mfx->sw_source->name %s requested %s\n", mfx->sw_source->name, requested);
		if (strcmp(mfx->sw_source->name, requested) == 0)
			//ac domain access is requested from the same package where it was define. this case is always allowed
			return 0;		
	} 
	// no need to check if developer allowed other packages to request this domain, because this isn't a request to belong to a domain, but request to domain access
	
	if (msmIsRequestAllowed(mfx, defined_ac_domain)) {
		// request is allowed by domain policy
	    rpmlog(RPMLOG_DEBUG, "Request to access a domain name %s is allowed based on package sw source\n", requested);
	    return 0;
		
	} else {
	    rpmlog(RPMLOG_ERR, "Request to access a domain name %s isn't allowed based on package sw source\n", requested);
	    return -1;
	}
}


int msmSetupDefine(struct smack_accesses *smack_accesses, manifest_x *mfx)
{
    d_request_x *d_request;
    d_permit_x *d_permit;
    ac_domain_x * defined_ac_domain = NULL;
    int ret;

    /* need to check if domain hasn't been already defined by other package */

    HASH_FIND(hh, all_ac_domains, mfx->define->name, strlen(mfx->define->name), defined_ac_domain);
    if ((defined_ac_domain) && (defined_ac_domain->pkg_name)) { // this domain has been previously defined
		if (strcmp(defined_ac_domain->pkg_name, mfx->name) != 0) {
			rpmlog(RPMLOG_ERR, "Attempt to define a domain name %s that has been already defined by package %s\n",
											 mfx->define->name, defined_ac_domain->pkg_name);
			return -1;
		}

    }

    if (mfx->define->d_requests) {
	    for (d_request = mfx->define->d_requests; d_request; d_request = d_request->prev) {

			// first check if the current's package sw source can grant access to requested domain
			char* name = calloc(strlen(d_request->label_name) + 1, sizeof(char));
			if (!name) return -1;
			strncpy(name, d_request->label_name, strlen(d_request->label_name));
			strtok(name, ":");// remove label name if present
			rpmlog(RPMLOG_DEBUG, "label name %s domain name %s \n", d_request->label_name, name);
                        ret = msmCheckDomainRequest(mfx, name);
			free(name);
			if (ret < 0) {
				return -1;
			}
			ret = smack_accesses_add(smack_accesses, mfx->define->name, d_request->label_name, d_request->ac_type);
			if (ret < 0) {
				rpmlog(RPMLOG_ERR, "Failed to set smack rules for domain requests\n");
				return -1;
			}	
	
	    }
    }

    if (mfx->define->d_permits) {
	    for (d_permit = mfx->define->d_permits; d_permit; d_permit = d_permit->prev) {
			ret = smack_accesses_add(smack_accesses, d_permit->label_name, mfx->define->name, d_permit->ac_type);
			if (ret < 0) {
				rpmlog(RPMLOG_ERR, "Failed to set smack rules for domain permits\n");
				return -1;
			}	
	
	    }
    }

 
    return 0;
}


package_x *msmCreatePackage(const char *name, sw_source_x *sw_source, provide_x *provides, const char *modified)
{
    if (!name) return NULL;

    package_x *package = calloc(1, sizeof(package_x));
    if (package) {
	package->name = strdup(name);
	if (!package->name) goto exit;
	package->sw_source = sw_source;
	package->provides = provides;
	if (modified) {
	    package->modified = strdup(modified);
	    if (!package->modified) goto exit;
	}
    }
    return package;

 exit:
    if (package->name) free((void *)package->name);
    if (package->modified) free((void *)package->modified);
    free(package);

    return NULL;
}

int msmSetupSmackRules(struct smack_accesses *smack_accesses, const char* package_name, int flag){

    int ret, res;
    char * buffer = calloc(strlen(SMACK_RULES_PATH) + strlen(package_name) + 1, sizeof(char));
    if (!buffer) return -1;    
    strncpy(buffer, SMACK_RULES_PATH, strlen(SMACK_RULES_PATH));
    strncpy(buffer + strlen(SMACK_RULES_PATH), package_name, strlen(package_name));
    rpmlog(RPMLOG_DEBUG, "smack rule file path %s\n", buffer);


    if (flag == SMACK_UNINSTALL) { /* uninstallation case */
	FILE* fd = fopen(buffer, "r");
    	if (!fd) return -1;
	struct smack_accesses *old_rule_set = NULL;
	res = smack_accesses_new(&old_rule_set);
	if (res != 0) return -1;
	res = smack_accesses_add_from_file(old_rule_set, fileno(fd));
	if (!res != 0) return -1;
	fclose(fd);
	remove(buffer); /* delete rules file from system */
	ret = smack_accesses_clear(old_rule_set); /* deletes rules from kernel */
	smack_accesses_free(old_rule_set);
    	rpmlog(RPMLOG_DEBUG, "ret in uninstallation %d\n", ret);
    } else { /*installation case */
        /* first attempt to clean previous version of rules, if exists */
	FILE* fd = fopen(buffer, "r");
    	if (fd) {
		struct smack_accesses *old_rule_set = NULL;
		res = smack_accesses_new(&old_rule_set);
		if (res != 0) return -1;
		res = smack_accesses_add_from_file(old_rule_set, fileno(fd));
		if (!res != 0) return -1;
		fclose(fd);
		ret = smack_accesses_clear(old_rule_set); /* deletes old rules from kernel */
		smack_accesses_free(old_rule_set);
	} 
        /* now write new rules to the system */
	fd = fopen(buffer, "w");
    	if (!fd) return -1;
    	ret = smack_accesses_save(smack_accesses, fileno(fd));
    	rpmlog(RPMLOG_DEBUG, "ret in installation %d\n", ret);
	if (!ret) ret = smack_accesses_apply(smack_accesses);
    	fclose(fd);
    }
    
    free (buffer);
    if (ret) return -1;
    return 0;	

}

int msmSetupPackages(struct smack_accesses *smack_accesses, package_x *packages, sw_source_x *sw_source)
{
    package_x *package, *first = NULL;

    for (package = packages; package; package = package->prev) {
	package_x *current;
	HASH_FIND(hh, allpackages, package->name, strlen(package->name), current);
	if (current) {
	    /* this is an upgrade, remove old one from config */
	    if (strcmp(package->sw_source->rankkey, current->sw_source->rankkey) <= 0) {
		HASH_DELETE(hh, allpackages, current);
		rpmlog(RPMLOG_INFO, "sw source %s upgraded package %s previously provided in sw source %s\n", 
								package->sw_source->name, package->name, current->sw_source->name);
		current->newer = package;
		package->older = current;
	    } else {
		/* upgrade from lower ranked sw source is not allowed */ 
		rpmlog(RPMLOG_ERR, "sw source %s tried to upgrade package %s previously provided in sw source %s\n", 
								package->sw_source->name, package->name, current->sw_source->name);
		return -1;
	    }
	} else {
	    if (sw_source) {
	    rpmlog(RPMLOG_INFO, "sw source %s provided package %s\n", package->sw_source->name, package->name);
	    }
	}

	HASH_ADD_KEYPTR(hh, allpackages, package->name, strlen(package->name), package);   
	/* set sw source smack rules*/
	if ((msmSetupProvides(smack_accesses, package)) < 0 )
		return -1;
	first = package;
    }

    if (sw_source && packages) {
	/* catenate list to sw_source config */
	LISTCAT(sw_source->packages, first, packages);
    }
    return 0;
}


package_x *msmCheckPackage(const char *name)
{
    package_x *package = NULL;

    if (name)
	HASH_FIND(hh, allpackages, name, strlen(name), package);

    return package;
}

void msmCancelPackage(const char *name)
{
    if (name) {
	package_x *package;
	HASH_FIND(hh, allpackages, name, strlen(name), package);
	if (package) {
	    HASH_DELETE(hh, allpackages, package);
	    if (package->older) {
		/* resume previous version */
		HASH_ADD_KEYPTR(hh, allpackages, package->older->name, strlen(package->older->name), package->older);
		package->older->older = package->older->newer;
		package->older->newer = NULL;
		package->newer = package->older;
		package->older = NULL;
	    } else {
		/* no previous, just take this one out */
		package->newer = package;
	    }
	}
    }
}

static int is_executable(const char* path) {

 char buffer[1024];
 int result;
 char string[] = "file ";
 char* ptr = NULL, *ptr1 = NULL;
 FILE* pipe;

 if (!path)
	return -1;

 char* str = calloc(strlen(path) + 6, sizeof (char*));
 strncpy(str, string, 5);
 strncpy(str + 5, path, strlen(path));

 pipe = popen(str, "r");
 if (!pipe) {
   free(str);
   return -1;
 }

 result = -1; 

 if(fgets(buffer, 1023, pipe) != NULL) {
	ptr = strchr(buffer,':');
	if (ptr!= NULL) { 
		ptr1 = strstr(ptr,"executable");
		if (ptr1) result = 0;		
	}
 }
 free(str);
 pclose(pipe);
 return result;
}


int msmSetFilesystemLabels(manifest_x *mfx) {
    file_x *file;
    provide_x *provide;
    filesystem_x *filesystem;
    int fd, ret = 0;
    size_t len;
    const char *label = NULL;
    const char *exec_label = NULL;
    const char *type = NULL;
    int match = 0;
    char aid[256];
    struct stat st;

    for (file = mfx->files; file; file = file->prev) {
	if (mfx->name) {
		package_x *package = msmCheckPackage(mfx->name);
		if (!package)
			return -1;
		for (provide = package->provides; provide; provide = provide->prev) {
		    for (filesystem = provide->filesystems; filesystem; filesystem = filesystem->prev) {
			if (!strcmp(file->path, filesystem->path)) {
			    /* exact match */
			    label = filesystem->label;
			    exec_label = filesystem->exec_label;
			    if (filesystem->type) type = filesystem->type;
			    goto found;
			}
			len = strlen(filesystem->path);
			if (len > match) {
			    if (!strncmp(file->path, filesystem->path, len)) {
				/* partial match */
				label = filesystem->label;
			    	exec_label = filesystem->exec_label;
				match = len;
			    }
			}
		    }
		}
	} else 
		return -1;
	
    found:

	if (!label) {
	    /* no match, use default label of AC domain */
	    if (mfx->request) { //AC domain is requested in manifest
		if (mfx->request->ac_domain)
			label = mfx->request->ac_domain;
		else {
			rpmlog(RPMLOG_ERR, "Request for AC domain is empty. Can't identify default file label\n");
			return -1;
		}
	     } else if (mfx->define) { // AC domain defined in manifest
		if (mfx->define->name)
			label = mfx->define->name;
		else {
			rpmlog(RPMLOG_ERR, "Define for AC domain is empty. Can't identify default file label\n");
			return -1;
		}		 
	     } else { // no request or definition of domain, return an error
			rpmlog(RPMLOG_ERR, "Both request and define for AC domain are empty. Can't identify default file label\n");
			return -1;
	     }
	} 
         

	fd = open(file->path, O_RDONLY);
	if (fd == -1) {
	    rpmlog(RPMLOG_ERR, "Failed to open %s: %s\n", 
		   file->path, strerror(errno));
	    continue;
	}
	ret = fstat(fd, &st);
	if (ret == -1) {
	    rpmlog(RPMLOG_ERR, "fstat failed for %s: %s\n", 
		   file->path, strerror(errno));
	    goto next;
	}
	if (file->ino && (st.st_ino != file->ino)) {
	    rpmlog(RPMLOG_ERR, "Inode check failed for %s\n", file->path);
	    goto next;
	}	    

	rpmlog(RPMLOG_INFO, "setting SMACK64 %s for %s\n", label, file->path);
	ret = fsetxattr(fd, SMACK64, label, strlen(label), 0);
	if (ret < 0) {
	    rpmlog(RPMLOG_ERR, "Failed to set SMACK64 %s for %s: %s\n", 
		   aid, file->path, strerror(errno));
	}


	if ((is_executable(file->path)) == 0) {
		if ((exec_label) && (strcmp(exec_label, "none") == 0)) {
			// do not set SMACK64EXEC
			rpmlog(RPMLOG_INFO, "not setting SMACK64EXEC for %s as requested in manifest\n", file->path);
		} else {
			rpmlog(RPMLOG_INFO, "setting SMACK64EXEC %s for %s\n", mfx->request->ac_domain, file->path);
			ret = fsetxattr(fd, SMACK64EXEC, mfx->request->ac_domain, strlen(mfx->request->ac_domain), 0);
			if (ret < 0) {
		    		rpmlog(RPMLOG_ERR, "Failed to set SMACK64EXEC %s for %s: %s\n", 
			   aid, file->path, strerror(errno));
			}
		}
	}


	if (type) { //marked as transmutable
		if (S_ISDIR(st.st_mode)) { //check that it is a directory
			char at_true[]="TRUE";
			rpmlog(RPMLOG_INFO, "setting SMACK64TRANSMUTE %s for %s\n", at_true, file->path);
			ret = fsetxattr(fd, SMACK64TRANSMUTE, at_true, strlen(at_true), 0);
			if (ret < 0) {
			    rpmlog(RPMLOG_ERR, "Failed to set SMACK64TRANSMUTE %s for %s: %s\n", 
				   at_true, file->path, strerror(errno));
			}
		} else {
			rpmlog(RPMLOG_INFO, "An attempt to setup a transmute attr for a non-directory, path %s\n", 
				   file->path);
		}
	
	}

    next:
	close(fd);
	label = NULL;
    }
    return 0;
}

#if 0

static void msmRemoveObjectRules(SmackRuleSet rule_set, const char *name, package_x *package )
{
    if (package) {
	provide_x *provide;
	ac_domain_x *ac_domain;
	for (provide = package->provides; provide; provide = provide->prev) {
	    for (ac_domain = provide->ac_domains; ac_domain; ac_domain = ac_domain->prev) {
		if (!strcmp(name, ac_domain->name)) {
		    name = NULL; /* don't remove this one, it's in upgrade */
		    goto out;
		}
	    }
	}
    }
 out:
    if (name) {
	rpmlog(RPMLOG_INFO, "removing smack object rules for %s\n", name);
	smack_rule_set_remove_by_object(rule_set, name, NULL);
    }
}
#endif

void msmRemoveRules(struct smack_accesses *smack_accesses, manifest_x *mfx)
{

    provide_x *provide;
    package_x *package;

    HASH_FIND(hh, allpackages, mfx->name, strlen(mfx->name), package);
    if (!package)
	return;

    if ((mfx->define) || (mfx->sw_sources)) {
	    /* remove smack rule file and rule set from kernel */
	rpmlog(RPMLOG_DEBUG, "removing smack rules for %s\n", mfx->name);
	    msmSetupSmackRules(smack_accesses, mfx->name, SMACK_UNINSTALL);
    }

    for (provide = mfx->provides; provide; provide = provide->prev) {
	if (provide->dbuss && !package->older) 
	    msmRemoveDBusConfig(package, provide->dbuss);

    }

}


void msmRemoveConfig(manifest_x *mfx)
{
    package_x *package;

    HASH_FIND(hh, allpackages, mfx->name, strlen(mfx->name), package);
    if (package) {
	if (!package->older) {
	    /* set newer to remove from config list */
	    package->newer = package;
	    rpmlog(RPMLOG_INFO, "removing package for %s\n", mfx->name);
	}
    }
}

sw_source_x *msmSWSourceTreeTraversal(sw_source_x *sw_sources, int (func)(sw_source_x *, void *), void *param)
{
    sw_source_x *sw_source;

    if (sw_sources) {
	LISTHEAD(sw_sources, sw_source);
	/* sw source tree is actually a list ordered into tree traversal path */
	for (; sw_source; sw_source = sw_source->next)
	    if (!sw_source->newer)
		if (!(func)(sw_source, param)) return sw_source;
    }
    return NULL;
}

