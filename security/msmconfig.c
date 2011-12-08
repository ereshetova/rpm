/*
 * This file is part of MSM security plugin
 * Greatly based on the code of MSSF security plugin
 *
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
 *
 * Contact: Ilhan Gurel <ilhan.gurel@nokia.com>
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

#include <libxml/tree.h>

#include "rpmio/base64.h"

#include "msm.h"

typedef enum credType_e {
    CRED_ALLOWMATCHES  = 0,
    CRED_ALLOW         = 1,
    CRED_DENYMATCHES   = 2,
    CRED_DENY          = 3,
    CRED_PROVIDE       = 4
} credType;

/**
 * Serializes key data
 * @todo Problem with getting keydata
 * @param parent	XML node
 * @param keyinfo	keyinfo structure
 * @return		none
 */
static void msmHandleKeyinfo(xmlNode *parent, keyinfo_x *keyinfo)
{    
    char *enc = NULL;

    if (!parent)
        return;
    
    while (keyinfo) {
        xmlNode *node = xmlNewNode(NULL, BAD_CAST "keyinfo");

        /* b64 encode keydata first */    
        if ((enc = b64encode(keyinfo->keydata, keyinfo->keylen, -1)) != NULL) {
            xmlAddChild(node, xmlNewText(BAD_CAST "\n"));        
            xmlAddChild(node, xmlNewText(BAD_CAST enc));
            _free(enc);   
        }

        xmlAddChild(parent, node);
        keyinfo = keyinfo->prev;
    }
}

/**
 * Serializes ac_domain data
 * @param parent	XML node
 * @param type	    Type (allow, deny,..)
 * @param ac_domain	ac_domain structure
 * @return		    none
 */
static void msmHandleACDomains(xmlNode *parent, credType type, 
				  ac_domain_x *ac_domain)
{
    if (!ac_domain || !parent)
        return;

    xmlNode *node = NULL;

    if ((type == CRED_ALLOWMATCHES) || (type == CRED_ALLOW)) {
        node = xmlNewNode(NULL, BAD_CAST "allow");    
    } else if ((type == CRED_DENYMATCHES) || (type == CRED_DENY)) {
        node = xmlNewNode(NULL, BAD_CAST "deny"); 
    } else if (type == CRED_PROVIDE) {
	node = parent;
    } else {
        return;    
    }

    while (ac_domain) {
        xmlNode *childnode = xmlNewNode(NULL, BAD_CAST "ac_domain");
        if ((type == CRED_ALLOWMATCHES) || (type == CRED_DENYMATCHES)) {
            xmlNewProp(childnode, BAD_CAST "match", BAD_CAST ac_domain->match);
        } else {
            xmlNewProp(childnode, BAD_CAST "name", BAD_CAST ac_domain->name);
	    if (ac_domain->type)
		xmlNewProp(childnode, BAD_CAST "policy", BAD_CAST ac_domain->type);
	    if (ac_domain->plist)
		xmlNewProp(childnode, BAD_CAST "plist", BAD_CAST ac_domain->plist);
        }
        xmlAddChild(node, childnode);
	if (type == CRED_ALLOW || type == CRED_DENY)
	    ac_domain = ac_domain->hh.next;
	else
	    ac_domain = ac_domain->prev;
    }

    if (type != CRED_PROVIDE)
	    xmlAddChild(parent, node);
}

/**
 * Serializes origin data
 * @param parent	XML node
 * @param origin	origin structure
 * @return		    none
 */
static void msmHandleOrigin(xmlNode *parent, origin_x *origin)
{    
    if (!parent)
        return;
    
    while (origin) {
        xmlNode *node = xmlNewNode(NULL, BAD_CAST "origin");
        xmlAddChild(parent, node);
        msmHandleKeyinfo(node, origin->keyinfos);
        origin = origin->prev;
    }
}

/**
 * Serializes provides data
 * @param parent	XML node
 * @param provide	provide structure
 * @return		    none
 */
static void msmHandleProvide(xmlNode *parent, provide_x *provide)
{    
    if (!parent)
        return;     

    while (provide) {
	if (provide->ac_domains) {
		xmlNode *node = xmlNewNode(NULL, BAD_CAST "provide");
		xmlAddChild(parent, node);
		msmHandleACDomains(node, CRED_PROVIDE, provide->ac_domains);
		if (provide->origin) {
		    xmlNode *childnode = xmlNewNode(NULL, BAD_CAST "for");
		    xmlNewProp(childnode, BAD_CAST "origin", BAD_CAST provide->origin);
		    xmlAddChild(node, childnode);
		}
	}
        provide = provide->prev;
    }
}

/**
 * Serializes packages data
 * @param parent	XML node
 * @param package	package structure
 * @return		none
 */
static void msmHandlePackage(xmlNode *parent, package_x *package)
{    
    if (!parent)
        return; 

    while (package) {
	if (!package->newer) {
	    xmlNode *node = xmlNewNode(NULL, BAD_CAST "package");
	    xmlNewProp(node, BAD_CAST "name", BAD_CAST package->name);
	    if (package->modified) 
		xmlNewProp(node, BAD_CAST "modified", BAD_CAST package->modified);
	    xmlAddChild(parent, node);
	    msmHandleProvide(node, package->provides);
	}
	package = package->prev;
    }
}

/**
 * Serializes sw source data
 * @param parent	XML node
 * @param sw_source	sw_source structure
 * @return		    none
 */
static void msmHandleSWSource(xmlNode *parent, sw_source_x *sw_source)
{
    #define MAX_DEPTH 10
    xmlNode *node[MAX_DEPTH];
    sw_source_x *temp;
    int depth = 0;

    if (!sw_source || !parent)
        return;

    node[0] = parent;

    while (sw_source) {
	depth = 1; /* recalculate depth */
	for (temp = sw_source->parent; temp; temp = temp->parent) depth++;
	if (!sw_source->newer && depth < MAX_DEPTH) {
	    node[depth] = xmlNewNode(NULL, BAD_CAST "sw_source");
	    xmlNewProp(node[depth], BAD_CAST "name", BAD_CAST sw_source->name);
	    xmlNewProp(node[depth], BAD_CAST "rankkey", BAD_CAST sw_source->rankkey);
	    xmlAddChild(node[depth-1], node[depth]);
	    msmHandleOrigin(node[depth], sw_source->origins);
	    msmHandleACDomains(node[depth], CRED_ALLOWMATCHES, sw_source->allowmatches);
	    msmHandleACDomains(node[depth], CRED_ALLOW, sw_source->allows);
	    msmHandleACDomains(node[depth], CRED_DENYMATCHES, sw_source->denymatches);
	    msmHandleACDomains(node[depth], CRED_DENY, sw_source->denys);
	    msmHandlePackage(node[depth], sw_source->packages);
	    if (sw_source->older) {
		/* packages still belong to this sw_source */
		msmHandlePackage(node[depth], sw_source->older->packages);
	    }
	}
	sw_source = sw_source->next;
    }
}

/**
 * Saves sw_source configuration into /etc/dev-sec-policy.
 * @param mfx		data to serialize
 * @return		RPMRC_OK or RPMRC_FAIL
 */
rpmRC msmSaveDeviceSecPolicyXml(manifest_x *mfx)
{    
    FILE *outFile;
    rpmRC rc = RPMRC_OK;    

    /* if data doesn't have sw_source information, no need to do anything */    
    if (mfx && mfx->sw_sources) {    
	sw_source_x *sw_source;
	xmlDoc *doc = xmlNewDoc( BAD_CAST "1.0");
	xmlNode *rootnode = xmlNewNode(NULL, BAD_CAST "config");
	xmlDocSetRootElement(doc, rootnode);

	LISTHEAD(mfx->sw_sources, sw_source);	
        msmHandleSWSource(rootnode, sw_source);

        outFile = fopen(DEVICE_SECURITY_POLICY, "w");
        if (outFile) {
            xmlElemDump(outFile, doc, rootnode);
            fclose(outFile);
        } else {
            rpmlog(RPMLOG_ERR, "Unable to write device security policy%s\n", 
	           DEVICE_SECURITY_POLICY);
            rc = RPMRC_FAIL;
        }
        xmlFreeDoc(doc);
        xmlCleanupParser();
    }

    return rc;
}

