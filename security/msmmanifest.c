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
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libxml/xmlreader.h>
#include <sys/capability.h>

#include "msm.h"

#include "rpmio/base64.h"

/* We'll support only the basic set of characters */
#define ASCII(s) (const char *)s
#define XMLCHAR(s) (const xmlChar *)s

static int msmNextChildElement(xmlTextReaderPtr reader, int depth) {
    int ret = xmlTextReaderRead(reader);
    int cur = xmlTextReaderDepth(reader);
    while (ret == 1) {
	/*
	rpmlog(RPMLOG_DEBUG, "node %s %d\n", 
	       ASCII(xmlTextReaderConstName(reader)), 
	       xmlTextReaderDepth(reader));
	*/
	switch (xmlTextReaderNodeType(reader)) {
	case XML_READER_TYPE_ELEMENT:
	case XML_READER_TYPE_TEXT:
	    if (cur == depth+1) 
		return 1;
	    break;
	case XML_READER_TYPE_END_ELEMENT:
	    if (cur == depth) 
		return 0;
	    break;
	default:
	    if (cur <= depth)
		return 0;
	    break;
	}
	ret = xmlTextReaderRead(reader);
	cur = xmlTextReaderDepth(reader);
    }
    return ret;
}

static ac_domain_x *msmFreeACDomain(ac_domain_x *ac_domain)
{
	if (ac_domain) {
	    ac_domain_x *prev = ac_domain->prev;
	    if (ac_domain->name) free((void *)ac_domain->name);
	    if (ac_domain->type) free((void *)ac_domain->type);
	    if (ac_domain->match) free((void *)ac_domain->match);
	    if (ac_domain->plist) free((void *)ac_domain->plist);
	    free((void *)ac_domain);
	    return prev;
	} else return NULL;
}

static annotation_x *msmProcessAnnotation(xmlTextReaderPtr reader)
{
    const xmlChar *name, *value;

    name = xmlTextReaderGetAttribute(reader, XMLCHAR("name"));
    value = xmlTextReaderGetAttribute(reader, XMLCHAR("value"));
    rpmlog(RPMLOG_DEBUG, "annotation %s %s\n", ASCII(name), ASCII(value));

    if (name && value) {
	annotation_x *annotation = calloc(1, sizeof(annotation_x));
	if (annotation) {
	    annotation->name = ASCII(name);
	    annotation->value = ASCII(value);
	    return annotation;
	}
    }
    if (name) free((void *)name);
    if (value) free((void *)value);
    return NULL;
}

static int msmProcessMember(xmlTextReaderPtr reader, member_x *member) 
{
    const xmlChar *node, *name;
    int ret, depth;

    name = xmlTextReaderGetAttribute(reader, XMLCHAR("name"));
    rpmlog(RPMLOG_DEBUG, "member %s\n", ASCII(name));
    member->name = ASCII(name);

    if (!name) return -1;

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "annotation")) {
	    annotation_x *annotation = msmProcessAnnotation(reader);
	    if (annotation) {
		member->annotation = annotation;
	    } else return -1;
	} else return -1;

	if (ret < 0) return -1;
    }
    return ret;
}

static int msmProcessInterface(xmlTextReaderPtr reader, interface_x *interface) 
{
    const xmlChar *node, *name;
    int ret, depth;

    name = xmlTextReaderGetAttribute(reader, XMLCHAR("name"));
    rpmlog(RPMLOG_DEBUG, "interface %s\n", ASCII(name));
    interface->name = ASCII(name);

    if (!name) return -1;

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "method")) {
	    member_x *member = calloc(1, sizeof(member_x));
	    if (member) {
		member->type = DBUS_METHOD;
		ret = msmProcessMember(reader, member);
		LISTADD(interface->members, member);
	    } else return -1;
	} else if (!strcmp(ASCII(node), "signal")) {
	    member_x *member = calloc(1, sizeof(member_x));
	    if (member) {
		member->type = DBUS_SIGNAL;
		ret = msmProcessMember(reader, member);
		LISTADD(interface->members, member);
	    } else return -1;
	} else if (!strcmp(ASCII(node), "annotation")) {
	    annotation_x *annotation = msmProcessAnnotation(reader);
	    if (annotation) {
		interface->annotation = annotation;
	    } else return -1;
	} else return -1;

	if (ret < 0) return -1;
    }
    return ret;
}

static int msmProcessNode(xmlTextReaderPtr reader, node_x *nodex) 
{
    const xmlChar *node, *name;
    int ret, depth;

    name = xmlTextReaderGetAttribute(reader, XMLCHAR("name"));
    rpmlog(RPMLOG_DEBUG, "node %s\n", ASCII(name));
    nodex->name = ASCII(name);

    if (!name) return -1;

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "interface")) {
	    interface_x *interface = calloc(1, sizeof(interface_x));
	    if (interface) {
		ret = msmProcessInterface(reader, interface);
		LISTADD(nodex->interfaces, interface);
	    } else return -1;
	} else if (!strcmp(ASCII(node), "method")) {
	    member_x *member = calloc(1, sizeof(member_x));
	    if (member) {
		member->type = DBUS_METHOD;
		ret = msmProcessMember(reader, member);
		LISTADD(nodex->members, member);
	    } else return -1;
	} else if (!strcmp(ASCII(node), "signal")) {
	    member_x *member = calloc(1, sizeof(member_x));
	    if (member) {
		member->type = DBUS_SIGNAL;
		ret = msmProcessMember(reader, member);
		LISTADD(nodex->members, member);
	    } else return -1;
	} else if (!strcmp(ASCII(node), "annotation")) {
	    annotation_x *annotation = msmProcessAnnotation(reader);
	    if (annotation) {
		nodex->annotation = annotation;
	    } else return -1;
	} else return -1;

	if (ret < 0) return -1;
    }
    return ret;
}

static int msmProcessDBus(xmlTextReaderPtr reader, dbus_x *dbus) 
{
    const xmlChar *node, *name, *own, *bus;
    int ret, depth;

    name = xmlTextReaderGetAttribute(reader, XMLCHAR("name"));
    own = xmlTextReaderGetAttribute(reader, XMLCHAR("own"));
    bus = xmlTextReaderGetAttribute(reader, XMLCHAR("bus"));
    rpmlog(RPMLOG_DEBUG, "dbus %s %s %s\n", ASCII(name), ASCII(own), ASCII(bus));
    dbus->name = ASCII(name);
    dbus->own = ASCII(own);
    dbus->bus = ASCII(bus);    

    if (!name || !bus) return -1;
    if (strcmp(dbus->bus, "session") && strcmp(dbus->bus, "system"))
	return -1;

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "node")) {
	    node_x *nodex = calloc(1, sizeof(node_x));
	    if (nodex) {
		ret = msmProcessNode(reader, nodex);
		LISTADD(dbus->nodes, nodex);
	    } else return -1;
	} else if (!strcmp(ASCII(node), "annotation")) {
	    annotation_x *annotation = msmProcessAnnotation(reader);
	    if (annotation) {
		dbus->annotation = annotation;
	    } else return -1;
	} else return -1;

	if (ret < 0) return -1;
    }
    return ret;
}

static ac_domain_x *msmProcessACDomain(xmlTextReaderPtr reader, sw_source_x *sw_source, char* pkg_name)
{
    const xmlChar *name, *match, *policy, *plist;

    name = xmlTextReaderGetAttribute(reader, XMLCHAR("name"));
    match = xmlTextReaderGetAttribute(reader, XMLCHAR("match"));
    policy = xmlTextReaderGetAttribute(reader, XMLCHAR("policy"));
    plist = xmlTextReaderGetAttribute(reader, XMLCHAR("plist"));
    rpmlog(RPMLOG_DEBUG, "ac_domain %s match %s policy %s plist %s\n", ASCII(name), ASCII(match), ASCII(policy), ASCII(plist));

    if (!((!name && !match) || (name && match))) {
	ac_domain_x *ac_domain = calloc(1, sizeof(ac_domain_x));
	if (ac_domain) {
	    ac_domain->name = ASCII(name);
	    ac_domain->match = ASCII(match);
 	    ac_domain->type = ASCII(policy);
 	    ac_domain->plist = ASCII(plist);
	    ac_domain->sw_source = sw_source;
	    ac_domain->pkg_name = pkg_name;	
	    return ac_domain;
	}
    }
    if (name) free((void *)name);
    if (match) free((void *)match);
    if (policy) free ((void*)policy);
    if (plist) free ((void*)plist);
    return NULL;
}

static filesystem_x *msmProcessFilesystem(xmlTextReaderPtr reader)
{
    const xmlChar *path, *label, *type, *exec_label;

    path = xmlTextReaderGetAttribute(reader, XMLCHAR("path"));
    label = xmlTextReaderGetAttribute(reader, XMLCHAR("label"));
    exec_label = xmlTextReaderGetAttribute(reader, XMLCHAR("exec_label"));
    type = xmlTextReaderGetAttribute(reader, XMLCHAR("type"));

    rpmlog(RPMLOG_DEBUG, "filesystem %s %s %s %s\n", 
	   ASCII(path), ASCII(label), ASCII(exec_label), ASCII(type));

    if (path && (label || exec_label)) {
	if (exec_label && label) {
	    rpmlog(RPMLOG_ERR, "An attempt to setup both label and exec_label on file. You should not need to do it.\n");
	    goto exit;
	}
	filesystem_x *filesystem = calloc(1, sizeof(filesystem_x));
	if (filesystem) {
	    filesystem->path = ASCII(path);
	    filesystem->label = ASCII(label);
	    filesystem->exec_label = ASCII(exec_label);
	    filesystem->type = ASCII(type);
	    return filesystem;
	}
    }

exit:

    if (path) free((void *)path);
    if (label) free((void *)label);
    if (exec_label) free((void *)exec_label);
    if (type) free((void *)type);
    return NULL;
}

static int msmProcessProvide(xmlTextReaderPtr reader, provide_x *provide, sw_source_x *current, manifest_x *mfx, const char* pkg_name)
{
    const xmlChar *node, *name, *origin;
    int ret, depth;

    name = xmlTextReaderGetAttribute(reader, XMLCHAR("name"));
    rpmlog(RPMLOG_DEBUG, "assign %s\n", ASCII(name));
    provide->name = ASCII(name);

    if (provide->name && 
	(strcmp(provide->name, "_system_") || mfx->sw_source->parent))
	return -1; /* only _system_ is accepted from root sw source */

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "dbus")) {
	    dbus_x *dbus = calloc(1, sizeof(dbus_x));
	    if (dbus) {
		ret = msmProcessDBus(reader, dbus);
		LISTADD(provide->dbuss, dbus);
	    } else return -1;
	} else if (!strcmp(ASCII(node), "ac_domain")) {
	    ac_domain_x *ac_domain = msmProcessACDomain(reader, current, pkg_name);
	    if (ac_domain) {
		const char *name = ac_domain->name;
		LISTADD(provide->ac_domains, ac_domain);
		if (!name) return -1;
		if (mfx && !provide->name) {
		    ac_domain->name = malloc(strlen(mfx->name) + 2 +
					      strlen(name) + 1);
		    sprintf((char *)ac_domain->name, "%s::%s", mfx->name, name);
		    free((void *)name);
		}
	    } else return -1;

	} else if (!strcmp(ASCII(node), "for")) {
	    origin = xmlTextReaderGetAttribute(reader, XMLCHAR("origin"));
	    rpmlog(RPMLOG_DEBUG, "for %s\n", ASCII(origin));
	    if (!origin) return -1;
	    if (provide->origin) { 
		free((void *)origin);
		return -1;
	    }
	    provide->origin = ASCII(origin);
	    if (strcmp(ASCII(origin), "trusted") && 
		strcmp(ASCII(origin), "current") &&
		strcmp(ASCII(origin), "all"))
		return -1;

	} else if (!strcmp(ASCII(node), "filesystem")) {
	    filesystem_x *filesystem = msmProcessFilesystem(reader);
	    if (filesystem) {
	    	LISTADD(provide->filesystems, filesystem);
	    } else return -1;

	} else return -1;

	if (ret < 0) return ret;
    }

    return ret;
}

static int msmProcessPackage(xmlTextReaderPtr reader, package_x *package, sw_source_x *current)
{
    const xmlChar *node, *name, *modified;
    int ret, depth;

    /* config processing */
    name = xmlTextReaderGetAttribute(reader, XMLCHAR("name"));
    modified = xmlTextReaderGetAttribute(reader, XMLCHAR("modified"));
    rpmlog(RPMLOG_DEBUG, "package %s %s\n", name, modified);

    package->name = ASCII(name);
    package->modified = ASCII(modified);
    package->sw_source = current;

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "provide")) {
	    provide_x *provide = calloc(1, sizeof(provide_x));
	    if (provide) {
		LISTADD(package->provides, provide);
		ret = msmProcessProvide(reader, provide, current, NULL, package->name);
	    } else return -1;
	} else return -1;

	if (ret < 0) return ret;
    }
    return ret;
}



static int msmProcessRequest(xmlTextReaderPtr reader, request_x *request) 
{
    const xmlChar *node, *name;
    int ret, depth;

    rpmlog(RPMLOG_DEBUG, "request \n");

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	    if (!strcmp(ASCII(node), "domain")) {
		    name = xmlTextReaderGetAttribute(reader, XMLCHAR("name"));   
		    rpmlog(RPMLOG_DEBUG, "ac domain name %s\n", ASCII(name));
		    if (name) {
			request->ac_domain = ASCII(name);
		    } else return -1;

	    } else if (!strcmp(ASCII(node), "description")) {
			continue;
	    } else return -1;
    }
    
    return ret;
}

static int msmProcessDRequest(xmlTextReaderPtr reader, define_x *define) 
{
    const xmlChar *node, *label, *type;
    int ret, depth;

    rpmlog(RPMLOG_DEBUG, "request\n");

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "smack")) {
	    label = xmlTextReaderGetAttribute(reader, XMLCHAR("request"));
	    type = xmlTextReaderGetAttribute(reader, XMLCHAR("type"));
	    rpmlog(RPMLOG_DEBUG, "request %s type %s\n", ASCII(label), ASCII(type));
	    if (label && type) {
		    d_request_x *request = calloc(1, sizeof(d_request_x));
		    if (request) {
			request->label_name = ASCII(label);
			request->ac_type = ASCII(type);
			LISTADD(define->d_requests, request);
		    } else {
			if (label) free((void *)label);
		   	if (type) free((void *)type);
			return -1;
		    }

	    } else  {
		    if (label) free((void *)label);
		    if (type) free((void *)type);	
		    return -1;
	    }
	} else if (!strcmp(ASCII(node), "description")) {
		continue;
	} else return -1;
    }
    return ret;
}
static int msmProcessDPermit(xmlTextReaderPtr reader, define_x *define) 
{
    const xmlChar *node, *label, *type;
    int ret, depth;

    rpmlog(RPMLOG_DEBUG, "permit\n");

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "smack")) {
	    label = xmlTextReaderGetAttribute(reader, XMLCHAR("permit"));
	    type = xmlTextReaderGetAttribute(reader, XMLCHAR("type"));
	    rpmlog(RPMLOG_DEBUG, "permit %s type %s\n", ASCII(label), ASCII(type));

	    if (label && type) {
		    d_permit_x *permit = calloc(1, sizeof(d_permit_x));
		    if (permit) {
			permit->label_name = ASCII(label);
			permit->ac_type = ASCII(type);
			LISTADD(define->d_permits, permit);
		    } else {
			if (label) free((void *)label);
		   	if (type) free((void *)type);
			return -1;
		    }

	    } else  {
		    if (label) free((void *)label);
		    if (type) free((void *)type);	
		    return -1;
	    }
	} else if (!strcmp(ASCII(node), "description")) {
		continue;
	} else return -1;
    }
    return ret;
}

static int msmProcessDProvide(xmlTextReaderPtr reader, define_x *define) 
{
    const xmlChar *node, *label;
    int ret, depth;
    char sep[]= "::";

    rpmlog(RPMLOG_DEBUG, "provide\n");

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "label")) {
	    label = xmlTextReaderGetAttribute(reader, XMLCHAR("name"));
	    rpmlog(RPMLOG_DEBUG, "label %s \n", ASCII(label));
	    if (label) {
		     if (strlen(ASCII(label)) > SMACK_LABEL_LENGTH) { //smack limitation on lenght
			rpmlog(RPMLOG_ERR, "Label name  %s lenght %d is longer than defined SMACK_LABEL_LENGTH. Can't define such domain\n", 
													label, strlen(ASCII(label)));
			if (label) free((void *)label);
			return -1;
		    }
		    char *tmp = calloc(strlen(define->name) + 3, sizeof (const char));
		    if (!tmp) {
		         if (label) free((void *)label);
			 return -1;
		    }
		    strncpy(tmp, define->name, strlen(define->name));
		    strncpy(tmp + strlen(define->name), sep, 2);
		    if (strstr(ASCII(label), tmp) != ASCII(label)) { //label name should be prefixed by domain name and "::"
			rpmlog(RPMLOG_ERR, "Label name %s isn't prefixed by domain name %s. Can't define such domain\n", ASCII(label), define->name);
			if (label) free((void *)label);
			return -1;
		    } 
		    if (tmp) free ((void*)tmp);
		    d_provide_x *provide = calloc(1, sizeof(d_provide_x));
		    if (provide) {
			provide->label_name = ASCII(label);
			LISTADD(define->d_provides, provide);
		    } else {
			if (label) free((void *)label);
			return -1;
		    }

	    } else  {
		    return -1;
	    }
	} else if (!strcmp(ASCII(node), "description")) {
		continue;
	} else return -1;
    }
    return ret;
}

static int msmProcessDefine(xmlTextReaderPtr reader, define_x *define, manifest_x *mfx, sw_source_x *current) 
{
    const xmlChar *node, *name, *policy, *plist;
    int ret, depth;

    rpmlog(RPMLOG_DEBUG, "define\n");

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	    node = xmlTextReaderConstName(reader);
	    if (!node) return -1;

	    if (!strcmp(ASCII(node), "domain")) {
		    name = xmlTextReaderGetAttribute(reader, XMLCHAR("name"));
		    policy = xmlTextReaderGetAttribute(reader, XMLCHAR("policy"));
		    plist = xmlTextReaderGetAttribute(reader, XMLCHAR("plist"));
		    rpmlog(RPMLOG_DEBUG, "domain %s policy %s plist %s\n", 
			   ASCII(name), ASCII(policy), ASCII(plist));

		    if (name) {
			    define->name = ASCII(name);
			    if (strlen(define->name) > SMACK_LABEL_LENGTH) { //smack limitation on lenght
				rpmlog(RPMLOG_ERR, "Domain name  %s lenght is longer than defined SMACK_LABEL_LENGTH. Can't define such domain\n", define->name);
			    	if (policy) free((void *)policy);
				if (plist) free((void *)plist);
				return -1;
			    }
                            if (strlen(define->name) == 0){
				rpmlog(RPMLOG_ERR, "An attempt to define an empty domain name. Can't define such domain\n");
			    	if (policy) free((void *)policy);
				if (plist) free((void *)plist);
				return -1;
			     }
			    define->policy = ASCII(policy);
			    define->plist = ASCII(plist);

			    // store defined ac domain name 
			    ac_domain_x *ac_domain = calloc(1, sizeof(ac_domain_x));
			    if (ac_domain) {
				    if (define->name) {
				    	ac_domain->name = calloc(strlen(define->name) + 1, sizeof(const char));
			    	    	if (!ac_domain->name) {
						free(ac_domain);
						return -1;
					}
			    	    	strncpy(ac_domain->name, define->name, strlen(define->name));
				    }
				    ac_domain->match = calloc(8, sizeof(const char));
				    if (!ac_domain->match) {
						msmFreeACDomain(ac_domain);
						return -1;
					}	
				    strncpy(ac_domain->match, "trusted", 7); // hardcode trusted policy for ac domain definition
				    if (define->policy) {
				    	ac_domain->type = calloc(strlen(define->policy) + 1, sizeof(const char));
				    	if (!ac_domain->type) {
						msmFreeACDomain(ac_domain);
						return -1;
					}
				    	strncpy(ac_domain->type, define->policy, strlen(define->policy));
				    }	
				    if (define->plist) {
				    	ac_domain->plist = calloc(strlen(define->plist) + 1, sizeof(const char));
				    	if (!ac_domain->plist) {
						msmFreeACDomain(ac_domain);
						return -1;
					}
				    	strncpy(ac_domain->plist, define->plist, strlen(define->plist));
				    }				  
				    ac_domain->sw_source = current;
				    ac_domain->pkg_name = mfx->name;
				    if (!mfx->provides){
				 	provide_x *provide = calloc(1, sizeof(provide_x));
					if (provide) {
						LISTADD(mfx->provides, provide);
					} else { 
						if (ac_domain) {
							msmFreeACDomain(ac_domain);
							return -1;
						}
					}
				    }
				    LISTADD(mfx->provides->ac_domains, ac_domain);
			    } else 
				    return -1;
		    } else  {
			    if (name) free((void *)name);
			    if (policy) free((void *)policy);	
			    if (plist) free((void *)plist);	
			    return -1;
		    }
	    } else if (!strcmp(ASCII(node), "request")) {
		    int res = msmProcessDRequest(reader, define);
		    if (res < 0) return res;
	    
	    } else if (!strcmp(ASCII(node), "permit")) {
		    int res = msmProcessDPermit(reader, define);
		    if (res < 0) return res;

	    } else if (!strcmp(ASCII(node), "provide")) {
		    int res = msmProcessDProvide(reader, define);
		    if (res < 0) return res;
	    } else if (!strcmp(ASCII(node), "description")) {
		    continue; /* we don't store decriptions tags */
	    } else return -1;

	if (ret < 0) return ret;
    }
  
    return ret;
}



static int msmProcessKeyinfo(xmlTextReaderPtr reader, origin_x *origin) 
{
    const xmlChar *keydata;
    keyinfo_x *keyinfo;
    int ret, depth;

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	keydata = xmlTextReaderConstValue(reader);
	rpmlog(RPMLOG_DEBUG, "keyinfo %.40s...\n", ASCII(keydata));
	if (!keydata) return -1;
	keyinfo = calloc(1, sizeof(keyinfo_x));
	if (keyinfo) {
	    if ((ret = b64decode(ASCII(keydata), (void **)&keyinfo->keydata, &keyinfo->keylen))) {
		rpmlog(RPMLOG_ERR, "Failed to decode keyinfo %s, %d\n", keydata, ret);
		ret = -1;
	    }
	    LISTADD(origin->keyinfos, keyinfo);
	} else return -1;

	if (ret < 0) return ret;
    }
    return ret;
}

static access_x *msmProcessAccess(xmlTextReaderPtr reader, origin_x *origin) 
{
    const xmlChar *data, *type;

    data = xmlTextReaderGetAttribute(reader, XMLCHAR("data"));
    type = xmlTextReaderGetAttribute(reader, XMLCHAR("type"));
    rpmlog(RPMLOG_DEBUG, "access %s %s\n", ASCII(data), ASCII(type));

    if (data) {
	access_x *access = calloc(1, sizeof(access_x));
	if (access) {
	    access->data = ASCII(data);
	    access->type = ASCII(type);
	    return access;
	}
    }
    if (data) free((void *)data);
    if (type) free((void *)type);
    return NULL;
}

static int msmProcessOrigin(xmlTextReaderPtr reader, origin_x *origin) 
{
    const xmlChar *node, *type;
    int ret, depth;

    type = xmlTextReaderGetAttribute(reader, XMLCHAR("type"));
    rpmlog(RPMLOG_DEBUG, "origin %s\n", ASCII(type));
    origin->type = ASCII(type);

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "keyinfo")) {
	    ret = msmProcessKeyinfo(reader, origin);
	} else if (!strcmp(ASCII(node), "access")) {
	    access_x *access = msmProcessAccess(reader, origin);
	    if (access) {
		LISTADD(origin->accesses, access);
	    } else return -1;
	} else return -1;

	if (ret < 0) return ret;
    }
    return ret;
}

static int msmProcessDeny(xmlTextReaderPtr reader, sw_source_x *sw_source) 
{
    const xmlChar *node;
    int ret, depth;

    rpmlog(RPMLOG_DEBUG, "deny\n");

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "ac_domain")) {
	    ac_domain_x *ac_domain = msmProcessACDomain(reader, sw_source, NULL);
	    if (ac_domain) {
		if (ac_domain->name) {
		    HASH_ADD_KEYPTR(hh, sw_source->denys, ac_domain->name, 
				    strlen(ac_domain->name), ac_domain);
		} else {
		    LISTADD(sw_source->denymatches, ac_domain);
		}
	    } else return -1;
	} else return -1;
    }
    return ret;
}

static int msmProcessAllow(xmlTextReaderPtr reader, sw_source_x *sw_source) 
{
    const xmlChar *node;    
    int ret, depth;

    rpmlog(RPMLOG_DEBUG, "allow\n");

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "deny")) {
	    ret = msmProcessDeny(reader, sw_source);
	} else if (!strcmp(ASCII(node), "ac_domain")) {
	    ac_domain_x *ac_domain = msmProcessACDomain(reader, sw_source, NULL);
	    if (ac_domain) {
		if (ac_domain->name) {
		    HASH_ADD_KEYPTR(hh, sw_source->allows, ac_domain->name, 
				    strlen(ac_domain->name), ac_domain);
		} else {
		    LISTADD(sw_source->allowmatches, ac_domain);
		}
	    } else return -1;
	} else return -1;

	if (ret < 0) return ret;
    }
    return ret;
}

static int msmFindSWSourceByName(sw_source_x *sw_source, void *param)
{
    const char *name = (const char *)param;
    return strcmp(sw_source->name, name); 
}

static int msmProcessSWSource(xmlTextReaderPtr reader, sw_source_x *sw_source, const char *parentkey, manifest_x *mfx) 
{
    const xmlChar *name, *node, *rank, *rankkey;
    sw_source_x *current;
    int ret, depth, len;
    int rankval = 0;

    /* config processing */
    current = sw_source;

    name = xmlTextReaderGetAttribute(reader, XMLCHAR("name"));
    rank = xmlTextReaderGetAttribute(reader, XMLCHAR("rank"));
    rankkey = xmlTextReaderGetAttribute(reader, XMLCHAR("rankkey"));
    rpmlog(RPMLOG_DEBUG, "sw source %s rank %s key %s\n", 
	   ASCII(name), ASCII(rank), ASCII(rankkey));

    sw_source->name = ASCII(name);

    if (rankkey) {
	/* config processing */
	sw_source->rankkey = ASCII(rankkey);
    } else {
	if (rank) {
	    rankval = atoi(ASCII(rank));
	    free((void *)rank); /* rankkey is used from now on */
	}
    }
    if (!sw_source->name) return -1; /* sw source must have name */
    if (!mfx && rankkey) return -1; /* manifest cannot set rankkey itself */

    if (!mfx) {
	sw_source_x *old = msmSWSourceTreeTraversal(sw_source->parent, msmFindSWSourceByName, (void *)sw_source->name);
	if (old && old->parent != sw_source->parent) {
	    if (!old->parent && old == sw_source->parent) {
		/* root sw source upgrade (it's signed by root) */
		parentkey = "";
	    } else {
		rpmlog(RPMLOG_ERR, "SW source called %s has already been installed\n", 
		       sw_source->name);
		return -1; /* sw_source names are unique (allow upgrade though) */
	    }
	}
	/* rank algorithm is copied from harmattan dpkg wrapper */
	if (rankval > RANK_LIMIT) rankval = RANK_LIMIT;
	if (rankval < -RANK_LIMIT) rankval = -RANK_LIMIT;
	rankval += RANK_LIMIT;

	len = strlen(parentkey) + 1 + 5 + 1 + 5 + 1 + strlen(sw_source->name) + 1;
	if (!(sw_source->rankkey = malloc(len))) return -1;
	sprintf((char *)sw_source->rankkey, "%s/%05d/%05d.%s", 
		parentkey, rankval, RANK_LIMIT, sw_source->name);
    }

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "allow")) {
	    ret = msmProcessAllow(reader, sw_source);
	} else if (!strcmp(ASCII(node), "deny")) {
	    ret = msmProcessDeny(reader, sw_source);
	} else if (!strcmp(ASCII(node), "origin")) {
	    origin_x *origin = calloc(1, sizeof(origin_x));
	    if (origin) {
		LISTADD(sw_source->origins, origin);
		ret = msmProcessOrigin(reader, origin);
	    } else return -1;
	} else if (!strcmp(ASCII(node), "package")) {
	    /* config processing */
	    if (!mfx) return -1;
	    package_x *package = calloc(1, sizeof(package_x));
	    if (package) {
		LISTADD(sw_source->packages, package);
		ret = msmProcessPackage(reader, package, current);
	    } else return -1;
	} else if (!strcmp(ASCII(node), "sw_source")) {
	    /* config processing */
	    if (!mfx) return -1;
	    sw_source_x *sw_source = calloc(1, sizeof(sw_source_x));
	    if (sw_source) {
		sw_source->parent = current;
		LISTADD(mfx->sw_sources, sw_source);
	    } else return -1;
	    ret = msmProcessSWSource(reader, sw_source, "", mfx);
	} else return -1;

	if (ret < 0) return ret;
    }
    return ret;
}

static int msmProcessMsm(xmlTextReaderPtr reader, manifest_x *mfx, sw_source_x *current)
{
    const xmlChar *node;
    int ret, depth;

    mfx->sw_source = current;

    rpmlog(RPMLOG_DEBUG, "manifest\n");

    depth = xmlTextReaderDepth(reader);
    while ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "assign")) {
	    provide_x *provide = calloc(1, sizeof(provide_x));
	    if (provide) {
		LISTADD(mfx->provides, provide);
		ret = msmProcessProvide(reader, provide, current, mfx, NULL);
	    } else return -1;
	} else if (!strcmp(ASCII(node), "define")) {
	    mfx->define = calloc(1, sizeof(define_x));
	    if (mfx->define) {
		ret = msmProcessDefine(reader, mfx->define, mfx, current);
	    } else return -1;
	} else if (!strcmp(ASCII(node), "request")) {
	    mfx->request = calloc(1, sizeof(request_x));
	    if (mfx->request) {
		ret = msmProcessRequest(reader, mfx->request);
	    } else return -1;
	} else if (!strcmp(ASCII(node), "sw_source")) {
	    sw_source_x *sw_source = calloc(1, sizeof(sw_source_x));
	    if (sw_source) {
		char parentkey[256] = { 0 };
		sw_source->parent = current;
		if (sw_source->parent) {
		    snprintf(parentkey, sizeof(parentkey), 
			     "%s", sw_source->parent->rankkey);
		    char *sep = strrchr(parentkey, '/');
		    if (sep) *sep = '\0';
		}
		LISTADD(mfx->sw_sources, sw_source);
		ret = msmProcessSWSource(reader, sw_source, parentkey, NULL);
	    } else return -1;
	} else return -1;

	if (ret < 0) return ret;
    }

    return ret;
}

static int msmProcessConfig(xmlTextReaderPtr reader, manifest_x *mfx)
{
    const xmlChar *node;
    int ret, depth;

    rpmlog(RPMLOG_DEBUG, "config\n");

    depth = xmlTextReaderDepth(reader);
    if ((ret = msmNextChildElement(reader, depth))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "sw_source")) {
	    mfx->sw_sources = calloc(1, sizeof(sw_source_x));
	    if (!mfx->sw_sources) return -1;
	    ret = msmProcessSWSource(reader, mfx->sw_sources, "", mfx);
	} else return -1;
    }
    return ret;
}

static int msmProcessManifest(xmlTextReaderPtr reader, manifest_x *mfx, sw_source_x *current) 
{
    const xmlChar *node;
    int ret;

    if ((ret = msmNextChildElement(reader, -1))) {
	node = xmlTextReaderConstName(reader);
	if (!node) return -1;

	if (!strcmp(ASCII(node), "manifest")) {
	    ret = msmProcessMsm(reader, mfx, current);
	} else if (!strcmp(ASCII(node), "config")) {
	    ret = msmProcessConfig(reader, mfx);
	} else return -1;
    }
    return ret;
}



static filesystem_x *msmFreeFilesystem(filesystem_x *filesystem)
{    
	if (filesystem) {
	    filesystem_x *prev = filesystem->prev;
	    if (filesystem->path) free((void *)filesystem->path);
	    if (filesystem->label) free((void *)filesystem->label);
	    if (filesystem->exec_label) free((void *)filesystem->exec_label);
	    if (filesystem->type) free((void *)filesystem->type);
	    free((void *)filesystem);
	    return prev;
	} else
		return NULL;

}

static member_x *msmFreeMember(member_x *member)
{    

	if (member) {
	    member_x *prev = member->prev;
	    if (member->name) free((void *)member->name);
 	    if (member->annotation) {
		if (member->annotation->name) free((void *)member->annotation->name);
	    	if (member->annotation->value) free((void *)member->annotation->value);
		free((void *)member->annotation);
	    }
	    free((void *)member);
	    return prev;
	} else
		return NULL;

}


static interface_x *msmFreeInterface(interface_x *interface)
{    

        member_x *member;

	if (interface) {
	    interface_x *prev = interface->prev;
	    if (interface->name) free((void *)interface->name);
 	    if (interface->annotation) {
		if (interface->annotation->name) free((void *)interface->annotation->name);
	    	if (interface->annotation->value) free((void *)interface->annotation->value);
		free((void *)interface->annotation);
	    }
            for (member = interface->members; member; member = msmFreeMember(member));
	    free((void *)interface);
	    return prev;
	} else
		return NULL;

}

static node_x *msmFreeNode(node_x *node)
{    
 	member_x *member;
 	interface_x *interface;

	if (node) {
	    node_x *prev = node->prev;
	    if (node->name) free((void *)node->name);
 	    if (node->annotation) {
		if (node->annotation->name) free((void *)node->annotation->name);
	    	if (node->annotation->value) free((void *)node->annotation->value);
		free((void *)node->annotation);
	    }
	    for (member = node->members; member; member = msmFreeMember(member));
	    for (interface = node->interfaces; interface; interface = msmFreeInterface(interface));
	    free((void *)node);
	    return prev;
	} else
		return NULL;

}

static dbus_x *msmFreeDBus(dbus_x *dbus)
{
	node_x *node;

	if (dbus) {
	    dbus_x *prev = dbus->prev;
	    if (dbus->name) free((void *)dbus->name);
	    if (dbus->own) free((void *)dbus->own);
	    if (dbus->bus) free((void *)dbus->bus);
            if (dbus->annotation) {
		if (dbus->annotation->name) free((void *)dbus->annotation->name);
	    	if (dbus->annotation->value) free((void *)dbus->annotation->value);
		free((void *)dbus->annotation);
	    }
	    for (node = dbus->nodes; node; node = msmFreeNode(node));
	    free((void *)dbus);
	    return prev;
	} else return NULL;
}



static provide_x *msmFreeProvide(provide_x *provide) 
{
    ac_domain_x *ac_domain;
    filesystem_x *filesystem;
    provide_x *prev = provide->prev;
    dbus_x *dbus;

    if (provide) {
	    for (ac_domain = provide->ac_domains; ac_domain; ac_domain = msmFreeACDomain(ac_domain));
	    if (provide->filesystems)
	    	for (filesystem = provide->filesystems; filesystem; filesystem = msmFreeFilesystem(filesystem));
	    if (provide->name) free((void *)provide->name);
	    if (provide->origin) free((void *)provide->origin);
	    for (dbus = provide->dbuss; dbus; dbus = msmFreeDBus(dbus));
	    free((void *)provide);
    }
    return prev;
}


static file_x *msmFreeFile(file_x *file)
{
    file_x *prev = file->prev;
    if (file->path) free((void *)file->path);
    free((void *)file);
    return prev;
}

package_x *msmFreePackage(package_x *package)
{
    provide_x *provide;
    package_x *prev = package->prev;
    for (provide = package->provides; provide; provide = msmFreeProvide(provide));
    if (package->name) free((void *)package->name);
    if (package->modified) free((void *)package->modified);
    free((void *)package);
    package = NULL;
    return prev;
}

static keyinfo_x *msmFreeKeyinfo(keyinfo_x *keyinfo)
{
    keyinfo_x *prev = keyinfo->prev;
    if (keyinfo->keydata) free((void *)keyinfo->keydata);
    free((void *)keyinfo);
    return prev;
}

static access_x *msmFreeAccess(access_x *access)
{
    access_x *prev = access->prev;
    if (access->data) free((void *)access->data);
    if (access->type) free((void *)access->type);
    free((void *)access);
    return prev;
}

static origin_x *msmFreeOrigin(origin_x *origin)
{
    keyinfo_x *keyinfo;
    access_x *access;
    origin_x *prev = origin->prev;
    for (keyinfo = origin->keyinfos; keyinfo; keyinfo = msmFreeKeyinfo(keyinfo));
    for (access = origin->accesses; access; access = msmFreeAccess(access));
    if (origin->type) free((void *)origin->type);
    free((void *)origin);
    return prev;
}

static sw_source_x *msmFreeSWSource(sw_source_x *sw_source)
{
    package_x *package;
    ac_domain_x *ac_domain, *temp;
    origin_x *origin;
    sw_source_x *next = sw_source->next;

    rpmlog(RPMLOG_DEBUG, "freeing sw source %s\n", sw_source->name);

    for (package = sw_source->packages; package; package = msmFreePackage(package));
    for (ac_domain = sw_source->allowmatches; ac_domain; ac_domain = msmFreeACDomain(ac_domain));
    if (sw_source->allows) {
	HASH_ITER(hh, sw_source->allows, ac_domain, temp) {
	    HASH_DELETE(hh, sw_source->allows, ac_domain);
	    msmFreeACDomain(ac_domain);
	}
    }
    for (ac_domain = sw_source->denymatches; ac_domain; ac_domain = msmFreeACDomain(ac_domain));
    if (sw_source->denys) {
	HASH_ITER(hh, sw_source->denys, ac_domain, temp) {
	    HASH_DELETE(hh, sw_source->denys, ac_domain);
	    msmFreeACDomain(ac_domain);
	}
    }
    for (origin = sw_source->origins; origin; origin = msmFreeOrigin(origin));
    if (sw_source->name) free((void *)sw_source->name);
    if (sw_source->rankkey) free((void *)sw_source->rankkey);
    free((void *)sw_source);
    return next;
}

static d_request_x *msmFreeDRequest(d_request_x *d_request)
{
    d_request_x *next = d_request->next;
    rpmlog(RPMLOG_DEBUG, "freeing domain request %s\n", d_request->label_name);
    if (d_request->label_name) free((void *)d_request->label_name);
    if (d_request->ac_type) free((void *)d_request->ac_type);
    free((void *)d_request);
    return next;
}

static d_permit_x *msmFreeDPermit(d_permit_x *d_permit)
{
    d_permit_x *next = d_permit->next;
    rpmlog(RPMLOG_DEBUG, "freeing domain permit %s\n", d_permit->label_name);
    if (d_permit->label_name) free((void *)d_permit->label_name);
    if (d_permit->ac_type) free((void *)d_permit->ac_type);
    free((void *)d_permit);
    return next;
}

static d_provide_x *msmFreeDProvide(d_provide_x *d_provide)
{
    d_provide_x *next = d_provide->next;
    rpmlog(RPMLOG_DEBUG, "freeing domain provide %s\n", d_provide->label_name);
    if (d_provide->label_name) free((void *)d_provide->label_name);
    free((void *)d_provide);
    return next;
}

void msmFreeManifestXml(manifest_x *mfx)
{
    provide_x *provide;
    file_x *file;
    sw_source_x *sw_source;
    d_request_x *d_request;
    d_permit_x *d_permit;
    d_provide_x *d_provide;

    rpmlog(RPMLOG_DEBUG, "in msmFreeManifestXml\n");

    if (mfx) {
	if (mfx->provides)
		for (provide = mfx->provides; provide; provide = msmFreeProvide(provide));
        rpmlog(RPMLOG_DEBUG, "after freeing provides\n");
	if (mfx->request) {
		if (mfx->request->ac_domain) free ((void*)mfx->request->ac_domain);
		free((void*)mfx->request);
	}
        rpmlog(RPMLOG_DEBUG, "after freeing requests\n");
	for (file = mfx->files; file; file = msmFreeFile(file));
        rpmlog(RPMLOG_DEBUG, "after freeing files\n");
	if (mfx->sw_sources) {
	    LISTHEAD(mfx->sw_sources, sw_source);	
	    for (; sw_source; sw_source = msmFreeSWSource(sw_source));
	}
	if (mfx->name) free((void *)mfx->name);
        rpmlog(RPMLOG_DEBUG, "after freeing name\n");
	if (mfx->define) {
		if (mfx->define->name) free ((void*)mfx->define->name);
		if (mfx->define->policy) free ((void*)mfx->define->policy);
		if (mfx->define->plist) free ((void*)mfx->define->plist);
		if (mfx->define->d_requests) {
			LISTHEAD(mfx->define->d_requests, d_request);	
	    		for (; d_request; d_request = msmFreeDRequest(d_request));
		}
        rpmlog(RPMLOG_DEBUG, "after freeing define requests\n");
		if (mfx->define->d_permits) {
			LISTHEAD(mfx->define->d_permits, d_permit);	
	    		for (; d_permit; d_permit = msmFreeDPermit(d_permit));
		}
        rpmlog(RPMLOG_DEBUG, "after freeing define permits\n");
		if (mfx->define->d_provides) {
			LISTHEAD(mfx->define->d_provides, d_provide);	
	    		for (; d_provide; d_provide = msmFreeDProvide(d_provide));
		}
        rpmlog(RPMLOG_DEBUG, "after freeing provides\n");
		free ((void*) mfx->define); 
	}
        rpmlog(RPMLOG_DEBUG, "after freeing defines\n");
	free((void *)mfx);

    }
}

manifest_x *msmProcessManifestXml(const char *buffer, int size, sw_source_x *current, const char *packagename) 
{
    xmlTextReaderPtr reader;
    manifest_x *mfx = NULL;

    reader = xmlReaderForMemory(buffer, size, NULL, NULL, 0);
    if (reader) {
	mfx = calloc(1, sizeof(manifest_x));
	if (mfx) {
	    mfx->name = strdup(packagename);
	    if (msmProcessManifest(reader, mfx, current) < 0) {
		msmFreeManifestXml(mfx);
		mfx = NULL;
	    }
	}
	xmlFreeTextReader(reader);
    } else {
        rpmlog(RPMLOG_ERR, "Unable to create xml reader\n");
    }
    return mfx;
}

manifest_x *msmProcessDevSecPolicyXml(const char *filename) 
{
    xmlTextReaderPtr reader;
    manifest_x *mfx = NULL;

    reader = xmlReaderForFile(filename, NULL, 0);
    if (reader) {
	mfx = calloc(1, sizeof(manifest_x));
	if (mfx) {
	    if (msmProcessManifest(reader, mfx, NULL) < 0) {
		msmFreeManifestXml(mfx);
		mfx = NULL;
	    }
	}
        xmlFreeTextReader(reader);
    } else {
        rpmlog(RPMLOG_ERR, "Unable to open device security policy %s\n", filename);
    }
    return mfx;
}
