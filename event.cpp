/*
 * Copyright 2008 Juniper Networks, Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * o Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * o Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the  
 *   distribution.
 * o Neither the name of Juniper Networks nor the names of its
 *   contributors may be used to endorse or promote products 
 *   derived from this software without specific prior written 
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ifmap.nsmap"
#include "ifmapServiceProxy.h"
#include "connect.h"

static void usage()
{
    fprintf(stderr, "usage: event update if-map-server-url ip name [ -d time ] [ -m magnitude ]\n"
                    "             [ -c confidence ] [ -s significance ] [ -t type ]\n"
                    "             [ -o other ] [ -i information ] [ -v vulnerability-uri ]\n"
                    "             [ -u user ] [ -p password ]\n\n");
    fprintf(stderr, "             If time, magnitude, confidence, or significance\n"
                    "             is not specified a reasonable default is used.\n\n");
    fprintf(stderr, "       event delete if-map-server-url ip name [ -u user ] [ -p password ]\n");
    exit(1);
}

int main(int argc, char* argv[])
{
    if (argc < 4) {
        usage();
    }
    char* op = argv[1];
    char* url = argv[2];
    char* ip = argv[3];
    char* name = argv[4];
    time_t date = 0;
    int magnitude = 50;
    int confidence = 50;
    char* significance = "important";
    char* type = 0;
    char* other = 0;
    char* information = 0;
    char* vulnerabilityUri = 0;
    char* user = 0;
    char* password = 0;
    if (strcmp(op, "delete") == 0) {
        argv += 4;
        argc -= 4;
        while (--argc) {
            char* option = *++argv;
            if (!argc) {
                usage();
            }
            --argc;
            char* argument = *++argv;
            if (strcmp(option, "-u") == 0) {
                user = argument;
            } else if (strcmp(option, "-p") == 0) {
                password = argument;
            } else {
                usage();
            }
        }
    } else if (strcmp(op, "update") == 0) {
        argv += 4;
        argc -= 4;
        while (--argc) {
            char* option = *++argv;
            if (!argc) {
                usage();
            }
            --argc;
            char* argument = *++argv;
            if (strcmp(option, "-d") == 0) {
                date = atoi(argument);
            } else if (strcmp(option, "-m") == 0) {
                magnitude = atoi(argument);
                if (magnitude < 0 || magnitude > 100) {
                    fprintf(stderr, "magnitude must be between 0 and 100\n");
                    return 1;
                }
            } else if (strcmp(option, "-c") == 0) {
                confidence = atoi(argument);
                if (confidence < 0 || confidence > 100) {
                    fprintf(stderr, "confidence must be between 0 and 100\n");
                    return 1;
                }
            } else if (strcmp(option, "-s") == 0) {
                significance = argument;
            } else if (strcmp(option, "-t") == 0) {
                type = argument;
            } else if (strcmp(option, "-o") == 0) {
                other = argument;
            } else if (strcmp(option, "-i") == 0) {
                information = argument;
            } else if (strcmp(option, "-v") == 0) {
                vulnerabilityUri = argument;
            } else if (strcmp(option, "-u") == 0) {
                user = argument;
            } else if (strcmp(option, "-p") == 0) {
                password = argument;
            } else {
                usage();
            }
        }
        if (!date) {
            date = time(0);
        }
    } else {
        usage();
    }

    Service service;
    if (user && password) {
        service.soap->userid = user;
        service.soap->passwd = password;
    }
    service.endpoint = url;
    int code = ifmapConnect(service);
    if (code != SOAP_OK) {
        soap_print_fault(service.soap, stderr);
        return 1;
    }
    
    service.soap->header->ifmap__publisher_id = 0;

    ifmap__IPAddressType ipAddr;
    ipAddr.type = _ifmap__IPAddressType_type__IPv4;
    ipAddr.value = ip;
    ifmap__IdentifierType ipIdent;
    ipIdent.__union_IdentifierType = SOAP_UNION__ifmap__union_IdentifierType_ip_address;
    ipIdent.union_IdentifierType.ip_address = &ipAddr;
    
    _meta__event event;
    struct soap metaSoap(SOAP_XML_DOM);
    ifmap__MetadataListType metadata;
    ifmap__PublishType update;
    ifmap__DeleteType delete_;
    char filterBuf[100];
    __ifmap__union_PublishRequestType publish;

    if (strcmp(op, "update") == 0) {
        event.name = name;
        event.event_recorded_time = date;
        char magnitudeBuf[20];
        snprintf(magnitudeBuf, sizeof magnitudeBuf, "%d", magnitude);
        event.magnitude = magnitudeBuf;
        char confidenceBuf[100];
        snprintf(confidenceBuf, sizeof confidenceBuf, "%d", confidence);
        event.confidence = confidenceBuf;
        if (strcmp(significance, "critical") == 0) {
            event.significance = _meta__event_significance__critical;
        } else if (strcmp(significance, "important") == 0) {
            event.significance = _meta__event_significance__important;
        } else if (strcmp(significance, "informational") == 0) {
            event.significance = _meta__event_significance__informational;
        } else {
            fprintf(stderr, "significance must be one of critical, important, or informational\n");
            return 1;
        }
        event.type = 0;
        if (type) {
            _meta__event_type eventType;
            if (strcmp(type, "p2p") == 0) {
                eventType = _meta__event_type__p2p;
            } else if (strcmp(type, "cve") == 0) {
                eventType = _meta__event_type__cve;
            } else if (strcmp(type, "botnet infection") == 0) {
                eventType = _meta__event_type__botnet_x0020infection;
            } else if (strcmp(type, "worm infection") == 0) {
                eventType = _meta__event_type__worm_x0020infection;
            } else if (strcmp(type, "excessive flows") == 0) {
                eventType = _meta__event_type__excessive_x0020flows;
            } else if (strcmp(type, "behavioral change") == 0) {
                eventType = _meta__event_type__behavioral_x0020change;
            } else if (strcmp(type, "policy violation") == 0) {
                eventType = _meta__event_type__policy_x0020violation;
            } else if (strcmp(type, "other") == 0) {
                eventType = _meta__event_type__other;
            } else {
                fprintf(stderr, "type must be one of p2p, cve, botnet infection, worm infection,"
                        " excessive flows, behavioral change, policy violation, or other\n");
                return 1;
            }
            event.type = &eventType;
            if (eventType == _meta__event_type__other && !other) {
                fprintf(stderr, "must specify \"other\" parameter for type other\n");
                return 1;
            }
        }
        if ((!event.type || *event.type != _meta__event_type__other) && other) {
            fprintf(stderr, "Do not specify \"other\" parameter unless type is other\n");
            return 1;
        }
        event.other_type_definition = other;
        event.information = information;
        event.vulnerability_uri = vulnerabilityUri;

        event.soap_out(&metaSoap, "meta:event", 0, 0);
        metadata.__size = 1;
        metadata.__any = metaSoap.dom;

        update.__union_PublishType = SOAP_UNION__ifmap__union_PublishType_identifier;
        update.union_PublishType.identifier = &ipIdent;
        update.metadata = &metadata;
        publish.__union_PublishRequestType = SOAP_UNION__ifmap__union_PublishRequestType_update;
        publish.union_PublishRequestType.update = &update;
    } else {
        delete_.__union_DeleteType = SOAP_UNION__ifmap__union_PublishType_identifier;
        delete_.union_DeleteType.identifier = &ipIdent;
        snprintf(filterBuf, sizeof filterBuf, "meta:event[name=\"%s\"]", name);
        delete_.filter = filterBuf;
        publish.__union_PublishRequestType = SOAP_UNION__ifmap__union_PublishRequestType_delete_;
        publish.union_PublishRequestType.delete_ = &delete_;
    }

    ifmap__PublishRequestType publishRequest;
    publishRequest.__size_PublishRequestType = 1;
    publishRequest.__union_PublishRequestType = &publish;
    
    struct __wsdl__PublishResponse response;
    bzero(&response, sizeof response);

    code = service.__wsdl__Publish(&publishRequest, response);
    if (code != SOAP_OK) {
        soap_print_fault(service.soap, stderr);
    }
    return code == SOAP_OK ? 0 : 1;
}

#include <dom.cpp>
