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
#include <unistd.h>
#include <signal.h>
#include "ifmap.nsmap"
#include "ifmapStub.h"
#include "ifmapServiceProxy.h"
#include "connect.h"

using namespace std;

static pid_t g_pollPid = -1;
static char* g_user = 0;
static char* g_password = 0;

static void onExit(void)
{
    if (g_pollPid > 0) {
        kill(SIGTERM, g_pollPid);
    }
}

static void onSigChld(int)
{
    exit(0);
}

static void displayMetadata(struct soap_dom_element& elem)
{
    switch (elem.type) {
    case SOAP_TYPE__meta__capability:
        {
            _meta__capability* cap = (_meta__capability*)elem.node;
            printf("Capability: %s\n", cap->name);
        }
        break;
    case SOAP_TYPE__meta__event:
        {
            _meta__event* event = (_meta__event*)elem.node;
            printf("Event: %s\n", event->name);
            break;
        }
    }
}

static void displaySearchResult(ifmap__SearchResultType& result)
{
    printf("\n\nSearch result for %s\n", result.name);
    int ii;
    for (ii = 0; ii < result.__sizeidentifierResult; ii++) {
        // Look for IP address and identity identifiers
        // Look for access-request identifier, and get capabilities
        ifmap__IdentifierType* ident = result.identifierResult[ii]->identifier;
        switch (ident->__union_IdentifierType) {
        case SOAP_UNION__ifmap__union_IdentifierType_access_request:
            break;
        case SOAP_UNION__ifmap__union_IdentifierType_identity:
            printf("userName: %s\n", ident->union_IdentifierType.identity->name);
            break;
        case SOAP_UNION__ifmap__union_IdentifierType_ip_address:
            printf("IP Address: %s\n", ident->union_IdentifierType.ip_address->value);
            break;
        case SOAP_UNION__ifmap__union_IdentifierType_mac_address:
            printf("MAC Address: %s\n", ident->union_IdentifierType.mac_address->value);
            break;
        case SOAP_UNION__ifmap__union_IdentifierType_device:
            if (ident->union_IdentifierType.device->__union_DeviceType == SOAP_UNION__ifmap__union_DeviceType_aik_name) {
                printf("AIK Device: %s\n", ident->union_IdentifierType.device->union_DeviceType.aik_name);
            } else if (ident->union_IdentifierType.device->__union_DeviceType == SOAP_UNION__ifmap__union_DeviceType_name) {
                printf("Device: %s\n", ident->union_IdentifierType.device->union_DeviceType.aik_name);
            }
            break;
        }
        ifmap__MetadataListType* md = result.identifierResult[ii]->metadata;
        if (!md) {
            continue;
        }
        for (int jj = 0; jj < md->__size; jj++) {
            displayMetadata(*(md->__any + jj));
        }
    }
    for (ii = 0; ii < result.__sizelinkResult; ii++) {
        ifmap__MetadataListType* md = result.linkResult[ii]->metadata;
        if (!md) {
            continue;
        }
        for (int jj = 0; jj < md->__size; jj++) {
            displayMetadata(*(md->__any + jj));
        }
    }
    printf("\n\n-> ");
    fflush(stdout);
}

static void runPollProc(char* url, char* sessionId)
{
    Service service;
    service.soap->imode |= SOAP_C_UTFSTRING | SOAP_IO_KEEPALIVE | SOAP_DOM_NODE;
    service.soap->omode |= SOAP_C_UTFSTRING | SOAP_IO_KEEPALIVE | SOAP_DOM_NODE;
    if (g_user && g_password) {
        service.soap->userid = g_user;
        service.soap->passwd = g_password;
    }
    service.endpoint = url;
    if (soap_ssl_client_context(service.soap,
                                SOAP_SSL_NO_AUTHENTICATION,
                                0, 0, 0, 0, 0)) {
        soap_print_fault(service.soap, stderr);
        return;
    }

    struct __wsdl__AttachSessionResponse response;
    bzero(&response, sizeof response);

    SOAP_ENV__Header header;
    bzero(&header, sizeof header);
    header.ifmap__attach_session = const_cast<char*>(sessionId);
    service.soap->header = &header;

    int code = service.__wsdl__AttachSession("", response);
    if (code) {
        soap_print_fault(service.soap, stderr);
        return;
    }
    
    while (true) {
        ifmap__PollRequestType pollRequest;
        __wsdl__PollResponse pollResponse;
        code = service.__wsdl__Poll(&pollRequest, pollResponse);
        if (code) {
            soap_print_fault(service.soap, stderr);
            return;
        }
        if (pollResponse.ifmap__response) {
            if (pollResponse.ifmap__response->__union_ResponseType !=
                SOAP_UNION__ifmap__union_ResponseType_pollResult) {
                fprintf(stderr, "Unexpected result type: %d",
                        pollResponse.ifmap__response->__union_ResponseType);
                continue;
            }
            ifmap__PollResultType* pollResult = pollResponse.ifmap__response->union_ResponseType.pollResult;
            for (int ii = 0; ii < pollResult->__size_PollResultType; ii++) {
                if (pollResult->__union_PollResultType[ii].__union_PollResultType
                    == SOAP_UNION__ifmap__union_PollResultType_searchResult) {
                    displaySearchResult(*pollResult->__union_PollResultType[ii].union_PollResultType.searchResult);
                }
            }
        }
    }
}

static void subscribe(Service& service, char* ipStr)
{
    _ifmap__SubscribeRequestType_update update;
    ifmap__IdentifierType identifier;
    identifier.__union_IdentifierType = SOAP_UNION__ifmap__union_IdentifierType_ip_address;

    ifmap__IPAddressType ip;
    ip.value = ipStr;
    ip.type = _ifmap__IPAddressType_type__IPv4;

    identifier.union_IdentifierType.ip_address = &ip;

    update.identifier = &identifier;
    update.name = ipStr;
    update.match_links = "meta:authenticated-as or meta:access-request-ip or"
        " meta:access-request-device or meta:ip-mac or meta:access-request-mac";

    ifmap__SubscribeRequestType subscribeRequest;
        subscribeRequest.__size_SubscribeRequestType = 1;

    __ifmap__union_SubscribeRequestType req;
    req.__union_SubscribeRequestType = SOAP_UNION__ifmap__union_SubscribeRequestType_update;
    req.union_SubscribeRequestType.update = &update;

    subscribeRequest.__union_SubscribeRequestType = &req;

    __wsdl__SubscribeResponse subscribeResponse;

    int code = service.__wsdl__Subscribe(&subscribeRequest, subscribeResponse);
    if (code) {
        soap_print_fault(service.soap, stderr);
        exit(1);
    }
}

static void unsubscribe(Service& service, char* ipStr)
{
    ifmap__DeleteSearchRequestType deleteSearchRequest;
    deleteSearchRequest.name = ipStr;

    ifmap__SubscribeRequestType subscribeRequest;
    subscribeRequest.__size_SubscribeRequestType = 1;

    __ifmap__union_SubscribeRequestType req;
    req.__union_SubscribeRequestType = SOAP_UNION__ifmap__union_SubscribeRequestType_delete_;
    req.union_SubscribeRequestType.delete_ = &deleteSearchRequest;

    subscribeRequest.__union_SubscribeRequestType = &req;
    
    __wsdl__SubscribeResponse subscribeResponse;

    int code = service.__wsdl__Subscribe(&subscribeRequest, subscribeResponse);
    if (code) {
        soap_print_fault(service.soap, stderr);
        exit(1);
    }
}

int main(int argc, char* argv[])
{
    if (argc != 2 && argc != 4) {
        fprintf(stderr, "usage: poll url [ user password ]\n");
        return 1;
    }

    char* url = argv[1];
    if (argc == 4) {
        g_user = argv[2];
        g_password = argv[3];
    }

    Service service;
    service.endpoint = url;
    if (g_user && g_password) {
        service.soap->userid = g_user;
        service.soap->passwd = g_password;
    }
    service.soap->imode |= SOAP_IO_KEEPALIVE;
    service.soap->omode |= SOAP_IO_KEEPALIVE;
    int code = ifmapConnect(service);
    if (code != SOAP_OK) {
        soap_print_fault(service.soap, stderr);
        return 1;
    }
    service.soap->header->ifmap__publisher_id = 0;
    
    printf("got session id: %s\n", service.soap->header->ifmap__session_id);

    g_pollPid = fork();
    if (g_pollPid == -1) {
        perror("fork");
        exit(1);
    }
    if (g_pollPid == 0) {
        runPollProc(url, service.soap->header->ifmap__session_id);
        return 0;
    } else {
        signal(SIGCHLD, onSigChld);
        atexit(onExit);
        printf("Enter commands, 1 per line:\n");
        printf("subscribe ip: adds IP address \"ip\" to identifiers being polled\n");
        printf("unsubscribe ip: removes IP address \"ip\" from identifiers being polled\n");

        while (true) {
            printf("-> ");
            fflush(stdout);

            char buf[100];
            if (!fgets(buf, sizeof buf, stdin)) {
                break;
            }
            char* cmd = buf;
            char* ip = strchr(buf, ' ');
            if (!ip) {
                fprintf(stderr, "Parse error!\n");
                continue;
            }
            *ip++ = '\0';
            char* nl = strchr(ip, '\n');
            if (nl) {
                *nl = '\0';
            }
            if (strcmp(cmd, "subscribe") == 0) {
                subscribe(service, ip);
            } else if (strcmp(cmd, "unsubscribe") == 0) {
                unsubscribe(service, ip);
            } else {
                fprintf(stderr, "\"%s\" is not a valid command. Valid comands are \"subscribe\" and \"unsubscribe\".", cmd);
                continue;
            }
        }
    }
    return 0;
}

#include <dom.cpp>
