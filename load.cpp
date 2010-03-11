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

//
// Load test for IF-MAP server
//

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <vector>
#include <string>
#include <sys/param.h>

#include "ifmap.nsmap"
#include "ifmapStub.h"
#include "ifmapServiceProxy.h"

static const char* g_programName;
static pid_t g_pollPid = -1;
static char g_myIp[50];
static bool g_verbose = false;
static bool g_nosub = false;
static bool g_pause = false;
static bool g_purgePublisher = false;
static int g_startIp = 0x01010101;
static int g_step = 500;
static int g_start = 0;
static char* g_clientUsername = "ifmc";
static char* g_clientPassword = "ifmc";

static void onExit(void)
{
    if (g_pollPid > 0) {
        kill(g_pollPid, SIGTERM);
    }
}

static void onSigChld(int)
{
    exit(0);
}

static void usage()
{
    fprintf(stderr, 
            "usage: %s [ --usage ] [ --help ] [ --startip <ip> ] [ --nosub ] [ --pause ] [ --purge ] [ --step step ] [ --start start ] [ --username u ] [ --password p ] url num-sessions\n",
            g_programName);
    exit(1);
}

static void help()
{
    char defaultStartIp[50];
    snprintf(defaultStartIp, sizeof defaultStartIp, "%d.%d.%d.%d", g_startIp >> 24, 
             (g_startIp >> 16) & 0xff, 
             (g_startIp >> 8) & 0xff, 
             g_startIp & 0xff);

    fprintf(stderr, 
           //1234567890123456789012345678901234567890123456789012345678901234567890
            "<url>           Server's URL, such as\n"
            "                https://1.2.3.4/dana-ws/soap/dsifmap\n"
            "                                           \n"
            "<num-sessions>  Number of sessions to start\n"
            "                                               \n"
            "--startip <ip>  Endpoint address of user000000's session.\n"
            "                Successive usernames will have successive addresses.\n"
            "                Default is %s\n"
            "                                    \n"
            "--nosub         Do not subscribe for changes to the sessions. Just\n"
            "                publish them\n"
            "                                                     \n"
            "--pause         Makes this program pause at the end\n"
            "                                           \n"
            "--purge         Purges metadata from this client's IP address before\n"
            "                starting the load\n"
            "                                    \n"
            "--step <step>   Number of sessions to start before displaying\n"
            "                statistics. Default is %d\n"
            "                                          \n"
            "--start <n>     User number to start from. Usernames have the form\n"
            "                user<nnnnnn>. Default is %d\n"
            "                                \n"
            "--username <u>  Username of IF-MAP client. Default is %s\n"
            "                                   \n"
            "--password <p>  Password of IF-MAP client. Default is %s\n"
            ,
            defaultStartIp,
            g_step,
            g_start,
            g_clientUsername,
            g_clientPassword);
    exit(1);
}

static int ifmapConnect(Service& service)
{
    service.soap->imode |= SOAP_C_UTFSTRING;
    service.soap->omode |= SOAP_C_UTFSTRING;
    service.soap->userid = g_clientUsername;
    service.soap->passwd = g_clientPassword;

    int code = soap_ssl_client_context(service.soap,
                                       SOAP_SSL_NO_AUTHENTICATION,
                                       0, 0, 0, 0, 0);
    if (code != SOAP_OK) {
        return code;
    }

    service.soap->header = soap_new_SOAP_ENV__Header(service.soap, -1);
    service.soap->header->ifmap__new_session = "";
    service.soap->header->ifmap__attach_session = 0;
    service.soap->header->ifmap__session_id = 0;
    service.soap->header->ifmap__publisher_id = 0;
    struct __wsdl__NewSessionResponse response;
    bzero(&response, sizeof response);
    return service.__wsdl__NewSession("", response);
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
    if (!g_verbose) {
        return;
    }
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
    fflush(stdout);
}

static void startPolling(const char* url, const char* sessionId)
{
    g_pollPid = fork();
    if (g_pollPid == -1) {
        perror("fork");
    }
    if (g_pollPid) {
        signal(SIGCHLD, onSigChld);
        atexit(onExit);
        return;
    }
    Service service;
    service.soap->imode |= SOAP_C_UTFSTRING | SOAP_IO_KEEPALIVE | SOAP_DOM_NODE;
    service.soap->omode |= SOAP_C_UTFSTRING | SOAP_IO_KEEPALIVE | SOAP_DOM_NODE;
    service.endpoint = url;
    service.soap->userid = g_clientUsername;
    service.soap->passwd = g_clientPassword;
    if (soap_ssl_client_context(service.soap,
                                SOAP_SSL_NO_AUTHENTICATION,
                                0, 0, 0, 0, 0)) {
        soap_print_fault(service.soap, stderr);
        exit(1);
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
        exit(1);
    }

    while (true) {
        ifmap__PollRequestType pollRequest;
        __wsdl__PollResponse pollResponse;
        code = service.__wsdl__Poll(&pollRequest, pollResponse);
        if (code) {
            soap_print_fault(service.soap, stderr);
            exit(1);
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

static void getIp(int sessionNum, char* result, int resultSize)
{
    int ip = g_startIp + sessionNum;
    snprintf(result, resultSize, "%d.%d.%d.%d", ip >> 24, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
}

static soap_dom_element*
createCapabilityElements(struct soap* soap, const std::vector<char*>& roles, int& count)
{
    soap_dom_element* save = soap->dom;
    std::vector<soap_dom_element*> elems;
    int ii;
    for (ii = 0; ii < roles.size(); ii++) {
        soap->dom = 0;
        _meta__capability capability;
        capability.name = roles[ii];
        capability.soap_out(soap, "meta:capability", 0, 0);
        elems.push_back(soap->dom);
    }

    soap_dom_element* result = 0;
    count = elems.size();
    if (count) {
        result = soap_new_xsd__anyType(soap, count);
        for (ii = 0; ii < elems.size(); ii++) {
            result[ii] = *elems[ii];
        }
    }

    soap->dom = save;
    return result;
}

static ifmap__IdentifierType*
createAccessRequestIdentifier(struct soap* soap, const char* domain, const char* name)
{
    ifmap__AccessRequestType* accessRequest = soap_new_ifmap__AccessRequestType(soap, -1);
    if (domain && *domain) {
        accessRequest->administrative_domain = soap_strdup(soap, domain);
    }
    accessRequest->name = soap_strdup(soap, name);
    ifmap__IdentifierType* identifier = soap_new_ifmap__IdentifierType(soap, -1);
    identifier->__union_IdentifierType
        = SOAP_UNION__ifmap__union_IdentifierType_access_request;
    identifier->union_IdentifierType.access_request = accessRequest;
    return identifier;
}

static ifmap__IdentifierType*
createIpAddressIdentifier(struct soap* soap, const char* domain, int type, const char* ip)
{
    ifmap__IPAddressType* ipAddr = soap_new_ifmap__IPAddressType(soap, -1);
    if (domain && *domain) {
        ipAddr->administrative_domain = soap_strdup(soap, domain);
    }
    ipAddr->type = static_cast<_ifmap__IPAddressType_type>(type);
    ipAddr->value = soap_strdup(soap, ip);
    ifmap__IdentifierType* identifier = soap_new_ifmap__IdentifierType(soap, -1);
    identifier->__union_IdentifierType = SOAP_UNION__ifmap__union_IdentifierType_ip_address;
    identifier->union_IdentifierType.ip_address = ipAddr;
    return identifier;
}

static ifmap__IdentifierType*
createIdentityIdentifier(struct soap* soap, const char* domain, const char* name,
                         int type, const char* other)
{
    ifmap__IdentityType* identity = soap_new_ifmap__IdentityType(soap, -1);
    if (domain && *domain) {
        identity->administrative_domain = soap_strdup(soap, domain);
    }
    identity->name = soap_strdup(soap, name);
    identity->type = static_cast<_ifmap__IdentityType_type>(type);
    if (other && *other) {
        identity->other_type_definition = soap_strdup(soap, other);
    }
    ifmap__IdentifierType* identifier = soap_new_ifmap__IdentifierType(soap, -1);
    identifier->__union_IdentifierType = SOAP_UNION__ifmap__union_IdentifierType_identity;
    identifier->union_IdentifierType.identity = identity;
    return identifier;
}

static ifmap__IdentifierType*
createDeviceIdentifier(struct soap* soap, int type, const char* name)
{
    ifmap__DeviceType* device = soap_new_ifmap__DeviceType(soap, -1);
    device->__union_DeviceType = type;

    char* deviceName = soap_strdup(soap, name);
    if (type == SOAP_UNION__ifmap__union_DeviceType_name) {
        device->union_DeviceType.name = deviceName;
    } else {
        device->union_DeviceType.aik_name = deviceName;
    }

    ifmap__IdentifierType* identifier = soap_new_ifmap__IdentifierType(soap, -1);
    identifier->__union_IdentifierType = SOAP_UNION__ifmap__union_IdentifierType_device;
    identifier->union_IdentifierType.device = device;
    return identifier;
}

static ifmap__MetadataListType*
createMetadataList(struct soap* soap, soap_dom_element* elems, int count)
{
    ifmap__MetadataListType* list = soap_new_ifmap__MetadataListType(soap, -1);
    list->__size = count;
    list->__any = elems;
    return list;
}

static ifmap__PublishType*
createIdentifierUpdate(struct soap* soap, ifmap__IdentifierType* identifier,
                       ifmap__MetadataListType* metadata)
{
    ifmap__PublishType* update = soap_new_ifmap__PublishType(soap, -1);
    update->__union_PublishType = SOAP_UNION__ifmap__union_PublishType_identifier;
    update->union_PublishType.identifier = identifier;
    update->metadata = metadata;
    return update;
}

static ifmap__LinkType*
createLink(struct soap* soap, ifmap__IdentifierType* identifier0,
           ifmap__IdentifierType* identifier1)
{
    ifmap__LinkType* link = soap_new_ifmap__LinkType(soap, -1);
    link->__sizeidentifier = 2;
    link->identifier = (ifmap__IdentifierType**)soap_malloc(soap, sizeof(ifmap__IdentifierType*) * 2);
    link->identifier[0] = identifier0;
    link->identifier[1] = identifier1;
    return link;
}

static ifmap__PublishType*
createLinkUpdate(struct soap* soap, ifmap__IdentifierType* identifier0,
                 ifmap__IdentifierType* identifier1,
                 ifmap__MetadataListType* metadata)
{
    ifmap__LinkType* link = createLink(soap, identifier0, identifier1);
    ifmap__PublishType* update = soap_new_ifmap__PublishType(soap, -1);
    update->__union_PublishType = SOAP_UNION__ifmap__union_PublishType_link;
    update->union_PublishType.link = link;
    update->metadata = metadata;
    return update;
}

static void startSession(Service& service, int sessionNum, const char* pubId)
{
    if (g_verbose) {
        printf("startSession %d\n", sessionNum);
        fflush(stdout);
    }
    char userName[50];
    snprintf(userName, sizeof userName, "user%06d", sessionNum);
    char device[50];
    snprintf(device, sizeof device, "device%06d", sessionNum);
    char accessRequest[50];
    snprintf(accessRequest, sizeof accessRequest, "%s:ar%06d", pubId, sessionNum);
    char ip[50];
    getIp(sessionNum, ip, sizeof ip);

    ifmap__IdentifierType* accessRequestIdent
        = createAccessRequestIdentifier(service.soap, 0, accessRequest);
    ifmap__IdentifierType* ipAddressIdent
        = createIpAddressIdentifier(service.soap, 0, _ifmap__IPAddressType_type__IPv4, ip);
    ifmap__IdentifierType* identityIdent
        = createIdentityIdentifier(service.soap, 0, userName, _ifmap__IdentityType_type__username, 0);
    ifmap__IdentifierType* myIpIdent
        = createIpAddressIdentifier(service.soap, 0, _ifmap__IPAddressType_type__IPv4, g_myIp);
    ifmap__IdentifierType* deviceIdent =
        createDeviceIdentifier(service.soap, SOAP_UNION__ifmap__union_DeviceType_name, device);
    
    // capability
    struct soap metaSoap(SOAP_XML_DOM);
    std::vector<char*> roles;
    roles.push_back("role1");
    roles.push_back("role2");
    roles.push_back("role3");
    roles.push_back("role4");
    roles.push_back("role5");
    int count;
    soap_dom_element* elems = ::createCapabilityElements(&metaSoap, roles, count);
    ifmap__MetadataListType* caps = createMetadataList(service.soap, elems, count);
    ifmap__PublishType* accessRequestUpdate
        = createIdentifierUpdate(service.soap, accessRequestIdent, caps);

    // authenticated-as
    _meta__authenticated_as authenticatedAs;
    authenticatedAs.soap_out(&metaSoap, "meta:authenticated-as", 0, 0);
    ifmap__MetadataListType authenticatedAsMetadata;
    authenticatedAsMetadata.__size = 1;
    authenticatedAsMetadata.__any = metaSoap.dom;
    metaSoap.dom = 0;
    ifmap__PublishType* authenticatedAsUpdate
        = createLinkUpdate(service.soap, accessRequestIdent, identityIdent, &authenticatedAsMetadata);
    
    // access-request-ip
    ifmap__MetadataListType accessRequestIpMetadataList;
    ifmap__PublishType* accessRequestIpUpdate = 0;
    _meta__access_request_ip accessRequestIpMetadata;
    accessRequestIpMetadata.soap_out(&metaSoap, "meta:access-request-ip", 0, 0);
    accessRequestIpMetadataList.__size = 1;
    accessRequestIpMetadataList.__any = metaSoap.dom;
    metaSoap.dom = 0;
    accessRequestIpUpdate
        = createLinkUpdate(service.soap, accessRequestIdent, ipAddressIdent, &accessRequestIpMetadataList);

    // access-request-device
    _meta__access_request_device accessRequestDeviceMetadata;
    accessRequestDeviceMetadata.soap_out(&metaSoap, "meta:access-request-device", 0, 0);
    ifmap__MetadataListType accessRequestDeviceMetadataList;
    accessRequestDeviceMetadataList.__size = 1;
    accessRequestDeviceMetadataList.__any = metaSoap.dom;
    metaSoap.dom = 0;
    ifmap__PublishType* accessRequestDeviceUpdate
        = createLinkUpdate(service.soap, accessRequestIdent, deviceIdent, &accessRequestDeviceMetadataList);

    // authenticated-by
    _meta__authenticated_by authenticatedByMetadata;
    authenticatedByMetadata.soap_out(&metaSoap, "meta:authenticated-by", 0, 0);
    ifmap__MetadataListType authenticatedByMetadataList;
    authenticatedByMetadataList.__size = 1;
    authenticatedByMetadataList.__any = metaSoap.dom;
    metaSoap.dom = 0;
    ifmap__PublishType* authenticatedByUpdate
        = createLinkUpdate(service.soap, accessRequestIdent, myIpIdent, &authenticatedByMetadataList);

    __ifmap__union_PublishRequestType updateArray[7];
    int numUpdates = 0;
    updateArray[numUpdates].__union_PublishRequestType = SOAP_UNION__ifmap__union_PublishRequestType_update;
    updateArray[numUpdates++].union_PublishRequestType.update = accessRequestUpdate;
    updateArray[numUpdates].__union_PublishRequestType = SOAP_UNION__ifmap__union_PublishRequestType_update;
    updateArray[numUpdates++].union_PublishRequestType.update = authenticatedAsUpdate;
    updateArray[numUpdates].__union_PublishRequestType = SOAP_UNION__ifmap__union_PublishRequestType_update;
    updateArray[numUpdates++].union_PublishRequestType.update = accessRequestIpUpdate;
    updateArray[numUpdates].__union_PublishRequestType = SOAP_UNION__ifmap__union_PublishRequestType_update;
    updateArray[numUpdates++].union_PublishRequestType.update = accessRequestDeviceUpdate;
    updateArray[numUpdates].__union_PublishRequestType = SOAP_UNION__ifmap__union_PublishRequestType_update;
    updateArray[numUpdates++].union_PublishRequestType.update = authenticatedByUpdate;

    ifmap__PublishRequestType publishRequest;
    publishRequest.__size_PublishRequestType = sizeof updateArray/sizeof *updateArray;
    publishRequest.__union_PublishRequestType = updateArray;

    struct __wsdl__PublishResponse response;
    bzero(&response, sizeof response);
    int code = service.__wsdl__Publish(&publishRequest, response);
    if (code != 0) {
        soap_print_fault(service.soap, stderr);
        exit(1);
    }

    if (g_nosub) {
        return;
    }

    _ifmap__SubscribeRequestType_update update;
    std::string name("o:");
    name += accessRequest;
    update.name = const_cast<char*>(name.c_str());
    update.identifier = accessRequestIdent;
    update.match_links = "meta:ip-mac or meta:access-request-ip or meta:access-request-mac"
        " or meta:access-request-device or meta:authenticated-as";
    update.result_filter = "meta:ip-mac or meta:event";
    update.max_depth = "3";

    ifmap__SubscribeRequestType subscribeRequest;
    subscribeRequest.__size_SubscribeRequestType = 1;
    __ifmap__union_SubscribeRequestType req;
    req.__union_SubscribeRequestType = SOAP_UNION__ifmap__union_SubscribeRequestType_update;
    req.union_SubscribeRequestType.update = &update;
    subscribeRequest.__union_SubscribeRequestType = &req;

    __wsdl__SubscribeResponse subscribeResponse;
    code = service.__wsdl__Subscribe(&subscribeRequest, subscribeResponse);
    if (code != 0) {
        soap_print_fault(service.soap, stderr);
        exit(1);
    }
}

static void purgePublisher(Service& service, const char* publisherId)
{
    timeval start;
    gettimeofday(&start, 0);

    ifmap__PurgePublisherRequestType purgePublisherRequest;
    purgePublisherRequest.soap = service.soap;
    purgePublisherRequest.publisher_id = soap_strdup(service.soap, publisherId);
    struct __wsdl__PurgePublisherResponse response;
    bzero(&response, sizeof response);
    int code = service.__wsdl__PurgePublisher(&purgePublisherRequest, response);
    if (code != SOAP_OK) {
        fprintf(stderr, "Could not purge:\n");
        soap_print_fault(service.soap, stderr);
    }
    timeval done;
    gettimeofday(&done, 0);
    
    timeval diff;
    timersub(&done, &start, &diff);

    int msecs = diff.tv_sec * 1000 + diff.tv_usec / 1000;
    float total = (float)msecs / 1000.0;

    printf("Time to purge: %g\n", total);
    fflush(stdout);
}

static void loadTest(const char* url, int numSessions)
{
    Service service;
    service.endpoint = url;
    service.soap->imode |= SOAP_IO_KEEPALIVE;
    service.soap->omode |= SOAP_IO_KEEPALIVE;

    int code = ifmapConnect(service);
    if (code != SOAP_OK) {
        fprintf(stderr, "Could not connect to %s:\n", url);
        soap_print_fault(service.soap, stderr);
        exit(1);
    }
    const char* publisherId = service.soap->header->ifmap__publisher_id;
    service.soap->header->ifmap__publisher_id = 0;
    
    printf("got session id: %s\n", service.soap->header->ifmap__session_id);
    fflush(stdout);
    if (g_purgePublisher) {
        purgePublisher(service, publisherId);
    }
    startPolling(url, service.soap->header->ifmap__session_id);

    timeval start;
    gettimeofday(&start, 0);

    timeval stepStart = start;

    for (int ii = 0; ii < numSessions; ii++) {
        startSession(service, ii + g_start, publisherId);
        if ((ii + 1) % g_step == 0) {
            timeval stepDone;
            gettimeofday(&stepDone, 0);
            timeval diff;
            timersub(&stepDone, &stepStart, &diff);

            int msecs = diff.tv_sec * 1000 + diff.tv_usec / 1000;
            float total = (float)msecs / 1000.0;
            printf("%d sessions so far\n", ii + 1);
            printf("step: Time to start %d sessions: %g\n", g_step, total);
            printf("That's %g sessions/second.\n", (float)g_step / total);
            fflush(stdout);
            stepStart = stepDone;
        }
    }
    printf("Done with sessions\n");
    timeval done;
    gettimeofday(&done, 0);
    
    timeval diff;
    timersub(&done, &start, &diff);

    int msecs = diff.tv_sec * 1000 + diff.tv_usec / 1000;
    float total = (float)msecs / 1000.0;
    printf("Time to start %d sessions: %g\n", numSessions, total);
    printf("That's %g sessions/second.\n", (float)numSessions / total);
    fflush(stdout);

    if (g_pause) {
        pause();
    }
}

int main(int argc, char* argv[])
{
    g_programName = argv[0];

    while (--argc) {
        if (**++argv != '-') {
            break;
        }
        if (argc < 1) {
            usage();
        }
        if (strcmp(*argv, "--verbose") == 0) {
            g_verbose = true;
        } else if (strcmp(*argv, "--startip") == 0) {
            argc--;
            argv++;
            int num0, num1, num2, num3;
            if (sscanf(*argv, "%d.%d.%d.%d", &num0, &num1, &num2, &num3) != 4) {
                fprintf(stderr, "Unable to parse IP address %s\n", *argv);
                exit(1);
            }
            g_startIp = (num0 << 24) | (num1 << 16) | (num2 << 8) | num3;
        } else if (strcmp(*argv, "--nosub") == 0) {
            g_nosub = true;
        } else if (strcmp(*argv, "--pause") == 0) {
            g_pause = true;
        } else if (strcmp(*argv, "--purge") == 0) {
            g_purgePublisher = true;
        } else if (strcmp(*argv, "--step") == 0) {
            argc--;
            argv++;
            g_step = atoi(*argv);
            if (g_step <= 0) {
                fprintf(stderr, "step must be greater than 0\n");
                exit(1);
            }
        } else if (strcmp(*argv, "--start") == 0) {
            argc--;
            argv++;
            g_start = atoi(*argv);
            if (g_start < 0) {
                fprintf(stderr, "start must be greater than or equal to 0\n");
                exit(1);
            }
        } else if (strcmp(*argv, "--username") == 0) {
            argc--;
            argv++;
            g_clientUsername = *argv;
        } else if (strcmp(*argv, "--password") == 0) {
            argc--;
            argv++;
            g_clientPassword = *argv;
        } else if (strcmp(*argv, "--help") == 0 ||
                   strcmp(*argv, "-h") == 0) {
            help();
        } else {
            usage();
        }
    }
        
    if (argc != 2) {
        usage();
    }

    const char* url = argv[0];
    int numSessions = atoi(argv[1]);

    char hostName[MAXHOSTNAMELEN];
    if (gethostname(hostName, sizeof hostName) == -1) {
        perror("gethostname");
        return 1;
    }
    hostent* ent = gethostbyname(hostName);
    if (!ent) {
        fprintf(stderr, "Can't resolve my hostname: %s\n", hostName);
        return 1;
    }
    int myIp;
    bcopy(ent->h_addr, &myIp, sizeof myIp);
    myIp = ntohl(myIp);
    snprintf(g_myIp, sizeof g_myIp, "%d.%d.%d.%d",
             myIp >> 24, (myIp >> 16) & 0xff, (myIp >> 8) & 0xff, myIp & 0xff);
    loadTest(url, numSessions);
    return 0;
}

#include <dom.cpp>
