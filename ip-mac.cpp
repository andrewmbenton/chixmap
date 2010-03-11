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
#include "ifmap.nsmap"
#include "ifmapServiceProxy.h"
#include "connect.h"

static void usage()
{
    fprintf(stderr, "usage: ip-mac update|delete ifmap-server-url ip-address mac-address [ user password ]\n");
    exit(1);
}

int main(int argc, char* argv[])
{
    if (argc != 5 && argc != 7) {
        usage();
    }

    char* op = argv[1];
    if (strcmp(op, "update") != 0 && strcmp(op, "delete") != 0) {
        usage();
    }
    char* url = argv[2];
    char* ipArg = argv[3];
    char* macArg = argv[4];
    char* user = 0;
    char* password = 0;
    if (argc == 7) {
        user = argv[5];
        password = argv[6];
    }

    Service service;
    service.endpoint = url;
    if (user && password) {
        service.soap->userid = user;
        service.soap->passwd = password;
    }
    int code = ifmapConnect(service);
    if (code != SOAP_OK) {
        soap_print_fault(service.soap, stderr);
        return 1;
    }
    
    service.soap->header->ifmap__publisher_id = 0;

    ifmap__IPAddressType ipAddr;
    ipAddr.type = _ifmap__IPAddressType_type__IPv4;
    ipAddr.value = ipArg;
    ifmap__IdentifierType ipIdent;
    ipIdent.__union_IdentifierType = SOAP_UNION__ifmap__union_IdentifierType_ip_address;
    ipIdent.union_IdentifierType.ip_address = &ipAddr;

    ifmap__MACAddressType macAddr;
    macAddr.value = macArg;
    ifmap__IdentifierType macIdent;
    macIdent.__union_IdentifierType = SOAP_UNION__ifmap__union_IdentifierType_mac_address;
    macIdent.union_IdentifierType.mac_address = &macAddr;
    
    ifmap__IdentifierType* idents[] = { &ipIdent, &macIdent };
    ifmap__LinkType link;
    link.__sizeidentifier = 2;
    link.identifier = idents;
    
    struct soap metaSoap(SOAP_XML_DOM);
    _meta__ip_mac ipMac;
    ifmap__MetadataListType metadata;
    ifmap__PublishType update;
    ifmap__DeleteType delete_;
    
    __ifmap__union_PublishRequestType publish;
    if (strcmp(op, "update") == 0) {
        update.__union_PublishType = SOAP_UNION__ifmap__union_PublishType_link;
        update.union_PublishType.link = &link;
        ipMac.soap_out(&metaSoap, "meta:ip-mac", 0, 0);
        metadata.__size = 1;
        metadata.__any = metaSoap.dom;
        update.metadata = &metadata;
        publish.__union_PublishRequestType = SOAP_UNION__ifmap__union_PublishRequestType_update;
        publish.union_PublishRequestType.update = &update;
    } else {
        delete_.__union_DeleteType = SOAP_UNION__ifmap__union_PublishType_link;
        delete_.union_DeleteType.link = &link;
        delete_.filter = "meta:ip-mac";
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
