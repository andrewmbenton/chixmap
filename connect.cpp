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

#include "connect.h"
#include <stdio.h>
#include "ifmapServiceProxy.h"

int ifmapConnect(Service& service)
{
    service.soap->imode |= SOAP_C_UTFSTRING | SOAP_IO_KEEPALIVE;
    service.soap->omode |= SOAP_C_UTFSTRING | SOAP_IO_KEEPALIVE;

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
