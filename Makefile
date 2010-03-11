#
# Copyright 2008 Juniper Networks, Inc. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# o Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# o Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the  
#   distribution.
# o Neither the name of Juniper Networks nor the names of its
#   contributors may be used to endorse or promote products 
#   derived from this software without specific prior written 
#   permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

TARGETS = ip-mac event poll load

all: $(TARGETS)

SOAPCPP2_FILES := \
	ifmap.nsmap \
	ifmapC.cpp \
	ifmapClient.cpp \
	ifmapClientLib.cpp \
	ifmapH.h \
	ifmapServer.cpp \
	ifmapServerLib.cpp \
	ifmapServiceObject.h \
	ifmapServiceProxy.h \
	ifmapStub.h \
	*.xml

IP_MAC_OBJS = ip-mac.o connect.o ifmapClient.o ifmapC.o
EVENT_OBJS = event.o connect.o ifmapClient.o ifmapC.o
POLL_OBJS = poll.o connect.o ifmapClient.o ifmapC.o
LOAD_OBJS = load.o ifmapClient.o ifmapC.o

ifmap.gsoap.h: ifmap.wsdl ifmap-base-1.0v23.xsd ifmap-metadata-1.0v23.xsd \
	ifmap.dat ifmap.patch
	wsdl2h -g -s -d -tifmap.dat ifmap.wsdl -o$@
	patch < ifmap.patch

$(SOAPCPP2_FILES): ifmap.gsoap.h ifmapC.cpp.patch
	soapcpp2 $(SOAPCPP2FLAGS) -n -pifmap $<
	patch < ifmapC.cpp.patch

$(IP_MAC_OBJS): $(SOAPCPP2_FILES)
$(EVENT_OBJS): $(SOAPCPP2_FILES)
$(POLL_OBJS): $(SOAPCPP2_FILES)

ip-mac: $(IP_MAC_OBJS)
	g++ -o $@ $(IP_MAC_OBJS) $(LDFLAGS) -lgsoapssl++ -lssl -lcrypto

event: $(EVENT_OBJS)
	g++ -o $@ $(EVENT_OBJS) $(LDFLAGS) -lgsoapssl++ -lssl -lcrypto

poll: $(POLL_OBJS)
	g++ -o $@ $(POLL_OBJS) $(LDFLAGS) -lgsoapssl++ -lssl -lcrypto

load: $(LOAD_OBJS)
	g++ -o $@ $(LOAD_OBJS) $(LDFLAGS) -lgsoapssl++ -lssl -lcrypto

DIRT := ifmap.gsoap.h $(SOAPCPP2_FILES) *.o $(TARGETS)

clean:
	rm -f $(DIRT)
