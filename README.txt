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

Sample IF-MAP client code.

To build the examples you need to have gsoap and openssl headers
and libraries installed. You must also have the gsoap wsdl2h
and soapcpp2 commands in PATH.

If any of these items are in non-standard locations, use command
line arguments to pass locations to make, like this:

  PATH="..." SOAPCPP2FLAGS=-I"..." CPPFLAGS="-g -I"..." LDFLAGS="..." make all

It is extremely important that the same -D flags used to compile
the gsoap library are passed to the compiler when building these
sources. This can also be done using the make command line, like
this:

  PATH="..." SOAPCPP2FLAGS=-I"..." CPPFLAGS="-DWITH_DOM -DWITH_OPENSSL -g -I"..." LDFLAGS="..." make all

Makefile assumes you're using the C++/openssl version of the
gsoap libraries. C++ is required to compile this code, and
SSL is required for IF-MAP. This means that at the very
least -DWITH_OPENSSL must be used.

Sample code requires two files from the gsoap distribution
that do not get installed by default:

  soapcpp2/import/dom.h
  soapcpp2/dom.cpp

These files should be copied to a directory in the system
INCLUDE path.


Sample code compiles two binaries:

ip-mac: used to publish and delete ip-mac link metadata between
IP Address an MAC Address identifiers.

event: used to publish and delete event metadata on identifiers.


This version of the sample code is not yet compliant with the
IF-MAP spec because it does not support authentication.


This sample code was tested on MacOSX with gsoap 2.7.9l. gsoap was
configured using the command:

./configure --enable-debug --prefix=/sw --disable-strtof --disable-namespaces CPPFLAGS="-g -DWITH_DOM"

After building and installing gsoap, sample code was then compiled
using the command:

make SOAPCPP2FLAGS=-I/sw/include CPPFLAGS="-g -DWITH_OPENSSL -DWITH_DOM -I/sw/include" LDFLAGS=-L/sw/lib
