############################################################################
# apps/examples/tcpecho/Makefile
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.  The
# ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.
#
############################################################################

include $(APPDIR)/Make.defs

CFLAGS += -DWOLFSSL_USER_SETTINGS

# Discover built-in application info
ifeq ($(CONFIG_EXAMPLES_WOLFSSL_CLIENT_SERVER),y)

PROGNAME  += wolfssl_server_client
PRIORITY  += 100
STACKSIZE += 16384
MODULE += $(CONFIG_EXAMPLES_WOLFSSL)

MAINSRC += wolfssl-examples/embedded/tls-client-server.c

endif

ifeq ($(CONFIG_EXAMPLES_WOLFSSL_CLIENT),y)

PROGNAME  += wolfssl_client
PRIORITY  += 100
STACKSIZE += 16384
MODULE += $(CONFIG_EXAMPLES_WOLFSSL)

MAINSRC += wolfssl-examples/embedded/tls-sock-client.c

endif

ifeq ($(CONFIG_EXAMPLES_WOLFSSL_SERVER),y)

PROGNAME  += wolfssl_client
PRIORITY  += 100
STACKSIZE += 16384
MODULE += $(CONFIG_EXAMPLES_WOLFSSL)

MAINSRC += wolfssl-examples/embedded/tls-sock-server.c

endif

include $(APPDIR)/Application.mk
