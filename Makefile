###
 # (C) Copyright 2014 Faraday Technology
 # BingYao Luo <bjluo@faraday-tech.com>
 #
 # This program is free software; you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation; either version 2 of the License, or
 # (at your option) any later version.
 #
 # This program is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 # GNU General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this program; if not, write to the Free Software
 # Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 ##

#CROSS_COMPILE := arm-none-linux-gnueabi-

CC := $(CROSS_COMPILE)gcc

ifeq ($(OS),Windows_NT)
	PCAP_PATH := ./pcap/lib
	CFLAGS := -g -O -I ./pcap/include
	LDFLAGS := -L$(PCAP_PATH) -lwpcap
else
	LDLIBS	:= -lpcap -lpthread
ifeq ($(CC), gcc)
	PCAP_PATH := $(HOME)/working/source/libpcap-1.4.0/
	LDFLAGS :=
	PREFIX := x86
else
	PCAP_PATH := $(HOME)/working/source/libpcap-1.4.0-armv5
	LDLIBS	+= -lrt
	LDFLAGS := -static
	PREFIX := armv5
endif
	CFLAGS := -g -O -I $(PCAP_PATH)
	LDFLAGS += -L$(PCAP_PATH) $(LDLIBS)
endif

PRG	= $(addprefix $(PREFIX)/, txPkt rxPkt)
OBJ	= txPckt.o rxPckt.o if.o print.o
SRC	= $(OBJ:.o=.c)
DEPEND	= $(OBJ:.o=.d)

.PHONY: all
all: $(PRG)

%txPkt: $(filter-out rxPckt.c, $(SRC))
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%rxPkt: $(filter-out txPckt.c, $(SRC))
	@mkdir -p $(@D)
	${CC} ${CFLAGS} -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o $(PRG)

