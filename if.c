/**
 * (C) Copyright 2014 Faraday Technology
 * BingYao Luo <bjluo@faraday-tech.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "common.h"

struct ARP_entry 
{
	char ip[16];
	unsigned char mac[6];
	char intf[6];
};

#define ARP_TABLE_ENTRIES	5

static struct ARP_entry arp_table[ARP_TABLE_ENTRIES];
int arp_valid = 0;

void get_arp(void)
{
	int i=0, j;
	const char filename[] = "/proc/net/arp";
	char ipstr[16], macstr[18], intf[6], output[128];
	int mac[6];
	FILE *file;

	if (arp_valid)
		return;

	file = fopen(filename, "r");
	if (file) {
		char line [256];

		//remove the first line
		//IP address       HW type     Flags       HW address            Mask     Device
		if (!fgets(line, sizeof(line), file))
			return;

		while (fgets(line, sizeof(line), file))
		{
			char  a,b,c;

			if ( sscanf(line, "%s %s %s %s %s %s", ipstr, &a, &b, macstr, &c, intf) < 10 )
			{
				if ( i < ARP_TABLE_ENTRIES )
				{
					snprintf(arp_table[i].ip, 16, "%s", ipstr);
					snprintf(arp_table[i].intf, 6, "%s", intf);

					//convert mac string to char byte
					sscanf(macstr, "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
					for(j=0; j< 6; j++)
						arp_table[i].mac[j] = (unsigned char) mac[j];

					printf("IP %s Mac %02x:%02x:%02x:%02x:%02x:%02x Dev %s\n",arp_table[i].ip, 
						arp_table[i].mac[0], arp_table[i].mac[1], arp_table[i].mac[2],
						arp_table[i].mac[3], arp_table[i].mac[4], arp_table[i].mac[5], 
						arp_table[i].intf);

					i++;
				}
			}
		}
	} else {
		perror(filename);
	}

	arp_valid = 1;
}

static struct ARP_entry *get_arp_entry(const char *name)
{
	int i;

	get_arp();

	for (i=0; i < ARP_TABLE_ENTRIES; i++) {
		if (!strcmp(name, arp_table[i].intf)) {
			return &arp_table[i];	
		}
	}

	return NULL;
}

int get_dest_macaddr(const char *name, unsigned char *mac)
{
	struct ARP_entry *arp;

	arp = get_arp_entry(name);
	if (!arp) {
		printf("No ARP entry for dev %s\n", name);
		return -1;
	}

        memcpy(mac, arp->mac, 6);
	return 0;
}

int get_dest_ipaddr(const char *name, char *addr)
{
	struct ARP_entry *arp;

	arp = get_arp_entry(name);
	if (!arp) {
		printf("No ARP entry for dev %s\n", name);
		return -1;
	}

        memcpy(addr, arp->ip, 16);
	return 0;
}

int get_interface_macaddr(const char *name, unsigned char *mac)
{
        struct ifreq ifreq;
        int err, fd;

        memset(&ifreq, 0, sizeof(ifreq));
        strcpy(ifreq.ifr_name, name);

        fd = socket(PF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
                printf("socket failed: %m\n");
                return -1;
        }

        err = ioctl(fd, SIOCGIFHWADDR, &ifreq);
        if (err < 0) {
                printf("ioctl SIOCGIFHWADDR failed: %m\n");
                close(fd);
                return -1;
        }

        memcpy(mac, ifreq.ifr_hwaddr.sa_data, 6);

        close(fd);
        return 0;
}

int get_interface_ipaddr(const char *name, int family, uint8_t *addr, int len)
{
	struct ifaddrs *ifaddr, *i;
	int copy_len, result = -1;
	void *copy_from;
	if (getifaddrs(&ifaddr) == -1) {
		printf("getifaddrs failed: %m\n");
		return -1;
	}
	for (i = ifaddr; i; i = i->ifa_next) {
		if (i->ifa_addr && family == i->ifa_addr->sa_family &&
			strcmp(name, i->ifa_name) == 0)
		{
			switch (family) {
			case AF_INET:
				copy_len = 4;
				copy_from = &((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr;
				break;
			case AF_INET6:
				copy_len = 16;
				copy_from = &((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr.s6_addr;
				break;
			default:
				continue;
			}
			if (copy_len > len)
				copy_len = len;
			memcpy(addr, copy_from, copy_len);
			result = copy_len;
			break;
		}
	}
	freeifaddrs(ifaddr);
	return result;
}
