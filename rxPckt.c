/**
 * (C) Copyright 2013 Faraday Technology
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

#include "version.h"
#include "common.h"

#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


void
got_packet(u_char * args, const struct pcap_pkthdr *header,
	   const u_char * packet);

extern void print_payload(const u_char * payload, int len, FILE * fp);

pcap_t *handle;
char my_mac_addr[ETHER_ADDR_LEN] = { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 };
int verbose = 0;

/*
 * dissect/print packet
 */
void
got_packet(u_char * args, const struct pcap_pkthdr *pkthdr,
	   const u_char * packet)
{
	struct ethhdr eth;
	struct iphdr iph;
	struct tcphdr tcph;
	const char *payload;	/* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	/* define ethernet header */
	memcpy(&eth, packet, sizeof(struct ethhdr));
	if (eth.h_proto != htons(0x0800)) {
		printf("   * Not IPv4 packet\n");
		return;
	}

	/* define/compute ip header offset */
	memcpy(&iph, (packet + IPHDR_OFFSET), sizeof(struct iphdr));
	size_ip = iph.ihl * 4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	size_payload = ntohs(iph.tot_len) - size_ip;

	/* print source and destination IP addresses */
	printf("  Src: %s, ", inet_ntoa( *(struct in_addr *) &iph.saddr));
	printf("Dst: %s, ", inet_ntoa( *(struct in_addr *) &iph.daddr));

	/* determine protocol */
	switch (iph.protocol) {
	case IPPROTO_TCP:
		printf("Protocol: TCP\n");

		memcpy(&tcph, (packet + TCPHDR_OFFSET), sizeof(struct tcphdr));
		size_tcp = tcph.doff * 4;
		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
		/* compute tcp payload (segment) size */
		size_payload -= size_tcp;

		printf("  Src port: %d, Dst port: %d, seq %d\n",
			ntohs(tcph.source), ntohs(tcph.dest), ntohl(tcph.seq));
		break;
	case IPPROTO_UDP:
		printf("Protocol: UDP\n");
		return;
	case IPPROTO_ICMP:
		printf("Protocol: ICMP\n");
		return;
	case IPPROTO_IP:
		printf("Protocol: IP\n");
		return;
	default:
		memcpy(&tcph, (packet + TCPHDR_OFFSET), sizeof(struct tcphdr));
		printf("Protocol: unknown, seq %d\n", ntohl(tcph.seq));
		return;
	}

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *) (packet + PAYLOAD_OFFSET);

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if ((verbose == 2) && (size_payload > 0)) {
		printf("  Payload (%d bytes):\n", size_payload);
		//print_payload(payload, size_payload, NULL);
		print_payload((const char *)packet, ntohs(iph.tot_len) + 14, NULL);
	}
	return;
}

/*--------------------------------------------------------------------*/
/*--- checksum - standard 1s complement checksum                   ---*/
/*--------------------------------------------------------------------*/
unsigned short verify_checksum(void *b, int len)
{
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result;

	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(unsigned char *)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = sum;
	return result;
}

static void usage(void)
{
	printf("\n"
	       "usage: rxPckt [OPTION] [ifname]\n"
	       "\n"
	       "[OPTION]\n"
	       "    -v <level> : dump packet content to console\n"
	       "    	0 : not dump any messages\n"
	       "    	1 : dump simple information\n"
	       "    	2 : dump the whole packet content\n"
	       "    [ifname] : network interface to send/receive packet(s)\n");
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char dev[20];
	bpf_u_int32 mask;	/* subnet mask */
	bpf_u_int32 net;	/* ip */
	struct pcap_pkthdr *pkthdr;
	const u_char *pkt_data;
	int inum, res;
	int i = 0;
	unsigned short chksum;

	printf("rxPckt: " PRINT_VERS "\n");

	if (getuid() != 0) {
		fprintf(stderr, "%s: root privelidges needed\n", *(argv + 0));
		exit(EXIT_FAILURE);
	}

	/* 1. load configuration */
	while ((i = getopt(argc, argv, "hv:")) != -1) {
		switch (i) {
		case 'v':
			verbose = strtoul(optarg, NULL, 10);
			break;
		case 'h':
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	if (!argv[optind]) {
		if (pcap_findalldevs(&alldevs, errbuf) == -1) {
			fprintf(stderr, "Error in pcap_findalldevs: %s\n",
				errbuf);
			exit(EXIT_FAILURE);
		}

		/* Print the list */
		i = 0;
		for (d = alldevs; d; d = d->next) {
			if (d->description)
				printf("%d. %s\n", ++i, d->description);
			else
				printf("%d. %s (No description available)\n",
				       ++i, d->name);
		}

		if (i == 0) {
			printf("\nNo interfaces found!\n");
			exit(EXIT_FAILURE);
		}

		printf("Enter the interface number (1-%d):", i);
		if (scanf("%d", &inum) <= 0) {
			exit(EXIT_FAILURE);
		}

		if (inum < 1 || inum > i) {
			printf("Interface number out of range.\n");
			/* Free the device list */
			pcap_freealldevs(alldevs);
			exit(EXIT_FAILURE);
		}

		/* Jump to the selected adapter */
		for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++) ;

		strcpy(dev, d->name);
	} else {
		strcpy(dev, argv[optind]);

		/* get network number and mask associated with capture device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr,
				"Couldn't get netmask for device %s: %s\n", dev,
				errbuf);
			net = 0;
			mask = 0;
			exit(EXIT_FAILURE);
		}
	}

	get_interface_macaddr((const char *) dev, my_mac_addr);

	/* Open the adapter */
	if ((handle = pcap_open_live(dev,	/* name of the interface(device) */
				     PACKET_LEN,	/* portion of the packet to capture */
				     1,	/* promiscuous mode (nonzero means promiscuous) */
				     1000,	/* read timeout */
				     errbuf)) == NULL) {
		fprintf(stderr, "Could not open %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	printf("%02x:%02x:%02x:%02x:%02x:%02x ... listening on %s\n",
		my_mac_addr[0], my_mac_addr[1], my_mac_addr[2],
		my_mac_addr[3], my_mac_addr[4] & 0xff, my_mac_addr[5], dev);
#if 1
	inum = 0;
	while ((res = pcap_next_ex(handle, &pkthdr, &pkt_data)) >= 0) {
		if (res == 0)
			continue;

		/* Is this packet for me? */
		if (memcmp
		    ((void *)pkt_data, (void *)my_mac_addr, ETHER_ADDR_LEN))
			continue;

		inum++;
#if 0
		chksum = verify_checksum((void *)pkt_data, pkthdr->len);

		printf("%d\n", inum);

		if (chksum != (unsigned short)-1) {
			printf("Checksum error 0x%04x\n", chksum);
			print_payload(pkt_data, pkthdr->len, NULL);
			printf("\n\r");
			exit(EXIT_FAILURE);
		}
		//got_packet((u_char *) NULL, pkthdr, pkt_data);
		printf("Packet number %d: %d bytes\n", inum, pkthdr->len);
		//print_payload(pkt_data, 16, NULL);
#else
{
		if ((inum & 0xff) == 0)
			printf("Packet number %d ...\n", inum);

		if (verbose)
			got_packet((u_char *) NULL, pkthdr, pkt_data);
}
#endif
	}

	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
#else
	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);
#endif

	pcap_close(handle);
	return 0;
}
