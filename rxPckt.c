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

/* default packet length (maximum bytes per packet to capture) */
#define PACKET_LEN 1514

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN];	/* destination host address */
	u_char ether_shost[ETHER_ADDR_LEN];	/* source host address */
	u_short ether_type;	/* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src, ip_dst;	/* source and dest address */
};
#define IP_HL(ip)(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS   (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

void
got_packet(u_char * args, const struct pcap_pkthdr *header,
	   const u_char * packet);

extern void print_payload(const u_char * payload, int len, FILE * fp);

pcap_t *handle;
char my_mac_addr[ETHER_ADDR_LEN] = { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 };

/*
 * dissect/print packet
 */
void
got_packet(u_char * args, const struct pcap_pkthdr *pkthdr,
	   const u_char * packet)
{
	static int count = 1;	/* packet counter */
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;	/* The ethernet header [1] */
	const struct sniff_ip *ip;	/* The IP header */
	const struct sniff_tcp *tcp;	/* The TCP header */
	const char *payload;	/* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	printf("Packet number %d: %d bytes ...\n", count, pkthdr->len);
	count++;
	return;
	/* define ethernet header */
	ethernet = (struct sniff_ethernet *)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("  From: %s\n", inet_ntoa(ip->ip_src));
	printf("    To: %s\n", inet_ntoa(ip->ip_dst));

	/* determine protocol */
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		printf("   Protocol: TCP\n");
		break;
	case IPPROTO_UDP:
		printf("   Protocol: UDP\n");
		return;
	case IPPROTO_ICMP:
		printf("   Protocol: ICMP\n");
		return;
	case IPPROTO_IP:
		printf("   Protocol: IP\n");
		return;
	default:
		printf("   Protocol: unknown\n");
		return;
	}

	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload, NULL);
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

	if (argc < 2) {
		if (pcap_findalldevs(&alldevs, errbuf) == -1) {
			fprintf(stderr, "Error in pcap_findalldevs: %s\n",
				errbuf);
			exit(EXIT_FAILURE);
		}

		/* Print the list */
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
		strcpy(dev, argv[1]);

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

	/* Open the adapter */
	if ((handle = pcap_open_live(dev,	/* name of the interface(device) */
				     PACKET_LEN,	/* portion of the packet to capture */
				     1,	/* promiscuous mode (nonzero means promiscuous) */
				     1000,	/* read timeout */
				     errbuf)) == NULL) {
		fprintf(stderr, "Could not open %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	printf("listening on %s...\n", dev);

#if 0
	inum = 0;
	while ((res = pcap_next_ex(handle, &pkthdr, &pkt_data)) >= 0) {
		if (res == 0)
			continue;
		inum++;

		/* Is this packet for me? */
		if (memcmp
		    ((void *)pkt_data, (void *)my_mac_addr, ETHER_ADDR_LEN))
			continue;

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
