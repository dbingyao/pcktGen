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
 *
 *
 * This program sends packets with content randomly generated.
 * User may use -a to wait for ACK packet from client side.
 * Default interval time between packets is 600 microseconds,
 * uses -t to change this value.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <pcap.h>
#include <pthread.h>

#include "version.h"

/* default packet length (maximum bytes per packet to capture) */
#define PACKET_LEN 1460

/* flags value inside header: 
 * - SYNC : client need to send acknowledgment packets.
 * - ACK : this is ack packet from client, check the ack_no
 *         if necessary to know ack for which seq_no packet.
 * - CRC : client side has CRC or others error happen 
 */
#define SYNC 0x1
#define ACK 0x2
#define ERR 0x4

struct packet_header {
	unsigned char dhost[6];
	unsigned char shost[6];
	unsigned short proto;
	unsigned char flags;
	unsigned char over;
	unsigned int seq_no;
	unsigned int ack_no;
	unsigned short length;
	unsigned short chksum;
};

struct packet {
	struct packet_header hdr;
	char msg[PACKET_LEN];
};

#define HEADER_LEN (sizeof(struct packet_header))

pcap_t *handle;
struct packet pkt;

/* Expect to receive acknowlegment from client */
char need_ack = 0;
pthread_t rx_thread;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

/* Log packet to file */
char log_file = 0;
char tfname[50], rfname[50];
char fbin = 0;
FILE *tx_f = NULL;
int tx_fidx;
FILE *rx_f = NULL;
int rx_fidx;

/* statistics */
int tx_cnt;

char my_mac_addr[6] = { 0x12, 0x21, 0x12, 0x21, 0x22, 0x23 };

static void log_packets(FILE ** fp, char *fname, int *fidx, const u_char * buf,
			int len);

extern void print_payload(const u_char * payload, int len, FILE * fp);

void sig_handler(int signo)
{
	if ((signo == SIGINT) && (rx_thread != pthread_self())) {
		printf("received SIGINT\n");

		if (handle)
			pcap_close(handle);

		if (tx_f)
			fclose(tx_f);

		if (rx_f)
			fclose(rx_f);

		exit(EXIT_SUCCESS);
	}
}

/*--------------------------------------------------------------------*/
/*--- checksum - standard 1s complement checksum                   ---*/
/*--------------------------------------------------------------------*/
unsigned short checksum(void *b, int len)
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
	result = ~sum;
	return result;
}

static void log_packets(FILE ** fp, char *fname, int *fidx, const u_char * buf,
			int len)
{
	char outf[80];
	int pos;
	struct packet_header *hdr;

	if (log_file) {
		if (*fp) {
			pos = ftell(*fp);

			if ((pos + len) > 0x1000000) {
				fclose(*fp);
				goto open_file;
			}

			/* Only log in binary mode need to adjust to 16 bytes align */
			if (fbin) {
				pos = pos & 0xf;
				if (pos != 0) {
					//printf("advanced %d bytes\n", (int)(0x10-pos));
					fseek(*fp, 0x10 - pos, SEEK_CUR);
				}
			}
		} else {
open_file:
			sprintf(outf, fname, (*fidx)++);
			hdr = (struct packet_header *)buf;
			printf("Open %s to log packets, seq 0x%04x ... \n",
			       outf, hdr->seq_no);
			*fp = fopen(outf, "wb");
			if (*fp == NULL) {
				perror("fopen");
				exit(EXIT_FAILURE);
			}

			if (*fidx > 10)
				*fidx = 1;
		}

		//printf("(%d) Write %d bytes to %s\n", pkt.hdr.seq_no, pkt.hdr.length, outf);
	}

	if (fbin && *fp)
		fwrite(buf, 1, len, *fp);
	else
		print_payload(buf, len, *fp);

	if (*fp)
		fflush(*fp);
}

void *receive_packet(void *arg)
{
	struct pcap_pkthdr *pkthdr;
	const u_char *pkt_data;
	struct packet *p;
	int res;

	while (handle) {
		res = pcap_next_ex(handle, &pkthdr, &pkt_data);
		if (res < 0)
			break;
		if (res == 0)
			continue;

		/* Is this packet for me? */
		if (memcmp((void *)pkt_data, (void *)my_mac_addr, 6))
			continue;

		log_packets(&rx_f, rfname, &rx_fidx, pkt_data, pkthdr->len);

		p = (struct packet *)pkt_data;
		if (need_ack && (p->hdr.flags & ACK)) {
			/* signal main thread to continue sending packet */
			pthread_cond_signal(&cond);
		} else {
			if (p->hdr.flags & ERR)
				printf("Received ERR ack from client\n");
			exit(EXIT_FAILURE);
		}

	}
}

void send_packet(void)
{
	unsigned short payload_sz;
	int i = 0;
	long ran;
	int status;

	/* overflow */
	if ((tx_cnt + 1) > 0xffffffff) {
		pkt.hdr.over += 1;
		tx_cnt = 0;
	}
	pkt.hdr.seq_no = ++tx_cnt;
	pkt.hdr.ack_no = 0xffffffff;
#if 1
	pkt.hdr.flags = need_ack;
#else
	if ((pkt.hdr.seq_no % 0x2000) == 0)
		pkt.hdr.flags = SYNC;
	else
		pkt.hdr.flags = 0;
#endif
	/* MTU is 1500 bytes minus HEADER_LEN */
	ran = random();
	ran = ran >> 16;
	payload_sz = (unsigned short)((ran & 0x3ff) + (ran & 0x1ff));

	if (payload_sz < 64)
		payload_sz = 64 - HEADER_LEN;
	else if (payload_sz + HEADER_LEN > 1500)
		payload_sz = 1500 - HEADER_LEN;

	pkt.hdr.length = payload_sz + HEADER_LEN;
	for (i = 0; i < payload_sz; i++)
		pkt.msg[i] = (char)random();

	pkt.hdr.chksum = 0;
	pkt.hdr.chksum = checksum((void *)&pkt, pkt.hdr.length);

	log_packets(&tx_f, tfname, &tx_fidx, (const u_char *)&pkt,
		    pkt.hdr.length);

	/* Send down the packet */
	if (pcap_sendpacket(handle, (u_char *) & pkt, (HEADER_LEN + payload_sz))
	    != 0) {
		printf("Error sending the packet: %s\n", pcap_geterr(handle));
	}
}

static void usage(void)
{
	printf("\n"
	       "usage: txPckt [OPTION] [ifname]\n"
	       "\n"
	       "[OPTION]\n"
	       "    -a : require acknowledgement packet\n"
	       "    -t <microseconds>: time to wait before send next packet, default:550\n"
	       "    -b : log packet content to file as binary mode\n"
	       "    -f <filenameprefix> : may include directory, write packets content"
	       " to ./dir/<filename>-tx-xxx.log\n"
	       "    [ifname] : network interface to send/receive packet(s)\n");
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char dev[20];
	int inum, i = 0;
	useconds_t delay = 550;

	printf("txPckt: " PRINT_VERS "\n");

	if (getuid() != 0) {
		printf("%s: root privelidges needed\n", *(argv + 0));
		exit(EXIT_FAILURE);
	}

	/* 1. load configuration */
	while ((i = getopt(argc, argv, "abhf:t:")) != -1) {
		switch (i) {
		case 'a':
			need_ack = SYNC;
			break;
		case 't':
			delay = strtoul(optarg, NULL, 10);
			if (delay > 1000000)
				delay = 600;
			break;
		case 'b':
			fbin = 1;
			break;
		case 'f':
			strcpy(tfname, optarg);
			strcat(tfname, "-tx-%03d.log");
			strcpy(rfname, optarg);
			strcat(rfname, "-rx-%03d.log");
			log_file = 1;
			break;
		case 'h':
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	if (!argv[optind]) {
		pcap_if_t *alldevs;
		pcap_if_t *d;

		if (pcap_findalldevs(&alldevs, errbuf) == -1) {
			printf("Error in pcap_findalldevs: %s\n", errbuf);
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
		bpf_u_int32 mask;	/* subnet mask */
		bpf_u_int32 net;	/* ip */

		strcpy(dev, argv[optind]);

		/* get network number and mask associated with capture device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			printf("Couldn't get netmask for device %s: %s\n",
			       dev, errbuf);
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
		printf("Could not open %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	tx_fidx = rx_fidx = 1;

	printf("listening on %s...\n", dev);

	if (pthread_create(&rx_thread, NULL, receive_packet, NULL)) {
		printf("Rx Thread creation failed\n");
		exit(EXIT_FAILURE);
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		printf("\ncan't catch SIGINT\n");

	pkt.hdr.dhost[0] = 0x08;
	pkt.hdr.dhost[1] = 0x08;
	pkt.hdr.dhost[2] = 0x08;
	pkt.hdr.dhost[3] = 0x08;
	pkt.hdr.dhost[4] = 0x08;
	pkt.hdr.dhost[5] = 0x08;

	pkt.hdr.shost[0] = my_mac_addr[0];
	pkt.hdr.shost[1] = my_mac_addr[1];
	pkt.hdr.shost[2] = my_mac_addr[2];
	pkt.hdr.shost[3] = my_mac_addr[3];
	pkt.hdr.shost[4] = my_mac_addr[4];
	pkt.hdr.shost[5] = my_mac_addr[5];

	/* arbitary number prevent known ethertype */
	pkt.hdr.proto = 0x87a;

	do {
		send_packet();

		if (need_ack) {
			int rc;
			struct timespec ts;
			struct timeval tp;

			if (gettimeofday(&tp, NULL) != 0) {
				printf("gettimeofday failed\n");
				return 0;
			}

			/* Convert from timeval to timespec */
			ts.tv_sec = tp.tv_sec;
			ts.tv_nsec = tp.tv_usec * 1000;
			ts.tv_sec += 2;

			pthread_mutex_lock(&mutex);
			rc = pthread_cond_timedwait(&cond, &mutex, &ts);
			if (rc == ETIMEDOUT) {
				printf("Wait timed out!\n");
				pthread_mutex_unlock(&mutex);
				return 0;
			}
			pthread_mutex_unlock(&mutex);
		} else {
			usleep(delay);
		}
	} while (1);

	return 0;
}
