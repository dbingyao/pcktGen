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
#include <pthread.h>

#include "version.h"
#include "common.h"

/* Use Fix MAC address */
#define MAC_ADDR_FIX 1

struct iphdr iph;
struct tcphdr tcph;

pcap_t *handle;
char pkt[PACKET_LEN];
char pseudogram[PSEUDO_SIZE];

/* Expect to receive acknowlegment from client */
char need_ack = 0;
char insert_iphdr = 1, insert_tcphdr = 0;
pthread_t rx_thread;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

/* Log packet to file */
char log_file = 0, verbose = 0;
char tfname[50], rfname[50];
char fbin = 0;
FILE *tx_f = NULL;
int tx_fidx;
FILE *rx_f = NULL;
int rx_fidx;

/* statistics */
int tx_cnt = 0;

unsigned char my_mac_addr[6] = { 0x12, 0x21, 0x12, 0x21, 0x22, 0x23 };
unsigned char dest_mac_addr[6] = { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 };

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

/*
 * Generic checksum calculation function
 */
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;

	return(answer);
}

static void log_packets(FILE ** fp, char *fname, int *fidx, const u_char * buf,
			int len)
{
	char outf[80];
	int pos;
	struct tcphdr *hdr;

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
			hdr = (struct tcphdr *) (buf + TCPHDR_OFFSET);
			printf("Open %s to log packets, seq 0x%04x ... \n",
			       outf, hdr->seq);
			*fp = fopen(outf, "wb");
			if (*fp == NULL) {
				perror("fopen");
				exit(EXIT_FAILURE);
			}

			if (*fidx > 10)
				*fidx = 1;
		}

	} else {

		*fp = NULL;
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

		if (log_file || verbose)
			log_packets(&rx_f, rfname, &rx_fidx, pkt_data, pkthdr->len);

		if (need_ack) {
			if (pkt_data[PAYLOAD_OFFSET] & ACK) {
				/* signal main thread to continue sending packet */
				pthread_cond_signal(&cond);
			} else {
				if (pkt_data[PAYLOAD_OFFSET] & ERR)
					printf("Received ERR ack from client\n");
				exit(EXIT_FAILURE);
			}
		}

	}
}

void send_packet(void)
{
	struct pseudo_header psh;
	unsigned short payload_sz;
	int i = 0;
	long ran;

#if 1
	pkt[PAYLOAD_OFFSET] = need_ack;
#else
	if ((tcph->seq % 0x2000) == 0)
		pkt[PAYLOAD_OFFSET] = SYNC;
	else
		pkt[PAYLOAD_OFFSET] = 0;
#endif

#if (MAC_ADDR_FIX == 0)
	*((int *) &pkt[0]) = random();
	*((short *) &pkt[4]) = (short) random();

	*((int *) &pkt[6]) = random();
	*((short *) &pkt[10]) = (short) random();
#endif
	/* MTU is 1514 bytes minus HEADER_LEN */
	ran = random();
	ran = ran >> 16;
	//payload_sz = (unsigned short)((ran & 0x3ff) + (ran & 0x1ff));
	payload_sz = 20;

	if (!payload_sz)
		payload_sz = 20;
	else if (payload_sz + HEADER_LEN > PACKET_LEN)
		payload_sz = PACKET_LEN - HEADER_LEN;

	//Ip checksum
	iph.tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + payload_sz);
	iph.check = 0;      //Set to 0 before calculating checksum
	iph.check = csum ((unsigned short *) &iph, sizeof (struct iphdr));
	//printf("IP checksum: 0x%04x\n", iph.check);
	memcpy((pkt + IPHDR_OFFSET), (char *)&iph, sizeof(struct iphdr));

	for (i = (PAYLOAD_OFFSET + 1); i < (PAYLOAD_OFFSET + payload_sz); i+=4)
		*((int *) &pkt[i]) = random();

	tcph.check = 0;      //Set to 0 before calculating checksum
	tcph.seq = htonl(++tx_cnt);
	//Now the TCP checksum
	psh.source_address = iph.saddr;
	psh.dest_address = iph.daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + payload_sz);
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_sz;

	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , (char*) &tcph , sizeof(struct tcphdr));
	memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), &pkt[PAYLOAD_OFFSET] , payload_sz);

	tcph.check = csum( (unsigned short*) pseudogram , psize);

	//printf("TCP checksum: 0x%04x\n", tcph.check);
	memcpy((pkt + TCPHDR_OFFSET), (char *)&tcph, sizeof(struct tcphdr));

	if (log_file || verbose)
		log_packets(&tx_f, tfname, &tx_fidx, (const u_char *)&pkt,
			    (HEADER_LEN + payload_sz));

	/* Send down the packet */
	if (pcap_sendpacket(handle, (u_char *) & pkt, (HEADER_LEN + payload_sz))
	    != 0) {
		printf("Error sending the packet: %s\n", pcap_geterr(handle));
	}
}


static void prepare_header(const char *name)
{
	struct ethhdr *eth = (struct ethhdr *) pkt;
	unsigned long my_addr;
	char dest_addr[16];
	int i;

#if MAC_ADDR_FIX
	for (i=0; i< 6; i++) {
		pkt[i] = dest_mac_addr[i];
		pkt[i + 6] = my_mac_addr[i];
	}
#endif
	if (insert_iphdr)
		eth->h_proto = htons(0x0800);
	else
		eth->h_proto = 0x87a; // arbitary number prevent known ethertype

	//Fill in the IP Header
	memset(&iph, 0 , sizeof(struct iphdr));
	iph.ihl = 5;
	iph.version = 4;
	iph.tos = 0;
	iph.id = htonl (54321); //Id of this packet
	iph.frag_off = 0;
	iph.ttl = 255;
     
	get_interface_ipaddr(name, AF_INET, (unsigned char *) &my_addr, 4);
	iph.saddr = my_addr;

	if (!get_dest_ipaddr(name, dest_addr))
		iph.daddr = inet_addr (dest_addr);
	else //Get dest IP failed, just fill with arbitary IP
		iph.daddr = inet_addr ("10.0.0.68");

	if (insert_tcphdr)
		iph.protocol = IPPROTO_TCP;
	else
		iph.protocol = ~IPPROTO_TCP;
	memcpy((pkt + IPHDR_OFFSET), (char *)&iph, sizeof(struct iphdr));

	//Fill in TCP Header
	memset(&tcph, 0 , sizeof(struct tcphdr));
	tcph.source = htons (3234);
	tcph.dest = htons (3248);
	tcph.seq = 0;
	tcph.ack_seq = 0;
	tcph.doff = 5;  //tcp header size
	tcph.fin=0;
	tcph.syn=0;
	tcph.rst=0;
	tcph.psh=0;
	tcph.ack=0;
	tcph.urg=0;
	tcph.window = htons (5840); /* maximum allowed window size */
	tcph.check = 0; //leave checksum 0 now, filled later by pseudo header
	tcph.urg_ptr = 0;
	memcpy((pkt + TCPHDR_OFFSET), (char *)&tcph, sizeof(struct tcphdr));
}

struct timespec diff(struct timespec start, struct timespec end)
{
        struct timespec temp;

        if ((end.tv_nsec - start.tv_nsec) < 0) {
                temp.tv_sec = end.tv_sec-start.tv_sec - 1;
                temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
        } else {
                temp.tv_sec = end.tv_sec - start.tv_sec;
                temp.tv_nsec = end.tv_nsec - start.tv_nsec;
        }

        return temp;
}

static void usage(void)
{
	printf("\n"
	       "usage: txPckt [OPTION] [ifname]\n"
	       "\n"
	       "[OPTION]\n"
	       "    -a : require acknowledgement packet\n"
	       "    -t <nanoseconds>: time to wait before send next packet, default:550\n"
	       "    -v : dump packet content to console\n"
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
	struct timespec t0, t1, tdiff;
	int delay = 50000000;

	printf("txPckt: " PRINT_VERS "\n");

	if (getuid() != 0) {
		printf("%s: root privelidges needed\n", *(argv + 0));
		exit(EXIT_FAILURE);
	}

	/* 1. load configuration */
	while ((i = getopt(argc, argv, "abvhf:t:")) != -1) {
		switch (i) {
		case 'a':
			need_ack = SYNC;
			break;
		case 't':
			delay = strtoul(optarg, NULL, 10);
			if (delay >= 1000000000)
				delay -= 1;
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
		case 'v':
			verbose = 1;
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

	get_interface_macaddr((const char *) dev, my_mac_addr);
	get_dest_macaddr((const char *) dev, dest_mac_addr);

	printf("%02x:%02x:%02x:%02x:%02x:%02x ... listening on %s\n",
		my_mac_addr[0], my_mac_addr[1], my_mac_addr[2],
		my_mac_addr[3], my_mac_addr[4] & 0xff, my_mac_addr[5],dev);

	printf("send packets to %02x:%02x:%02x:%02x:%02x:%02x\n",
		dest_mac_addr[0], dest_mac_addr[1], dest_mac_addr[2],
		dest_mac_addr[3], dest_mac_addr[4] & 0xff, dest_mac_addr[5]);

	if (pthread_create(&rx_thread, NULL, receive_packet, NULL)) {
		printf("Rx Thread creation failed\n");
		exit(EXIT_FAILURE);
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		printf("\ncan't catch SIGINT\n");

	prepare_header((const char *) dev);

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0)
		printf("t0: clock_gettime failed\n");

	srandom(t0.tv_nsec);
	do {
		send_packet();

		if (need_ack) {
			int rc;
			struct timeval tp;

			if (gettimeofday(&tp, NULL) != 0) {
				printf("gettimeofday failed\n");
				return 0;
			}

			/* Convert from timeval to timespec */
			t0.tv_sec = tp.tv_sec;
			t0.tv_nsec = tp.tv_usec * 1000;
			t0.tv_sec += 2;

			pthread_mutex_lock(&mutex);
			rc = pthread_cond_timedwait(&cond, &mutex, &t0);
			if (rc == ETIMEDOUT) {
				printf("Wait timed out!\n");
				pthread_mutex_unlock(&mutex);
				return 0;
			}
			pthread_mutex_unlock(&mutex);
		} else {
			if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0)
				printf("t0: clock_gettime failed\n");
#if 1
			do {
				if (clock_gettime(CLOCK_MONOTONIC, &t1) < 0) {
					printf("t0: clock_gettime failed\n");
					return 0;
				}

				tdiff = diff(t0, t1);
				if (tdiff.tv_nsec > delay) {
					break;
				}
			} while(1);
#else
			if (delay)
				usleep(delay);
#endif
		}
	//} while (tx_cnt < 5);
	} while (1);

	return 0;
}
