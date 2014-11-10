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
 *
 *
 * This program sends packets with content randomly generated.
 * User may use -a to wait for ACK packet from client side.
 * Default interval time between packets is 600 microseconds,
 * uses -t to change this value.
 */
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/if_ether.h> ////Provides declarations for ethernet header
#include <net/if.h>

#include <pcap.h>

/* default packet length (maximum bytes per packet to capture) */
#define PACKET_LEN 1514

/* flags value at payload first byte: 
 * - SYNC : client need to send acknowledgment packets.
 * - ACK : this is ack packet from client, check the ack_no
 *         if necessary to know ack for which seq_no packet.
 * - CRC : client side has CRC or others error happen 
 */
#define SYNC 0x1
#define ACK 0x2
#define ERR 0x4

/* 
 * 96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
 */
struct pseudo_header {    
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
};

#define HEADER_LEN      (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))
#define PAYLOAD_OFFSET  HEADER_LEN
#define TCPHDR_OFFSET   (sizeof(struct ethhdr) + sizeof(struct iphdr))
#define IPHDR_OFFSET    sizeof(struct ethhdr)

#define PSEUDO_SIZE     sizeof(struct pseudo_header) + sizeof(struct tcphdr) + PACKET_LEN - HEADER_LEN

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14


extern int get_dest_macaddr(const char *name, unsigned char *mac); 
extern int get_dest_ipaddr(const char *name, char *addr);
extern int get_interface_macaddr(const char *name, unsigned char *mac);
extern int get_interface_ipaddr(const char *name, int family, uint8_t *addr, int len);
