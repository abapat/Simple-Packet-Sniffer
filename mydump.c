//Amit Bapat
#include "mydump.h"

void printHelp();
void printPacket(const u_char *packet, struct pcap_pkthdr header);
void printTimestamp(struct timeval timestamp);
void printTCP(const u_char *packet, int size_ip, const struct sniff_ip *ip);
void printUDP(const u_char *packet, int size_ip, const struct sniff_ip *ip);
void printPayload(const u_char *payload, int len);
void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

static int count = 1;                   /* packet counter */

void printHelp() {
	printf("Usage: mydump [-i interface] [-r file] [-s string] expression\n");
	exit(0);
}

void printTimestamp(struct timeval timestamp) {
	char buf[64];
	struct tm* now = localtime(&(timestamp.tv_sec));
	strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", now);
	printf("[%s.%06ld]\n", buf, (long int)timestamp.tv_usec);
}

void printUDP(const u_char *packet, int size_ip, const struct sniff_ip *ip) {
	const struct udphdr *udp;            /* The UDP header */
	const u_char *payload;               /* Packet payload */
	int size_payload;	
	int size_udp = SIZE_UDP_HEADER;

	udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
	
	printf("\tSrc port: %d\n", ntohs(udp->uh_sport));
	printf("\tDst port: %d\n", ntohs(udp->uh_dport));
	printf("\tUDP len: %d\n", ntohs(udp->uh_ulen));
	
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

	printf("\tIP packet size: %d \tTotal header size: %d\n", ntohs(ip->ip_len), size_ip + size_udp);

	if (size_payload > 0) {
		printf("\tPayload (%d bytes)\n", size_payload);
		//printf("\t%s", payload);
	}

}

void printTCP(const u_char *packet, int size_ip, const struct sniff_ip *ip) {
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */

	int size_tcp;
	int size_payload;	
	
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("\tError: Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf("\tSrc port: %d\n", ntohs(tcp->th_sport));
	printf("\tDst port: %d\n", ntohs(tcp->th_dport));
	
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	printf("\tIP packet size: %d \tTotal header size: %d\n", ntohs(ip->ip_len), size_ip + size_tcp);
	
	if (size_payload > 0) {
		printf("\tPayload (%d bytes)\n", size_payload);
		//printf("\t%s", payload);
	}
}

void printPacket(const u_char *packet, struct pcap_pkthdr header) {	
	/* declare pointers to packet headers */
	const struct ether_header *ethernet;  /* The ethernet header */
	const struct sniff_ip *ip;              /* The IP header */

	int size_ip;
	int IP_flag = 0;
	/* define ethernet header */
	ethernet = (struct ether_header*)(packet);
	uint16_t type = ntohs(ethernet->ether_type);
	printf("\tEthertype: ");
	switch (type) {
		case ETHERTYPE_ARP:
			printf("ARP [%#x]\n", type);
			break;
		case ETHERTYPE_IP:
			printf("IP [%#x]\n", type);
			IP_flag = 1;
			break;
		case ETHERTYPE_REVARP:
			printf("Reverse ARP [%#x]\n", type);
			break;
		default:
			printf("Other [%#x]\n", type);
			break;
	}
	printf("\tSource MAC address: %s\n", ether_ntoa((struct ether_addr*) ethernet->ether_shost));
	printf("\tDestination MAC address: %s\n", ether_ntoa((struct ether_addr*) ethernet->ether_dhost));
	if (IP_flag == 0)
		return;

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("\tError: Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("\tFrom: %s\n", inet_ntoa(ip->ip_src));
	printf("\tTo: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */
	printf("\tProtocol: ");	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("TCP\n");
			printTCP(packet, size_ip, ip);
			break;
		case IPPROTO_UDP:
			printf("UDP\n");
			printUDP(packet, size_ip, ip);
			break;
		case IPPROTO_ICMP:
			printf("ICMP\n");
			break;
		default:
			printf("Other\n");
			break;
	}
	
}

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct timeval timestamp = header->ts;
	printf("\nPacket %d ", count);
	printTimestamp(timestamp);
	count++;

	printPacket(packet, *header);
	printf("\n");
}

int main(int argc, char** argv) {
	bpf_u_int32 mask;			// The netmask of our sniffing device 
	bpf_u_int32 ip;				// The IP of our sniffing device 
	struct bpf_program fp;		// The compiled filter expression
	int numPackets = 10;		// How many packets to sniff for

	char* interface = NULL;
	char* file = NULL;
	char* str = NULL;
	char* filter = NULL;

	opterr = 0;
	char c;
	//parse arguments
	while ((c = getopt(argc, argv, "i:r:s:")) != -1) {
		switch(c) {
			case 'i':
				if (optarg == NULL)
					printHelp();
				interface = optarg;
				break;
			case 'r':
				if (optarg == NULL)
					printHelp();
				file = optarg;
				break;
			case 's':
				if (optarg == NULL)
					printHelp();
				str = optarg;
				break;
			default:
				printHelp(); //should exit program
				break;
		}
	}

	if (optind < argc) {
		filter = argv[optind];
	}

	printf("interface = %s, file = %s, string = %s, expression = %s\n", interface, file, str, filter);

	if (interface != NULL && file != NULL) {
		fprintf(stderr, "Error: Please select an interface or file to listen to");
		printHelp();
	}

	char *dev = NULL, errbuf[PCAP_ERRBUF_SIZE];

	if (file != NULL) {
		//TODO read file
	} else if (interface != NULL) {
		//open interface
		dev = interface;
	} else {
		//use default interface
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(1);
		}
	}
	
	printf("Device: %s\n", dev);
	
	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(1);
	}

	if (filter != NULL) {
		if (pcap_lookupnet(dev, &ip, &mask, errbuf) == -1) {
			fprintf(stderr, "Can't get netmask for device %s\n", dev);
			return(1);
		}
		if (pcap_compile(handle, &fp, filter, 0, ip) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
			return(1);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
			return(1);
		}
	}
	//packet capture
	pcap_loop(handle, numPackets, packetHandler, NULL);
	
	if (filter != NULL) {
		pcap_freecode(&fp);
	}

	pcap_close(handle);

	return 0;
}