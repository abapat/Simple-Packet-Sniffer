//Amit Bapat
#include "mydump.h"

void printHelp();
void getTimestamp(struct timeval timestamp, char* str);
void parseTCP(const u_char *packet, int size_ip, uint16_t len, struct my_packet *p);
void parseUDP(const u_char *packet, int size_ip, uint16_t len, struct my_packet *p);
void parseICMP(const u_char *packet, int size_ip, uint16_t len, struct my_packet *p);
void printPacket(struct my_packet *p);
void getPayload(char* asciiBuf, char* hexBuf, const u_char *payload, int len);
void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void freeStruct(struct my_packet *p);

static int count = 1;                   /* packet counter */

void printHelp() {
	printf("Usage: mydump [-i interface] [-r file] [-s string] expression\n");
	exit(0);
}

void getTimestamp(struct timeval timestamp, char* str) {
	char buf[64];
	struct tm* now = localtime(&(timestamp.tv_sec));
	strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", now);
	sprintf(str, "[%s.%06ld]\n", buf, (long int)timestamp.tv_usec);
}

void parseUDP(const u_char *packet, int size_ip, uint16_t len, struct my_packet *p) {
	const struct udphdr *udp;            /* The UDP header */
	const u_char *payload;               /* Packet payload */
	int size_payload;	
	int size_udp = SIZE_UDP_HEADER;

	udp = (struct udphdr*)(packet + SIZE_ETHERNET_HEADER + size_ip);
	
	p->sourcePort = ntohs(udp->uh_sport);
	p->destPort = ntohs(udp->uh_dport);
	
	payload = (u_char *)(packet + SIZE_ETHERNET_HEADER + size_ip + size_udp);
	size_payload = len - (size_ip + size_udp);
	p->payloadLen = size_payload;
	//printf("\tIP packet size: %d \tTotal header size: %d\n", len, size_ip + size_udp);

	if (size_payload > 0) {
		p->asciiPayload = calloc(size_payload, sizeof(char));
		p->hexPayload = calloc(size_payload, sizeof(char));
		getPayload(p->asciiPayload, p->hexPayload, payload, size_payload);
	} 

}

void parseICMP(const u_char *packet, int size_ip, uint16_t len, struct my_packet *p) {
	int size_payload = len - (size_ip + SIZE_ICMP_HEADER);
	p->payloadLen = size_payload;
	const u_char* payload = (u_char *)(packet + SIZE_ETHERNET_HEADER + size_ip + SIZE_ICMP_HEADER);
	if (size_payload > 0) {
		p->asciiPayload = calloc(size_payload, sizeof(char));
		p->hexPayload = calloc(size_payload, sizeof(char));
		getPayload(p->asciiPayload, p->hexPayload, payload, size_payload);
	}	
}

void parseTCP(const u_char *packet, int size_ip, uint16_t len, struct my_packet *p) {
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */

	int size_tcp;
	int size_payload;	
	
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET_HEADER + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("\tError: Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	p->sourcePort = ntohs(tcp->th_sport);
	p->destPort = ntohs(tcp->th_dport);
	
	payload = (u_char *)(packet + SIZE_ETHERNET_HEADER + size_ip + size_tcp);
	size_payload = len - (size_ip + size_tcp);
	p->payloadLen = size_payload;
	//printf("\tIP packet size: %d \tTotal header size: %d\n", len, size_ip + size_tcp);

	if (size_payload > 0) {
		p->asciiPayload = calloc(size_payload, sizeof(char));
		p->hexPayload = calloc(size_payload, sizeof(char));
		getPayload(p->asciiPayload, p->hexPayload, payload, size_payload);
	}
}

void getPayload(char* asciiBuf, char* hexBuf, const u_char *payload, int len) {
	int x;
	for (x = 0; x < len; x++) {
		if (isprint(*(payload+x)))
			sprintf(asciiBuf+x, "%c", *(payload+x));
		else
			asciiBuf[x] = '.';

		//sprintf(hexBuf+x, "%02x ", *(payload+x));
	}

	memcpy(hexBuf, payload, len);
}

void printPacket(struct my_packet *p) {
	int IPflag = 0;
	printf("\nPacket %d %s\n", count, p->timestamp);
	count++;

	printf("\tEthertype: ");
	switch (p->etherType) {
		case ETHERTYPE_ARP:
			printf("ARP [%#x]\n", p->etherType);
			break;
		case ETHERTYPE_IP:
			printf("IP [%#x]\n", p->etherType);
			IPflag = 1;
			break;
		case ETHERTYPE_REVARP:
			printf("Reverse ARP [%#x]\n", p->etherType);
			break;
		default:
			printf("Other [%#x]\n", p->etherType);
			break;
	}

	printf("\tSource MAC address: %s\n", p->sourceMAC);
	printf("\tDestination MAC address: %s\n", p->destMAC);

	if (IPflag == 0)
		return;

	printf("\tPacket Length: %u\n", p->packetLen);
	printf("\tFrom: %s\n", p->sourceIP);
	printf("\tTo: %s\n", p->destIP);
	printf("\tProtocol: %s", p->protocol);
	
	if (p->sourcePort != 0)
		printf("\tSource port: %d\n", p->sourcePort);
	if (p->destPort != 0)
		printf("\tDest port: %d\n", p->destPort);
	if (p->payloadLen > 0) {
		printf("\tPayload (%d bytes):\n", p->payloadLen);
		int x = 0;
		int len = p->payloadLen;
		while (x < len) {
			int y;
			int start = x;
			printf("\t");
			for (y = 0; y < 16 && x < len; y++){
				printf("%02x ", *(p->hexPayload+x) & 0xff);
				x++;
			}
			if (y < 16) {
				for (; y < 16; y++) {
					printf("   ");
				}
			}
			x = start;
			printf(" ");
			for (y = 0; y < 16 && x < len; y++) {
				printf("%c", *(p->asciiPayload+x));
				x++;
			}
			printf("\n");
		}
	}
}

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	char* searchStr = (char*) args;
	const struct ether_header *ethernet;  /* The ethernet header */
	const struct sniff_ip *ip;              /* The IP header */
	struct my_packet p;
	p.hexPayload = NULL;
	p.asciiPayload = NULL;

	char buf[64];
	struct timeval timestamp = header->ts;
	getTimestamp(timestamp, buf);
	p.timestamp = buf;

	int size_ip;
	/* define ethernet header */
	ethernet = (struct ether_header*)(packet);
	uint16_t type = ntohs(ethernet->ether_type);
	p.etherType = type;

	p.sourceMAC = ether_ntoa((struct ether_addr*) ethernet->ether_shost);
	p.destMAC = ether_ntoa((struct ether_addr*) ethernet->ether_dhost);

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET_HEADER);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("\tError: Invalid IP header length: %u bytes\n", size_ip);
		printPacket(&p);
		return;
	}
	uint16_t len = ntohs(ip->ip_len);
	p.packetLen = len + SIZE_ETHERNET_HEADER;
	p.sourceIP = inet_ntoa(ip->ip_src);
	p.destIP = inet_ntoa(ip->ip_dst);
	//printf("getting protocol\n");
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			p.protocol = "TCP";
			parseTCP(packet, size_ip, len, &p);
			break;
		case IPPROTO_UDP:
			p.protocol = "UDP";
			parseUDP(packet, size_ip, len, &p);
			break;
		case IPPROTO_ICMP:
			p.protocol = "ICMP";
			parseICMP(packet, size_ip, len, &p);
			break;
		default:
			p.protocol = "Other";
			break;
	}
	//printf("checking arg\n");
	//check arg -s
	if (searchStr != NULL) {
		//printf("Packet Length: %d", p.packetLen);
		if (p.packetLen <= 0) {
			freeStruct(&p);
			return;
		}

		if (strstr(p.asciiPayload, searchStr) == NULL) {
			freeStruct(&p);
			return;
		}
		//else
		//	printf("NO MATCH: %s\n", p.asciiPayload);
	}
	//print packet
	printPacket(&p);
	printf("\n");

	freeStruct(&p);
}

void freeStruct(struct my_packet *p) {
	
	if (p->hexPayload != NULL)
		free(p->hexPayload);

	if (p->asciiPayload != NULL)
		free(p->asciiPayload);	
	
}

int main(int argc, char** argv) {
	bpf_u_int32 mask;			// The netmask of our sniffing device 
	bpf_u_int32 ip;				// The IP of our sniffing device 
	struct bpf_program fp;		// The compiled filter expression
	int numPackets = 0;		// How many packets to sniff for

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
		dev = interface;
	} else {
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
	pcap_loop(handle, numPackets, packetHandler, str);
	
	if (filter != NULL) {
		pcap_freecode(&fp);
	}

	pcap_close(handle);

	return 0;
}