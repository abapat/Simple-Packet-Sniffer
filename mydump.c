#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>

void printHelp();
void printPacket(const u_char *packet, struct pcap_pkthdr header);
void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void printHelp() {
	printf("Usage: mydump [-i interface] [-r file] [-s string] expression\n");
	exit(0);
}

void printPacket(const u_char *packet, struct pcap_pkthdr header) {
	printf("Packet capture length: %d\n", header.caplen);
	printf("Packet total length %d\n", header.len);
}

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	printf("Captured Packet!\n");
	printPacket(packet, *header);
	printf("\n");
}

int main(int argc, char** argv) {
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
		//read file
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
		bpf_u_int32 mask;			// The netmask of our sniffing device 
		bpf_u_int32 ip;				// The IP of our sniffing device 
		struct bpf_program fp;		// The compiled filter expression

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
	pcap_loop(handle, 0, packetHandler, NULL);

	pcap_close(handle);
}