#include <unistd.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806

// define necessary struct for headers
/* Ethernet header */
struct sniff_ethernet
{
	u_char  ether_dhost[ETHER_ADDR_LEN];	/* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];	/* source host address */
	u_short ether_type;					 /* IP? ARP? RARP? etc */
};
/* IP header */
struct sniff_ip
{
	u_char  ip_vhl;				 /* version << 4 | header length >> 2 */
	u_char  ip_tos;				 /* type of service */
	u_short ip_len;				 /* total length */
	u_short ip_id;				  /* identification */
	u_short ip_off;				 /* fragment offset field */
#define IP_RF 0x8000			/* reserved fragment flag */
#define IP_DF 0x4000			/* dont fragment flag */
#define IP_MF 0x2000			/* more fragments flag */
#define IP_OFFMASK 0x1fff	   /* mask for fragmenting bits */
	u_char  ip_ttl;				 /* time to live */
	u_char  ip_p;				   /* protocol */
	u_short ip_sum;				 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp
{
	u_short th_sport;			   /* source port */
	u_short th_dport;			   /* destination port */
	tcp_seq th_seq;				 /* sequence number */
	tcp_seq th_ack;				 /* acknowledgement number */
	u_char  th_offx2;			   /* data offset, rsvd */
#define TH_OFF(th)	  (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS		(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;				 /* window */
	u_short th_sum;				 /* checksum */
	u_short th_urp;				 /* urgent pointer */
};
/* UDP header */
struct sniff_udp {
	u_short sport;	/* source port */
	u_short dport;	/* destination port */
	u_short udp_length;
	u_short udp_sum;	/* checksum */
};

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}
void print_ether_details(const struct pcap_pkthdr *header, const u_char *packet){
	const struct sniff_ethernet *ethernet;
	
	time_t raw_time = (time_t)header->ts.tv_sec;
	char timebuf[126];
	strftime(timebuf, 26, "%Y:%m:%d %H:%M:%S", localtime(&raw_time));
	printf("\n %s.%06ld", timebuf,header->ts.tv_sec);
	
	ethernet = (struct sniff_ethernet*)(packet);
//Print MAC address	
	printf(" %02x:%02x:%02x:%02x:%02x:%02x ->",
			(unsigned)ethernet->ether_shost[0],
			(unsigned)ethernet->ether_shost[1],
			(unsigned)ethernet->ether_shost[2],
			(unsigned)ethernet->ether_shost[3],
			(unsigned)ethernet->ether_shost[4],
			(unsigned)ethernet->ether_shost[5]);

	printf(" %02x:%02x:%02x:%02x:%02x:%02x ",
		(unsigned)ethernet->ether_dhost[0],
		(unsigned)ethernet->ether_dhost[1],
		(unsigned)ethernet->ether_dhost[2],
		(unsigned)ethernet->ether_dhost[3],
		(unsigned)ethernet->ether_dhost[4],
		(unsigned)ethernet->ether_dhost[5]);
	
	printf(" type 0x%x ", ETHERTYPE_IPV4);	
	printf(" len %d ", header->len);	
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	
	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	const struct sniff_udp *udp;
	//char *addr;
	//struct ether_addr host;

	int size_ip;
	int size_tcp;
	int size_payload;
	int size_udp = 8;
	int size_icmp = 8;
	char *toprint = NULL;
	
	//printf("\nPacket number %d:\n", count);
	count++;
	char *string = NULL;
	if (args != NULL) {
		string = (char *) args;
	}
	//printf("String is: %s\n", string);
	//time_t raw_time = (time_t)header->ts.tv_sec;
	//char timebuf[126];
	//strftime(timebuf, 26, "%Y:%m:%d %H:%M:%S", localtime(&raw_time));
	//printf("%s.%06ld", timebuf,header->ts.tv_sec);
	//snprintf(toprint,"%s.%06ld", timebuf,header->ts.tv_sec)
	
	ethernet = (struct sniff_ethernet*)(packet);
	
	if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV4) {
			//printf(" | type 0x%x", ETHERTYPE_IPV4);
			/*memethernetcpy(&host, ethernet->ether_dhost, sizeof(host));
			addr = ether_ntoa(&host);
			
			printf("%s%02x", addr);*/
				
			ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
			size_ip = IP_HL(ip)*4;
			if (size_ip < 20) {
				printf("   * Invalid IP header length: %u bytes\n", size_ip);
				return;
			}
	
			if (ip->ip_p == IPPROTO_TCP) {
				
				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcp)*4;
				if (size_tcp < 20) {
					printf("* Invalid TCP header length: %u bytes\n", size_tcp);
					return;
				}
				
				
				// extract payload
				/* compute tcp payload (segment) size */
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
				size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
				
				// print payload
				// Awkward method to print the details with and without filter string.
				// TO DO : Remove the below prints and use snprintf
				if (size_payload > 0) {
					if (string != NULL && strstr((char *) payload, string) == NULL)
						return;
					print_ether_details(header,packet);
					printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
					printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
					printf(" TCP \n");	
					print_payload(payload, size_payload);
				}
				else {
					if(string == NULL){
					print_ether_details(header,packet);
					printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
					printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
					printf(" TCP \n");	
					 return;
					}
				}
			}   else if (ip->ip_p == IPPROTO_UDP) {
				
				udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
				

				// extract payload
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
				size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
				
				// print payload
				if (size_payload > 0) {
				if (string != NULL && strstr((char *) payload, string) == NULL)
						return;
				print_ether_details(header,packet);
				printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->sport));
				printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(udp->dport));
				printf(" UDP \n");	
				print_payload(payload, size_payload);
				} else {
				if(string == NULL){	
				print_ether_details(header,packet);
				printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->sport));
				printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(udp->dport));
				printf(" UDP \n");
					return;
				  }
				}
			}
			else 
				if (ip->ip_p == IPPROTO_ICMP) {
				

				// extract payload
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
				size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
				
				// print payload
				if (size_payload > 0) {	
				if (string != NULL && strstr((char *) payload, string) == NULL)
						return;
				print_ether_details(header,packet);			
				printf("%s -> ", inet_ntoa(ip->ip_src));
				printf("%s ", inet_ntoa(ip->ip_dst));
				printf(" ICMP \n");		
				print_payload(payload, size_payload);
				} else {
				if(string == NULL){
				print_ether_details(header,packet);				
				printf("%s -> ", inet_ntoa(ip->ip_src));
				printf("%s ", inet_ntoa(ip->ip_dst));
				printf(" ICMP \n");	
					return;
					}
				}
			}else {
				
				// extract payload
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
				size_payload = ntohs(ip->ip_len) - (size_ip);
				

				// print payload
				if (size_payload > 0)
				{
				if (string != NULL && strstr((char *) payload, string) == NULL)
						return;	
				print_ether_details(header,packet);					
				printf("%s -> ", inet_ntoa(ip->ip_src));
				printf("%s ", inet_ntoa(ip->ip_dst));
				printf(" OTHER \n");
				print_payload(payload, size_payload);
				} else {
				if(string == NULL){
				print_ether_details(header,packet);					
				printf("%s -> ", inet_ntoa(ip->ip_src));
				printf("%s ", inet_ntoa(ip->ip_dst));
				printf(" OTHER \n");
				}	
					return;
				}
			}
	
	
	}else if(string == NULL){
		if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
				time_t raw_time = (time_t)header->ts.tv_sec;
				char timebuf[126];
				strftime(timebuf, 26, "%Y:%m:%d %H:%M:%S", localtime(&raw_time));
				printf("\n %s.%06ld", timebuf,header->ts.tv_sec);
			printf(" %02x:%02x:%02x:%02x:%02x:%02x ->",
				(unsigned)ethernet->ether_shost[0],
				(unsigned)ethernet->ether_shost[1],
				(unsigned)ethernet->ether_shost[2],
				(unsigned)ethernet->ether_shost[3],
				(unsigned)ethernet->ether_shost[4],
				(unsigned)ethernet->ether_shost[5]);
			
			printf(" %02x:%02x:%02x:%02x:%02x:%02x ",
				(unsigned)ethernet->ether_dhost[0],
				(unsigned)ethernet->ether_dhost[1],
				(unsigned)ethernet->ether_dhost[2],
				(unsigned)ethernet->ether_dhost[3],
				(unsigned)ethernet->ether_dhost[4],
				(unsigned)ethernet->ether_dhost[5]);
				
				
			printf(" type 0x%x ", ETHERTYPE_ARP);
			printf(" len %d ", header->len);	
			printf("  ARP\n");
	} else {
		printf("OTHER\n");
	}
	}	
}
int main(int argc, char *argv[])
{
	int opt = 0;
	char *interface = NULL;
	char *file = NULL;
	char *string = NULL;
	char *expr = NULL;
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int num_packets = -1;
	struct bpf_program fp;
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	
	dev = pcap_lookupdev(errbuf);
/*	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
         printf("Device: %s\n", dev);

	 handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	 if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		 return(2);
	 }
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - 			not supported\n", dev);
		return(2);
	}
	return(0);
*/
	while ((opt = getopt(argc, argv, "i:r:s:c:d")) != -1) {
		switch(opt) {
			case 'i':
				interface = optarg;
				printf("Interface: %s\n", interface);
				break;
			case 'r':
				file = optarg;
				printf("File: %s\n", file);
				break;
			case 's':
				string = optarg;
				printf("String: %s\n", string);
				break;
			case 'c':
				num_packets = atoi(optarg);
				break;	
			case '?': 
				if (optopt == 'i') {
					printf("Option 'i' requires an argument \n");
					return 0;
				} else if (optopt == 'r') {
					printf("Option 'r' requires an argument.\n");
					return 0;
				} else if (optopt == 's') {
					printf("Option 's' requires an argument \n");
					return 0;
				} else {
					printf("Invalid argument.\n");
					return 0;
				}
			default:
				printf("Default case?.\n");
				return 0;
		}
		
	}
	
	// get expression
	if (optind == argc - 1)
		expr = argv[optind];
	else if (optind < argc -1) {
		printf("Invalid set of arguments. Exiting...\n");
		return 0;
	}
	
	if (interface != NULL && file != NULL) {
		printf("Please specify either interface or file.!\n");
		return 0;
	}
	
	if (interface == NULL && file == NULL) {
		interface = pcap_lookupdev(errbuf);
		//interface = NULL;
		if (interface == NULL) {
			printf("Default device not found: %s \n", errbuf);
			return 0;
		}
	}
		// open interface or file here
	if (interface != NULL) {
		// Get ip and netmask of sniffing interface or file
		if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
			printf("Couldn't get netmask for device: %s\n", errbuf);
			net = 0;
			mask = 0;
		}
		// Start pcap session
		handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			printf("Couldn't open device: %s\n", errbuf);
			return 0;
		}
	} else if (file != NULL) {
		handle = pcap_open_offline(file, errbuf);
		if (handle == NULL) {
			printf("Couldn't open file : %s\n", errbuf);
			return 0;
		}
	}
	
	if (expr != NULL) {
		printf("Expression is : %s \n",expr);
		if (pcap_compile(handle, &fp, expr, 0, net) == -1) {
			printf("Couldn't parse filter : %s\n", pcap_geterr(handle));
			return 0;
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			printf("Couldn't install filter : %s\n", pcap_geterr(handle));
			return 0;
		}
	}
	
	pcap_loop(handle, num_packets, got_packet, (u_char *)string);
	pcap_close(handle);
	return 0;
}