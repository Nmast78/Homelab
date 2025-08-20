#include <pcap.h>
#include "hacking.h"
#include "hacking-network.h"

void pcap_fatal(const char *, const char *);
void decode_ethernet(const u_char *);
void decode_ip(const u_char *);
u_int decode_tcp(const u_char *);

void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int main() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle;
	pcap_if_t *alldevs;
	char *device;
	int ret;

	// Initialize the packet capture library
	if ((pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf)) != 0) {
		pcap_fatal("pcap_init", errbuf);
	}

	// Find a network device for packet capture
	pcap_findalldevs(&alldevs, errbuf);
	if (alldevs == NULL) {
		pcap_fatal("pcap_lookupdev", errbuf);
	}
	device = alldevs->name;

	// Open a handle for live capture 
	if ((pcap_handle = pcap_create(device, errbuf)) ==  NULL) {
		pcap_fatal("pcap_create", errbuf);
	}

	printf("Sniffing on device %s\n", device);

	// Set promiscuous mode
	ret = pcap_set_promisc(pcap_handle, 1);
	if (ret != 0) {
		pcap_fatal("pcap_set_promisc", errbuf);
	}

	// Activate the handle
	ret = pcap_activate(pcap_handle);
	if (ret != 0) {
		pcap_fatal("pcap_activate", errbuf);
	}

	pcap_loop(pcap_handle, 3, caught_packet, NULL);

	pcap_close(pcap_handle);
	pcap_freealldevs(alldevs);
	return 0;
}

/* This function is called whenever pcap_loop captures a packet. It uses the header lengths
 * to split up the packet by layers and call the appropriate decode functions */
void caught_packet(u_char *user_data, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	u_int tcp_header_length;
	u_int total_header_size;
	u_int pkt_data_length;
	u_char *pkt_data;

	printf("=== Got a %d byte packet ===\n", cap_header->len);

	// Decode each part of the packet by adding the size of the header offset
	decode_ethernet(packet);
	decode_ip(packet+ETHER_HDR_LEN);
	tcp_header_length = decode_tcp(packet+ETHER_HDR_LEN+sizeof(struct ip_hdr));

	// Get the total header size of the data
	total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + tcp_header_length;
	// Get the data of the packet by adding the total header size
	pkt_data = (u_char *)packet + total_header_size;
	// Get the packet data length
	pkt_data_length = cap_header->len - total_header_size;

	// Print packet data
	if (pkt_data_length > 0) {
		printf("\t\t\t%u bytes of packet data\n", pkt_data_length);
		dump(pkt_data, pkt_data_length);
	} else {
		printf("\t\t\t No Packet Data\n");
	}
}

/* Function to display a fatal error based on the function that caused the failure
 * and then exit with status code 1 */
void pcap_fatal(const char *failed_in, const char *errbuf) {
	printf("Fatal error in %s: %s\n", failed_in, errbuf);
	exit(1);
}

/* Function to decode the ethernet packet we have recieved */
void decode_ethernet(const u_char *header_start) {
	const struct ether_hdr *ethernet_header;

	ethernet_header = (const struct ether_hdr *) header_start;

	printf("[[   Layer 2 :: Ethernet Header   ]]\n");
	printf("[   Source: %02x", ethernet_header->ether_src_addr[0]);

	for (int i = 0; i < ETHER_ADDR_LEN; i++) {
		printf(":%02x", ethernet_header->ether_src_addr[i]);
	}

	printf("\tType: %hu ]\n", ethernet_header->ether_type);
}

/* Function to decode the ip packet we have recieved */
void decode_ip(const u_char *header_start) {
	const struct ip_hdr *ip_header;

	ip_header = (const struct ip_hdr *) header_start;

	printf("\t((   Layer 3 ::: IP Header   ))\n");
	printf("\t(   Source: %s\t", inet_ntoa(*(struct in_addr *) &ip_header->ip_src_addr));
	printf("Dest: %s )\n", inet_ntoa(*(struct in_addr *) &ip_header->ip_dest_addr));
	printf("\t(  Type: %u\t", (u_int) ip_header->ip_type);
	printf("ID: %hu\tLength: %hu   )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));
}

/* Function to decode the tcp packet we have recieved */
u_int decode_tcp(const u_char *header_start) {
	u_int header_size;
	const struct tcp_hdr *tcp_header;

	tcp_header = (const struct tcp_hdr *) header_start;

	printf("\t\t{{   Layer 4 :::: TCP Header   }}\n");
	printf("\t\t{   Src Port: %hu   }\t", ntohs(tcp_header->tcp_src_port));
	printf("Dest Port: %hu }\n", ntohs(tcp_header->tcp_dest_port));
	printf("\t\t{   Seq #: %u\t", ntohl(tcp_header->tcp_seq));
	printf("Ack #: %u   }\n", ntohl(tcp_header->tcp_ack));
	printf("\t\t{   Header Size: %u\tFlags: ", header_size);
	
	if (tcp_header->tcp_flags & TCP_FIN) {
		printf("FIN ");
	}
	if (tcp_header->tcp_flags & TCP_SYN) {
                printf("SYN ");
        }
	if (tcp_header->tcp_flags & TCP_RST) {
                printf("RST ");
        }
	if (tcp_header->tcp_flags & TCP_PUSH) {
                printf("PUSH ");
        }
	if (tcp_header->tcp_flags & TCP_ACK) {
                printf("ACK ");
        }
	if (tcp_header->tcp_flags & TCP_URG) {
                printf("URG ");
        }

	printf(" }\n");

	return header_size;
}
