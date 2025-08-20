#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include "hacking-network.h"
#include "hacking.h"

void packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Usage: %s eth0\n", argv[0]);
		exit(1);
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	char filter_exp[] = "tcp port 12345"; // Our filter expression
	struct bpf_program fp; // The compiled filter expression
	bpf_u_int32 net, mask; // The netmask and IP (net) of our sniffing device

	printf("Sniffing on device %s\n", dev);


	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		printf("Can't get netmask for device %s\n", dev);
		exit(1);
	}

	// Open eth0 for sniffing
	handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL) {
		printf("Couldn't open device %s: %s\n", dev, errbuf);
		exit(1);
	}

	// Filter traffic to only look for traffic on port
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}

	// Capture 3 packets
	pcap_loop(handle, 1, packet_handler, NULL);
}

/* Function to handle the packets that are captured by our listener */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	const struct ether_hdr *ethernet;
	const struct ip_hdr *ip;
	const struct tcp_hdr *tcp;
	u_int total_header_size, pkt_data_length, tcp_header_length;
	u_char *pkt_data;

	printf("---- Got a %d byte packet ----\n", header->len);

	ethernet = (const struct ether_hdr *) packet;
	ip = (const struct ip_hdr *)(packet + ETHER_HDR_LEN);
	tcp = (const struct tcp_hdr *)(packet + ETHER_HDR_LEN + sizeof(struct ip_hdr));

	// Print out Ethernet layer information
	printf("[[   Layer 2 :: Ethernet Header   ]]\n");
	printf("[   Source: %02x", ethernet->ether_src_addr[0]);
	for (int i = 1; i < ETHER_ADDR_LEN; i++) {
		printf(":%02x", ethernet->ether_src_addr[i]);
	}
	printf("\tType: %hu ]\n", ethernet->ether_type);

	// Print out IP layer information
	printf("\t((   Layer 3 ::: IP Header   ))\n");
	printf("\t(		Source: %s\t", inet_ntoa(*(struct in_addr *) &ip->ip_src_addr));
	printf("Dest: %s )\n", inet_ntoa(*(struct in_addr *) &ip->ip_dest_addr));
	printf("\t(  Type: %u\t", (u_int) ip->ip_type);
	printf("ID: %hu\tLength: %hu   )\n", ntohs(ip->ip_id), ntohs(ip->ip_len));

	// Print out the TCP layer information
	printf("\t\t{{   Layer 4 :::: TCP Header   }}\n");
	printf("\t\t{   Src Port: %hu   }\t", ntohs(tcp->tcp_src_port));
	printf("Dest Port: %hu }\n", ntohs(tcp->tcp_dest_port));
	printf("\t\t{   Seq #: %u\t", ntohl(tcp->tcp_seq));
	printf("Ack #: %u   }\n", ntohl(tcp->tcp_ack));
	printf("\t\t\tFlags: ");
	if (tcp->tcp_flags & TCP_FIN) {
		printf("FIN ");
	}
	if (tcp->tcp_flags & TCP_SYN) {
                printf("SYN ");
        }
	if (tcp->tcp_flags & TCP_RST) {
                printf("RST ");
        }
	if (tcp->tcp_flags & TCP_PUSH) {
                printf("PUSH ");
        }
	if (tcp->tcp_flags & TCP_ACK) {
                printf("ACK ");
        }
	if (tcp->tcp_flags & TCP_URG) {
                printf("URG ");
        }
	printf(" }\n");

	// Get the total header size of the data
	tcp_header_length = sizeof(struct tcp_hdr);
	total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + tcp_header_length;

	// Get the data of the packet by adding the total header size
	pkt_data = (u_char *)packet + total_header_size;
	// Get the packet data length
	pkt_data_length = header->len - total_header_size;

	// Print packet data
	if (pkt_data_length > 0) {
		printf("\t\t\t%u bytes of packet data\n", pkt_data_length);
		dump(pkt_data, pkt_data_length);
	} else {
		printf("\t\t\t No Packet Data\n");
	}
}
