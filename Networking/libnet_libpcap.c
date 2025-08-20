/* FUTURE UPGRADES:
    - Scan all ports and/or allow users to pick which ports to scan
    - Try to get around the shroud program
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libnet.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <time.h>

int answer = 0;

/* Usage function if the user doesn't correctly initialize the program */
void usage(char *name) {
    printf ("%s - Simple SYN scan\n", name);
    printf ("Usage: %s -i ip_address_to_scan\n", name);
    exit(1);
}

/* Function to handle captured packets. Called from pcap_dispatch after we send a packet */
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    // Use offset to get to tcp header and cast to tcphdr struct
    struct tcphdr *tcp = (struct tcphdr *) (packet + LIBNET_ETH_H + LIBNET_IPV4_H);

    // Determine what flags are set to see if the port is open or closed
    if ((tcp->syn && tcp->rst) || (tcp->rst)) {
        printf ("Port %d --> CLOSED\n", ntohs(tcp->source));
    } else if (tcp->syn && tcp->ack) {
        printf ("Port %d --> OPEN\n", ntohs(tcp->source));
    }

    answer = 0;
}

/* Main function to setup listener, construct, and send packets */
int main(int argc, char *argv[]) {
    libnet_t *context; // Libnet context
    pcap_t *handle; // Libpcap handle to capture packets
    char errbuf[LIBNET_ERRBUF_SIZE];
    char libpcap_errbuf[PCAP_ERRBUF_SIZE]; // Error message buffer
    int opt; // Return code for getopt function
    in_addr_t ip_address; // IP address to scan
    const char *device; // Name of device used for packet injection
    u_int32_t myipaddr; // IP address of the device this code is running on
    bpf_u_int32 netp, maskp; // IPV4 address and mask in network byte order
    libnet_ptag_t tcp = 0; // libnet protocol block for tcp header
    libnet_ptag_t ipv4 = 0; // libnet protocol block for ip header
    libnet_ptag_t ethernet = 0; // libnet protcol block for ethernet header
    int ports[] = { 21, 22, 23, 25, 53, 79, 80, 110, 139, 443, 445, 0 }; // Ports to scan
    struct bpf_program fp;    // compiled filter

    if (argc != 3) {
        usage(argv[0]);
    }

    //////// Creating the libnet Context: For the construction and injection of packets ////////
    // Create the libnet environment
	context = libnet_init(LIBNET_RAW4, NULL, errbuf);
	if (context == NULL) {
		printf("Error opening context: %s\n", errbuf);
		exit(1);
	}

    // Get the target IP address from the arguments
    while ((opt = getopt(argc, argv, "i:")) != -1) {
        switch (opt) {
            case 'i':
                if ((ip_address = libnet_name2addr4(context, optarg, LIBNET_RESOLVE)) == -1) {
                    printf("Invalid Address");
                    usage(argv[0]);
                }
                break;
            default:
                break;
        }
    }

    // Write our filter
    //char *filter = "(tcp[13] == 0x14) || (tcp[13] == 0x12) || (tcp[13] == 0x04)"; // Filter conditions (RST+ACK || SYN+ACK)
    char filter[256];
    snprintf(filter, sizeof(filter), "(tcp[13] == 0x14) || (tcp[13] == 0x12) || (tcp[13] == 0x04) and src host %s", inet_ntoa(*(struct in_addr*)&ip_address));

    // Get the IP address of this device
    if ((myipaddr = libnet_get_ipaddr4(context)) == -1) {
        printf("Error getting IP of this device.\n");
        exit(1);
    }

    // Get the device we are using for libpcap
    if ((device = libnet_getdevice(context)) == NULL) {
        printf("Device is NULL, packet capture may be broken\n");
    }

    //////// Creating the libpcap Context: This is for packet capturing ////////

    // Open the device with pcap
    if ((handle = pcap_open_live(device, 1500, 0, 2000, libpcap_errbuf)) == NULL) {
        printf("Handle is NULL, could not open device for capturing: %s\n", libpcap_errbuf);
        exit(1);
    }

    // Set nonblocking
    if (pcap_setnonblock(handle, 1, libpcap_errbuf) != 0) {
        printf("Unable to set NonBlock: %s\n", libpcap_errbuf);
        exit(1);
    }

    // Set the capture filter
    if (pcap_lookupnet(device, &netp, &maskp, libpcap_errbuf) == -1) {
        printf("Net lookup error: %s\n", libpcap_errbuf);
        exit(1);
    }

    // Compile our filter string into a filter program
    if (pcap_compile(handle, &fp, filter, 0, maskp) != 0) {
        printf("Error compiling filter: %s\n", pcap_geterr(handle));
        exit(1);
    }

    // Set the pcap filter
    if (pcap_setfilter(handle, &fp) != 0) {
        printf("Error setting the filter: %s\n", pcap_geterr(handle));
        exit(1);
    }

    // Loop through all the ports, generate headers, write the packet, and capture the reply
    for (int i = 0; (ports[i] != 0); i++) {
        // Build the TCP header
        tcp = libnet_build_tcp (libnet_get_prand (LIBNET_PRu16),    /* src port */
                ports[i],    /* destination port */
                libnet_get_prand (LIBNET_PRu16),    /* sequence number */
                0,    /* acknowledgement */
                TH_SYN,    /* control flags */
                512,    /* window */
                0,    /* checksum - 0 = autofill */
                0,    /* urgent */
                LIBNET_TCP_H,    /* header length */
                NULL,    /* payload */
                0,    /* payload length */
                context,    /* libnet context */
                tcp   /* protocol tag */
        );

        if (tcp == -1) {
            printf("Unable to build tcp header\n");
            exit(1);
        }

        // Build the IP header
        ipv4 = libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H,    /* length */
                0,    /* TOS */
                libnet_get_prand (LIBNET_PRu16),    /* IP ID */
                0,    /* frag offset */
                127,    /* TTL */
                IPPROTO_TCP,    /* upper layer protocol */
                0,    /* checksum, 0=autofill */
                myipaddr,    /* src IP */
                ip_address,    /* dest IP */
                NULL,    /* payload */
                0,    /* payload len */
                context,    /* libnet context */
                ipv4  /* protocol tag */
        );

        if (ipv4 == -1) {
            printf("Unable to build the IP header\n");
            exit(1);
        }

        // Write the packet
        if (libnet_write(context) == -1) {
            printf("Unable to send the packet: %s\n", libnet_geterror(context));
            continue;
        }

        // Capture the reply
        answer = 1;
        time_t tv = time(NULL);

        while (answer) {
            pcap_dispatch(handle, -1, packet_handler, NULL);

            if ((time(NULL) - tv) > 3) {
                answer = 0;
                printf("Port: %d appears to be filtered\n", ports[i]);
            }
        }
    }

    libnet_destroy(context);
    return 0;
}