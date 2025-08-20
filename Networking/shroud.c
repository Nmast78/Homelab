/* THIS IS A DEFENSE PROGRAM TO ALERT A SCANNER WITH A BUNCH OF FALSE POSITIVES
   PUT THIS ON THE MACHINE THAT IS BEING SCANNED 
   
   FUTURE UPGRADES:
        - Expand to spoof banners as well as just open ports
   */

#define _DEFAULT_SOURCE
#include <libnet.h>
#include <pcap.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>

#define MAX_EXISTING_PORTS 30

void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int set_packet_filter(pcap_t *, struct in_addr *, u_short *);

struct data_pass {
    intptr_t libnet_handle;
    u_char *packet;
};

/* Main function to initialize capture device and start cpature loop */
int main(int argc, char *argv[]) {
    libnet_t *context;
    pcap_t *pcap_handle;
    char errbuf[LIBNET_ERRBUF_SIZE];
    u_long target_ip;
    u_short existing_ports[MAX_EXISTING_PORTS];
    struct data_pass critical_libnet_data;
    
    // Determine usage and validate # of arguments
    if (argc < 2 || (argc > MAX_EXISTING_PORTS+2)) {
        if (argc > 2) {
            printf("Limited to tracking %d existing ports.\n", MAX_EXISTING_PORTS);
        } else {
            printf("Usage: %s <IP to shroud> [existing ports...]\n", argv[0]);
        }
        exit(1);
    }

    // Open handle to session state for building a packet
    context = libnet_init(LIBNET_RAW4, NULL, errbuf);

    // Get target IP from input
    target_ip = libnet_name2addr4(context, argv[1], LIBNET_RESOLVE);

    // Get all ports from input
    for (int i = 2; i < argc; i++) {
        existing_ports[i-2] = (u_short) atoi(argv[i]);
    }
    existing_ports[argc-2] = 0;

    // Open a libpcap handle to the device
    pcap_handle = pcap_open_live(context->device, 128, 1, 1000, errbuf);

    // Initalize libnet packet (intptr_t is guaranteed to be big enough to hold a pointer)
    critical_libnet_data.libnet_handle = (intptr_t)context;
    critical_libnet_data.packet = NULL;

    // Seed the random nunmber generator for packet
    libnet_seed_prand(context);

    // Call the set packet filter function
    set_packet_filter(pcap_handle, (struct in_addr *)&target_ip, existing_ports);

    // Loop for packets
    pcap_loop(pcap_handle, -1, caught_packet, (u_char *)&critical_libnet_data);

    pcap_close(pcap_handle);
}

/* Function to set the BPF filter for our shrouding technique */
int set_packet_filter(pcap_t *pcap_hdl, struct in_addr *target_ip, u_short *ports) {
    char filter_string[90 + (25 * MAX_EXISTING_PORTS)];
    char *str_ptr;
    int i = 0;
    struct bpf_program filter;

    sprintf(filter_string, "dst host %s and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0",
        inet_ntoa(*target_ip));

    // If there is at least one existing port...
    if (ports[0] != 0) {
        str_ptr = filter_string + strlen(filter_string);
        if (ports[1] == 0) { // Only one existing port
            sprintf(str_ptr, " and not dst port %hu", ports[i]);
        } else {
            sprintf(str_ptr, " and not (dst port %hu", ports[i++]);
            while (ports[i] != 0) {
                str_ptr = filter_string + strlen(filter_string);
                sprintf(str_ptr, " or dst port %hu", ports[i++]);
            }
            strcat(filter_string, ")");
        }
    }

    printf("DEBUG: filter string is \'%s\'\n", filter_string);

    // Comile filter string
    if (pcap_compile(pcap_hdl, &filter, filter_string, 0, 0) == -1) {
        printf("Error compiling BPF filter\n");
        exit(1);
    }

    // Set filter string
    if (pcap_setfilter(pcap_hdl, &filter) == -1) {
        printf("Error setting filter string\n");
        exit(1);
    }
}

/* Function that is called when we capture packets from our listening device */
void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
    struct data_pass *data_passed;
    libnet_t *context;
    struct libnet_ipv4_hdr *IPHdr;
    struct libnet_tcp_hdr *TCPHdr;
    libnet_ptag_t tcp_tag, ip_tag = 0;
    int byte_count, packet_size = LIBNET_IPV4_H + LIBNET_TCP_H;

    // Cast passed user aggs back to data_pass struct
    data_passed = (struct data_pass *) user_args;

    // Cast data_passed parameter to libnet_t
    context = (libnet_t *) (data_passed->libnet_handle);

    // Get IP and TCP headers
    IPHdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
    TCPHdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_IPV4_H);

    // Construct TCP header
    tcp_tag = libnet_build_tcp(htons(TCPHdr->th_dport), // Source TCP port (pretend we are the dst)
            htons(TCPHdr->th_sport),                    // Destination port (send back to src)
            htonl(TCPHdr->th_ack),                      // Sequence number
            htonl((TCPHdr->th_seq) + 1),                // Ack number
            TH_SYN | TH_ACK,                            // Control flags
            libnet_get_prand(LIBNET_PRu16),             // Window size
            0,                                          // Checksum (0 to autofill)
            0,                                          // Urgent pointer
            LIBNET_TCP_H,                               // Total length of the TCP packet
            NULL,                                       // Payload
            0,                                          // Length of payload
            context,                                    // Pointer to libnet_t context
            0                                     // Build a new header
    );

    if (tcp_tag == -1) {
        printf("There was an error creating the tcp header: %s\n", libnet_geterror(context));
        exit(1);
    }

    // Build IP header
    ip_tag = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H, // Size of the packet
        0,                 // Type of service bits
        libnet_get_prand(LIBNET_PRu16), // IP identification number
        0,                              // Fragmenation bits and offset
        libnet_get_prand(LIBNET_PR8),   // TTL (time to live)
        IPPROTO_TCP,                    // Transport protcol
        0,                              // Checksum (0 means autofill)
        IPHdr->ip_dst.s_addr,           // Source IP address (pretend we are dst)
        IPHdr->ip_src.s_addr,           // Destination IP address (send back to source)
        NULL,                           // Payload or NULL
        0,                              // Payload length or 0
        context,                        // Pointer to libnet_t context
        0                          // Build new header
    );

    if (ip_tag == -1) {
        printf("There was an error creating the ip header: %s\n", libnet_geterror(context));
        exit(1);
    }

    // Write packet
    byte_count = libnet_write(context);

    if (byte_count == -1) {
        printf("ERROR: libnet_write() failed: %s\n", libnet_geterror(context));
        exit(1);
    }

    if (byte_count < packet_size) {
        printf("WARNING: Incomplete packet written: %d of %d written: %s\n", byte_count, packet_size, libnet_geterror(context));
        exit(1);
    }

    // Clear the packet so we can send multiple
    libnet_clear_packet(context);
}