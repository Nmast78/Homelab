all: libnet libpcap nemesis pcap_net syn_flooding rst_hijack shroud

libnet:
	gcc -g libnet_test.c -o libnet_test -lnet

libpcap:
	gcc -g libpcap_test.c -o libpcap_test -lpcap

nemesis:
	gcc -g nemesis_test.c -o nemesis_test -lpcap

pcap_net:
	gcc -g libnet_libpcap.c -o libnet_libpcap -lpcap -lnet

syn_flooding:
	gcc -g syn_flooding.c -o syn_flooding -lnet

rst_hijack:
	gcc -g rst_hijack.c -o rst_hijack -lnet -lpcap

shroud:
	gcc -g shroud.c -o shroud -lnet -lpcap
