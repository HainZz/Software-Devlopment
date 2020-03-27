/* https://elf11.github.io/2017/01/22/libpcap-in-C.html */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#include <pcap.h>

#define PCAP_BUF_SIZE	100000
#define PCAP_SRC_FILE	2

void packetprocess();

int main(int argc, char **argv){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *file;
	
	if(argc != 2){ /* checks that a file has been specified in execution */
		printf("please include filename in command {%s filename.pcap}\n", argv[0]);
		return -1;
	}

        /* opens the file, if the specified file is empty an error message is returned to stderr */
	file = pcap_open_offline(argv[1], errbuf);
	if (file == NULL){
		fprintf(stderr,"failed to load pcap, %s\n", errbuf); 
		return 0;
	}

	if(pcap_loop(file,0,packetprocess, NULL) < 0){
		fprintf(stderr,"process failed on pcap_loop, %s\n", pcap_geterr(file)); 
		return 0;
	}

	return 0;
}


void packetprocess(){ /* where the packets are poked around with, some crazy shits happening here */


}
