
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* defines the IP protcols, UDP, TCP, ICMP */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>

/* used to determine if the packet is ip, arp, etc. */
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <pcap.h>

#define PCAP_BUF_SIZE	100000
#define PCAP_SRC_FILE	2

/* traks how many packets a source ip has sent */
int pctCount[PCAP_BUF_SIZE];
/* how many unique packets have been sent, used to iterate through  */
int pctIdx = 0;
/* stores the ip address of the packet */
char pctIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];

void packetprocess(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void quickSort(int array[], int low, int high);
int partition(int array[], int low, int high);
void swap(int* num1, int* num2);

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
	
    quickSort(pctCount, 0, pctIdx);
	
	for (int i = (pctIdx); i >= 1; i--) {
		printf("ip: %18s, count: %d \n", pctIP[i], pctCount[i]);
	}
	return 0;
}

void packetprocess(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet){ /* where the packets are poked around with, some crazy shits happening here */
	const struct ether_header* ethernetHeader; /* used to determine wether the packet is an IP packet or not */
	/* check for TCP, UDP, ICMP, IP, IPV6 */
	const struct ip* ipHeader;
	char sourceIP[INET_ADDRSTRLEN];
   	char destIP[INET_ADDRSTRLEN];
	int loopcheck = 0;
   	
		
	/* TCP, UDP, ICMP */
   	ethernetHeader = (struct ether_header*)packet;
	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP){
		printf("%s", " IP, ");
		/* fill out the ip header, gets the info from ether header? unwraps it? */
		ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
		/* inet_ntop - convert IPv4 and IPv6 addresses from binary to text form*/
		/* we save the source and destination ip's into variables here */
		inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

		/* is the header TCP? */
		if (ipHeader -> ip_p == IPPROTO_TCP){
			printf("%s", "  TCP, ");
			
		/* fuck it, lets print the ip's too */
		printf("  src: %15s    dst: %15s ,", sourceIP, destIP);
		}
		
		/* is the header UDP? */
		if (ipHeader -> ip_p == IPPROTO_UDP){
			printf("%s", "  UDP, ");
			
			
		/* fuck it, lets print the ip's too */
		printf("  src: %15s    dst: %15s ,", sourceIP, destIP);
		}
		if (1==1) {
            for (int i = 0; i < pctIdx; i++) {
                if (strcmp(sourceIP, pctIP[i]) == 0) {
	            	pctCount[i] = pctCount[i] + 1;
					loopcheck = 1;				
                }
            }
		} 
	if (loopcheck == 0){
		
		strcpy(pctIP[pctIdx], sourceIP);
        pctCount[pctIdx] = 1;
		pctIdx = pctIdx + 1;	
	}
	loopcheck = 0;
		
	}	
	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_ARP){
		printf("%s", "  ARP, ");
		/* fuck it, lets print the ip's too */
		printf("  src: %15s,", sourceIP);
		
	}
	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_REVARP){
		printf("%s", "REVARP");
	}
	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPV6){
		printf("%s", "IPv6");
	}
	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_LOOPBACK){
		printf("%s", "LOOPbck");
	}
	/* line break, dont include it anywhere else */
	printf("\n");

}
/* https://www.geeksforgeeks.org/quick-sort/ */
/* Small function to swap two variables */
void swap(int* num1, int* num2){
	int temp = *num1;
	*num1 = *num2;
	*num2 = temp;
	return;
}
/* https://www.geeksforgeeks.org/swap-strings-in-c/ */
/* added this to swap around the PctIP array with their related counts, this shit took waaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay too long */
void cheekyswap(char *str1, char *str2){
	char *temp = (char *)malloc((strlen(str1) + 1) * sizeof(char));
	strcpy(temp, str1);
	strcpy(str1, str2); 
  	strcpy(str2, temp);
	free(temp);
}
/* function to find the pivot point (the last element of the specified region) 
   and sorts around the given pivot */
int partition(int array[], int low, int high){
	int pivot = array[high]; /* section of array to pivot around */
	int i = (low - 1); /* location of low element */
	for (int j = low; j <= high - 1; j++){
		if(array[j] < pivot){
				i++;
				swap(&array[i], &array[j]);
				cheekyswap(pctIP[i],pctIP[j] );
		}
	}
	swap(&array[i + 1], &array[high]);
	cheekyswap(pctIP[i +1],pctIP[high] );
	return (i + 1);
}

/* recursive function to sort the ip doddledoos */
/* low is the starting index, high is the end of the filled array */
void quickSort(int array[], int low, int high){
	if (low < high){
		int partitionIndex = partition(array, low, high);
		/* recursion :((((((( */
		quickSort(array, low, partitionIndex - 1);
		quickSort(array, partitionIndex + 1, high);

	}
}

	













