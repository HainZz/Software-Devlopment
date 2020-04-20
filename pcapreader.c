/*references: 
	https://www.devdungeon.com/content/using-libpcap-c#packet-type - last accessed - 27/03/20
	https://www.geeksforgeeks.org/quick-sort/ - last accessed 09/04/20
*/
/* standard libraries */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* contains structs to dismantle each pcap and retrieve info */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

/* used to extract each packet for processing */
#include <pcap.h>

#define PCAP_BUF_SIZE	100000
#define PCAP_SRC_FILE	2

/* tracker variables */
int pctCount[PCAP_BUF_SIZE];
int srcPortCount[PCAP_BUF_SIZE];
int udpCount;
int tcpCount;
int arpCount;
int etcCount;


/* how many unique packets/ports have been sent, used to iterate through  */
int pctIdx = 0;
int PortIdx = 0;
/* stores the ip address/ port numbers of the packets */
char pctIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];
int PortNum[PCAP_BUF_SIZE];


/* pre calls the functions to allow main() to be topmost */
void printout();
void packetprocess(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void quickSort(int array[], int low, int high, char strArray[PCAP_BUF_SIZE][INET_ADDRSTRLEN], int intarray[],int mode);
int partition(int array[], int low, int high, char strArray[PCAP_BUF_SIZE][INET_ADDRSTRLEN],int intarray[], int mode);
void swap(int* num1, int* num2);
void stringswap(char *str1, char *str2);


/* takes 2 args, argc holds the number of arguments passed, argv points to each argument passed  */
int main(int argc, char **argv){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *file;
	
	/* checks that a file has been specified in execution */
	if(argc != 2){ 
		printf("please include filename in command {%s filename.pcap}\n", argv[0]);
		return -1;
	}

    /* opens the file, if the specified file is empty an error message is returned to stderr */
	file = pcap_open_offline(argv[1], errbuf);
	if (file == NULL){
		fprintf(stderr,"failed to load pcap, %s\n", errbuf); 
		return 0;
	}

	/* calles packetprocess with each seperate pcap file until all packets have been checked */
	if(pcap_loop(file,0,packetprocess, NULL) < 0){
		fprintf(stderr,"process failed on pcap_loop, %s\n", pcap_geterr(file)); 
		return 0;
	}
	/* sorts the ip source count then prints the output, mode 1 = ip, 2 = port */
    quickSort(pctCount, 0, pctIdx, pctIP, PortNum, 1);
	quickSort(srcPortCount, 0, PortIdx, pctIP, PortNum, 2);
	printout();
	

	return 0;
}

void packetprocess(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet){ /* where the packets are poked around with, some crazy shits happening here */
	const struct ether_header* ethernetHeader; /* used to determine the ether type of the packet */
	const struct ip* ipHeader; /* if the packet is of ip ether type, this determines the ip protocol */
	const struct tcphdr* tcpHeader; /* if the packet uses tcp, this gives the infomation about it */
	const struct udphdr* udpHeader;/* if the packet uses udp, this gives the infomation about it */
	
	char sourceIP[INET_ADDRSTRLEN];
   	char destIP[INET_ADDRSTRLEN];

	int loopcheckPct = 0;
	int loopcheckPrt = 0;
   	int port;
	
	/* gets ethernet related information from the packet */
   	ethernetHeader = (struct ether_header*)packet;

	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP){/* ip check */
		printf("%s", "  IP, ");
		/* gets ip related information from the packet */
		ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
		/* inet_ntop - convert IPv4 and IPv6 addresses from binary to text form*/
		/* we save the source and destination ip's into variables here */
		inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

	   	/* if packet is TCP packet infomation is extracted and tallied */
		if (ipHeader -> ip_p == IPPROTO_TCP){
			tcpHeader = (struct tcphdr*)packet;
			tcpCount = tcpCount + 1;
			port = tcpHeader -> th_sport;
			printf("%s", "  TCP, ");
			printf("  src: %15s    dst: %15s ,", sourceIP, destIP);
			printf("  sport: %10d  dport: %10d", tcpHeader -> th_sport,tcpHeader -> th_dport);
			
		}
		
		/* if packet is UDP packet infomation is extracted and tallied */
		if (ipHeader -> ip_p == IPPROTO_UDP){
			udpHeader = (struct udphdr*)packet;
			udpCount = udpCount + 1;
			port = udpHeader -> uh_sport;
			printf("%s", "  UDP, ");
			printf("  src: %15s    dst: %15s ,", sourceIP, destIP);
			printf("  sport: %10d  dport: %10d", udpHeader -> uh_sport,udpHeader -> uh_dport);
		}

		/* checks if the ip has sent packets before
		if it has its counter is incremented, if it hasnt a new counter is created */	
    	for (int i = 0; i < pctIdx; i++) {
     	    if (strcmp(sourceIP, pctIP[i]) == 0) {
		    	pctCount[i] = pctCount[i] + 1;
				loopcheckPct = 1;				
   	      }
		}
		/* add new ip */
		if (loopcheckPct == 0){	
			strcpy(pctIP[pctIdx], sourceIP);
   	 	    pctCount[pctIdx] = 1;
			pctIdx = pctIdx + 1;	
		}

		/* checks if the port has beed used before
		if it has its counter is incremented, if it hasnt a new counter is created */	
    	for (int i = 0; i < PortIdx; i++) {
     	    if (port == PortNum[i]) {
		      	srcPortCount[i] = srcPortCount[i] + 1;
				loopcheckPrt = 1;				
   	      }
		}
		/* add new port */
		if (loopcheckPrt == 0){	
			PortNum[PortIdx] = port;
   	 	    srcPortCount[PortIdx] = 1;
			PortIdx = PortIdx + 1;	
		}
		loopcheckPct = 0; loopcheckPrt = 0; 
	}	
	/* if ethertype is arp add to related tally */
	else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_ARP){
		printf("%s", "  ARP, ");
		arpCount = arpCount + 1;
			
	}

	/* ether types not defined in the struct, added from testing */
	else if (ntohs(ethernetHeader->ether_type) == 35020){
		printf("%s", "  LLDP ");
		etcCount = etcCount + 1;
	}
	else if (ntohs(ethernetHeader->ether_type) == 105){
		printf("%s", "  STP (spanning tree) ");
		etcCount = etcCount;
	}
	else{
		etcCount = etcCount + 1;
	}
	printf("  ether type: %d", ntohs(ethernetHeader -> ether_type));

	/* line break, dont include it anywhere else */
	printf("\n");
}

/* function to printout the end stats */
void printout(){
	printf("\n\n");
	printf("TCP packet count: %d\n", tcpCount);
	printf("UDP packet count: %d\n", udpCount);
	printf("ARP packet count: %d\n", arpCount);
	printf("other protocol count: %d\n", etcCount);
	printf("total packet count: %d\n", tcpCount + udpCount + arpCount + etcCount);
	printf("source ip that sent the most packets: %s\n", pctIP[pctIdx]);
	printf("top 5 most packet sending ip's: \n");
	for (int i = pctIdx; i != pctIdx - 5; i--){
		printf("%5sip: %15s   count: %6d\n"," ",pctIP[i], pctCount[i]);
	}
	printf("source port count: \n");
	for (int i = PortIdx; i != 0; i--){
		printf("%5sport num: %7d     count: %6d\n"," ",PortNum[i], srcPortCount[i]);
	}

}


/* Small function to swap two variables */
void swap(int* num1, int* num2){
	int temp = *num1;
	*num1 = *num2;
	*num2 = temp;
	
	return;
}

/* added this to swap around the PctIP array with their related counts, this shit took waaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay too long */
void stringswap(char *str1, char *str2){
	char *temp = (char *)malloc((strlen(str1) + 1) * sizeof(char));
	strcpy(temp, str1);
	strcpy(str1, str2); 
  	strcpy(str2, temp);
	free(temp);
}

/* https://www.geeksforgeeks.org/quick-sort/ - last accessed 09/04/20*/
/* function to find the pivot point (the last element of the specified region) 
   and sorts around the given pivot */
int partition(int array[], int low, int high, char strArray[PCAP_BUF_SIZE][INET_ADDRSTRLEN],int intarray[], int mode){
	int pivot = array[high]; /* section of array to pivot around */
	int i = (low - 1); /* location of low element */
	for (int j = low; j <= high - 1; j++){
		if(array[j] < pivot){
				i++;
				swap(&array[i], &array[j]);
				if (mode == 1){
					stringswap(strArray[i],strArray[j]);
				}
				else
				{
					swap(&intarray[i], &intarray[j]);
				}
				
		}
	}
	swap(&array[i + 1], &array[high]);
	if (mode == 1){
		stringswap(strArray[i +1],strArray[high]);
	}
	else
	{
		swap(&intarray[i + 1], &intarray[high]);
	}
	return (i + 1);
}

/* https://www.geeksforgeeks.org/quick-sort/ - last accessed 09/04/20*/
/* recursive function to sort the ip doddledoos */
/* low is the starting index, high is the end of the filled array */
void quickSort(int array[], int low, int high, char strArray[PCAP_BUF_SIZE][INET_ADDRSTRLEN], int intarray[],int mode){
	if (low < high){
		int partitionIndex = partition(array, low, high, strArray, intarray, mode);
		quickSort(array, low, partitionIndex - 1, strArray, intarray, mode);
		quickSort(array, partitionIndex + 1, high, strArray, intarray, mode);

	}
}

	


