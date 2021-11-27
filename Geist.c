#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

// Some global variables :^^^^^^^)
int sock_raw;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source, dest;
FILE * logfile;

void ProcessPacket(unsigned char*, int);
void print_ip_header(unsigned char * , int);
void print_tcp_header(unsigned char* , int);
void print_icmp_header(unsigned char* , int);
void print_udp_header(unsigned char* , int);
void Printdata(unsigned char* , int);



int main(){ 
    //Declaring variables 
    socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    struct sockaddr saddr;
    struct in_addr in;
    int saddr_size, data_size;

    unsigned char *buffer = (unsigned char *)malloc(66536); // Giga fucking malloc
    logfile=fopen("potential log.txt", "w");
    printf("Log file opening...\n");
        if (logfile==NULL){
            printf("\nUnable to open log.file, maybe some permission errors? sudo it bitch boy you won't");
        }
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0){
        puts("skill issue\n");
        return 1;
    }
    while (1)
    {
        /* we testing */
        saddr_size = sizeof saddr;
        // we get a little packets;
        data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);
        if (data_size < 0){
            puts("skill issue 2 can't get no data");
        }
        ProcessPacket(buffer, data_size);
    }
    pclose(sock_raw);
    printf("bravo you literally just copied some code off the internet and you claim it's yours");
    return 1;
}

// This function finds out the header and then makes a simple switch case decision on what to do with it

void ProcessPacket(unsigned char * buffer, int size) {
    // ok first of all we get the IP Header;
    struct iphdr *iph = (struct iphdr*)buffer;
    ++total;
    switch (iph->protocol) // ok we check da protocol
    {
        case 1:  //ICMP Protocol
			++icmp;
			print_ip_header(buffer,size);
			break;
		
		/*case 2:  //IGMP Protocol
		/	++igmp;
		/	break;
		
		/case 6:  //TCP Protocol
		/	++tcp;
			print_tcp_packet(buffer , size);
			break;
		
		case 17: //UDP Protocol
			++udp;
			print_udp_packet(buffer , size);
			break;
		*/
		default: //Some Other Protocol like ARP etc.
			++others;
            print_ip_header(buffer, size);
			break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r",tcp,udp,icmp,igmp,others,total);

};

void fprintfbutgood(int fid, char* coolwords, char* string){
    fprintf(fid, &string);
    printf("%d %d", &coolwords, &string);  
    }

// ip header print:


void print_ip_header(unsigned char* Buffer, int Size){

    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    char ProtocolText = "Protocol:  ";
    char SIP    = "Source Port: ";
    char DIP    = "Destination Port: ";
    char Ver    = "Protocol Verison: ";
    printf("\n");
    printf("IP HEADER");





    fprintf(logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile,"   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile,"   |-Source IP        : %d\n",inet_ntoa(source.sin_addr));
	fprintf(logfile,"   |-Destination IP   : %d\n",inet_ntoa(dest.sin_addr));
/*
    fprintfbutgood(logfile, Ver, iph->version);
    fprintfbutgood(logfile, ProtocolText, iph->protocol);
    fprintfbutgood(logfile, SIP,  inet_ntoa(source.sin_addr));
    fprintfbutgood(logfile, DIP,  inet_ntoa(dest.sin_addr));
*/
}