/*************************************************************************
	> File Name: tcpdump.cpp
	> Created Time: 2015年04月01日 星期三 21时58分38秒
 ************************************************************************/

#include<stdio.h>
#include<unistd.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<linux/if_ether.h>
//#include<linux/in.h>
#include<netinet/in.h>
#define BUFFER_MAX 2048
int main(int argc, char *argv[])
{
	int sock, n_read, proto;
	char buffer[BUFFER_MAX];
	char *ethhead, *iphead, *tcphead,
		 *udphead, *icmphead, *p;
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
	{
		fprintf(stdout, "create socket error\n");
		return 0;
	}

	while(1)
	{
		n_read = recvfrom(sock, buffer, 2048, 0, NULL, NULL);
		if(n_read < 42)
		{
			fprintf(stdout, "Incomplete header, packet corrupt\n");
			continue;
		}
		ethhead = buffer;
		p = ethhead;
		int n = 0xFF;
		printf("MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X ==> %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",p[6]&n, p[7]&n, p[8]&n, p[9]&n, p[10]&n, p[11]&n,p[0]&n, p[1]&n, p[2]&n,p[3]&n, p[4]&n, p[5]&n);
		uint16_t* hh = (uint16_t*)(p + 10);
		printf("-----\n \t%d \n------\n", hh[0]&0xFFFF);
		iphead = ethhead + 14;
		p = iphead + 12;
		printf("-----\n\tversion: %x, length: %x\n-----\n", (iphead[0]>>4)&0xF, iphead[0]&0xF);
		printf("-----\n\tlen: %d\n-----\n", ((uint16_t*)(iphead + 2))[0]&0xFFFF);
		printf("-----\n\tttl: %d\n-----\n", iphead[8]&0xFF);
		printf("-----\n\tcrc sum: %d\n-----\n", ((uint16_t*)(iphead + 10))[0]&0xFFFF);
		printf("IP: %d.%d.%d.%d => %d.%d.%d.%d\n",p[0]&0XFF, p[1]&0XFF, p[2]&0XFF, p[3]&0XFF,p[4]&0XFF, p[5]&0XFF, p[6]&0XFF, p[7]&0XFF);
		proto = (iphead + 9)[0];
		p = iphead + 20;
		printf("Protocol:");
		switch(proto)
		{
			case IPPROTO_ICMP: printf("ICMP\n");break;
			case IPPROTO_IGMP: printf("IGMP\n");break;
			case IPPROTO_IPIP: printf("IPIP\n");break;
			case IPPROTO_TCP:
			printf("-----TCP-----\n");
			printf("source port: %u,", (p[0]<<8)&0xFF00|p[1]&0xFF);
			printf("dest port: %u\n", (p[2]<<8)&0xFF00|p[3]&0xFF);
			printf("data number: %d\n",*((uint32_t*)(p+4))&0xFFFF);
			printf("ack numner: %d\n", *((uint32_t*)(p+8))&0xFFFF);
			printf("tcp length: %d  %d\n", (p[12]>>4)&0xF, p[12]&0xF);
			printf("wnd size: %d\n", (*(uint16_t*)(p+14))&0xFF);
			printf("crc: %d\n", (*(uint16_t*)(p + 16))&0xFF);
			printf("-----\n");
			break;
			case IPPROTO_UDP:
			printf("-----UDP-----\n");
			printf("source port: %u,", (p[0]<<8)&0xFF00|p[1]&0xFF);
			printf("dest port: %u\n", (p[2]<<8)&0xFF00|p[3]&0xFF);
			printf("-----\n");
			break;
			case IPPROTO_RAW: printf("RAW\n");break;
			default: printf("Unkown, please query in include/linux/in.h\n");
		}

		for(int i=0;i<n_read/10;++i)
		{
			for(int j=0;j<10;++j)
			{
				printf("%x ", buffer[10*i + j]&0xFF);
			}
			printf("          ");
			for(int j=0;j<10;++j)
			{
				printf("%c ", buffer[10*i + j]);
			}
			printf("\n");
		}
		for(int i=0;i<n_read%10;++i)
		{
			printf("%x ", buffer[n_read/10*10 + i]&0xFF);	
		}
		printf("          ");
		for(int i=0;i<n_read%10;++i)
		{
			printf("%c ", buffer[n_read/10*10 + i]);
		}
		printf("\n");
	}
}
