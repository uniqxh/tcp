/*
 * =====================================================================================
 *
 *       Filename:  arp.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2015年04月12日 14时26分56秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
/*************************************************************************
	> File Name: arp.h
	> Created Time: 2015年04月12日 星期日 14时26分56秒
 ************************************************************************/
typedef struct _ethhdr
{
	uint8_t dst[6]; //destination ethernet address
	uint8_t src[6]; //source ethernet address
	uint16_t type;   //type or length
}ETHHDR,*PETHHDR;
typedef struct _arphdr
{
	uint8_t  ht;		//hardware type
	uint8_t  pt;		//protocol type
	uint16_t hl;		//hardware length
	uint16_t pl;		//protocol length
	uint16_t op;		//arp/rarp operation
	uint8_t  s_eth[6];//sender ethernet address
	uint8_t  s_ip[4];	//sender ip address
	uint8_t  t_eth[6];//target ethernet address
	uint8_t  t_ip[4];	//target ip address
}ARPHDR,*PARPHDR;
typedef struct arpPacket
{
	ETHHDR ethhdr;
	ARPHDR arphdr;
}ARPPACKET,*PARPPACKET;
