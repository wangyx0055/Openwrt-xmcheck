/*
 * =====================================================================================
 *
 *       Filename:  xmcheck.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  09/25/2013 11:45:51 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Dr. Fritz Mehner (mn), mehner@fh-swf.de
 *        Company:  FH Südwestfalen, Iserlohn
 *
 * =====================================================================================
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <errno.h>
#include	<sys/time.h>


#include "xmcheck.h"

int init_rawsock()
{
	int fd;
	char hwaddr[48];
	int optval=1;

	if ((fd = socket(PF_PACKET,  SOCK_RAW, htons(ETH_P_ALL)))== -1)
	{
		lprint("socket error!\n");
		return 1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
		lprint("setsockopt error!\n");
	}
	struct ifreq ifr;
	const char *ifname = "eth0";
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { 
		lprint("ioctl(SIOCGIFHWADDR)");
	}    
	memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
            char buffer[256];
            sprintf(buffer, "Interface %.16s is not Ethernet", ifname);
            printf("%s", buffer);
        } 

#define NOT_UNICAST(e) ((e[0] & 0x01) != 0)
	if (NOT_UNICAST(hwaddr)) {
		char buffer[256];
		sprintf(buffer,	"Interface %.16s has broadcast/multicast MAC address??", ifname);
		printf("%s",buffer);
	}

	/* Sanity check on MTU */
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) { 
		printf("ioctl(SIOCGIFMTU)");
	}    
	if (ifr.ifr_mtu < ETH_DATA_LEN) {
		char buffer[256];
		sprintf(buffer, "Interface %.16s has MTU of %d -- should be %d.  You may have serious connection problems.",
				ifname, ifr.ifr_mtu, ETH_DATA_LEN);
		printf("%s\n", buffer);
	}    

	struct sockaddr_ll sa;
	/* Get interface index */
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { 
		printf("ioctl(SIOCFIGINDEX): Could not get interface index");
	}    
	sa.sll_ifindex = ifr.ifr_ifindex;

	/* We're only interested in packets on specified interface */
	if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) { 
		printf("bind");
	}

	return fd;
}

void parse_ppp(char *packet){
	struct pppoe_hdr *pppoehdr;
	pppoehdr = (struct pppoe_hdr*)(packet + sizeof(struct ethhdr));
	switch(pppoehdr->code){
		case PADI_CODE:
			lprint("This is a PADI packet!\n");
			break;
		case PADO_CODE:
			lprint("This is a PADO packet!\n");
#if 0
			int status ;
			status = pthread_mutex_lock(&mode_mutex);
			if(status != 0)
				err_abort (status, "mutex lock");
			mode = pppoe;
			pthread_mutex_unlock(&mode_mutex);
			if(status != 0)
				err_abort (status, "mutex unlock");
#endif
			break;
		case PADR_CODE:
			lprint("This is a PADR packet!\n");
			break;
		case PADS_CODE:
			lprint("This is a PADS packet!\n");
			break;
	}
}
void recv_main(){
	int fd;
	struct ethhdr *ether;
	char buf[10240];
	ssize_t n;
	fd = init_rawsock();
	while (1)
	{
#if 0
		pthread_mutex_lock(&mode_mutex);
		if(mode != none)	
			break;
		pthread_mutex_unlock(&mode_mutex);
#endif

		n = recv(fd, buf, sizeof(buf), 0);
		if (n == -1)
		{
			lprint("recv error!\n");
			break;
		}else if (n==0)	continue;

		ether = (struct ethhdr *)buf;
		lprint("%d____%#x\n", sizeof(struct ethhdr), ntohs(ether->h_proto));
#if 0
		lprint(MAC_FMT, MAC_ARG(ether->h_source));
		lprint("\n");
		lprint(MAC_FMT, MAC_ARG(ether->h_dest));
		lprint("\n");
#endif
		switch(ntohs(ether->h_proto)){
			case ETH_P_PPP_DISC:
				parse_ppp(buf);
				lprint("Get ppp packet...\n");
				break;
			case ETH_P_IP:
				//parse_ip(ether, buf);
				//lprint("ip\n");
				break;
			case ETH_P_ARP:
				lprint("Get ARP packet...\n");
				break;
			default:
				lprint("Get other packet...\n");
				break;
		}
		sleep(1);
	}
	close(fd);
}

	unsigned x_static,
		 x_dhcp,
		 x_pppoe;
int
main (int argc, char **argv )
{
#if 0
	pthread_t pppid, dhcpid;
	int status;
	status = pthread(&pppid, NULL, );
#endif
	struct timeval ts, ti, te;
	time_t now, last, mid;
	gettimeofday(&ts, NULL);
	now = (time_t) ts.tv_sec;

	/*-----------------------------------------------------------------------------
	 *  dhcp
	 *-----------------------------------------------------------------------------*/
	udhcpc_main(argc, argv);
	gettimeofday(&ti, NULL);
	mid =  (time_t) ti.tv_sec;
	/*-----------------------------------------------------------------------------
	 *  pppoe
	 *-----------------------------------------------------------------------------*/
	pppoe_main(argc, argv);

	gettimeofday(&te, NULL);
	last =  (time_t) te.tv_sec;
	lprint("interval1:%ld\n", mid - now);
	lprint("interval2:%ld\n", last - mid);
	if(!x_dhcp && !x_pppoe)
		x_static = 1;
	lprint("x_static:%d\n"
		"x_dhcp:%d\n"
		"x_pppoe:%d\n", x_static, x_dhcp, x_pppoe);
	if(x_static)
		printf("3\n");
	else if(x_dhcp)
		printf("2\n");
	else if(x_pppoe)
		printf("1\n");
//	recv_main();
	return 1;
}		/* -----  end of function main  ----- */
