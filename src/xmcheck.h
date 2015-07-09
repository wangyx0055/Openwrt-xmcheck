/*
 * =====================================================================================
 *
 *       Filename:  xmcheck.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  09/25/2013 10:04:03 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Dr. Fritz Mehner (mn), mehner@fh-swf.de
 *        Company:  FH Südwestfalen, Iserlohn
 *
 * =====================================================================================
 */

#ifndef __XMCHECK_H__
#define __XMCHECK_H__

#include	<asm/byteorder.h>
#define lprint(x, ...)
#define DB 
//#define lprint(x, ...)  do{printf(x, ##__VA_ARGS__);}while(0)
//#define DB printf("%10s:%10s______%3d\n", __FILE__, __func__, __LINE__)

#define MAC_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ARG(x) ((unsigned char*)(x))[0],((unsigned char*)(x))[1],((unsigned char*)(x))[2],\
	((unsigned char*)(x))[3],((unsigned char*)(x))[4],((unsigned char*)(x))[5]
#define PADI_CODE	0x09
#define PADO_CODE	0x07
#define PADR_CODE	0x19
#define PADS_CODE	0x65
#define PADT_CODE	0xa7

struct pppoe_tag {
	__be16 tag_type;
	__be16 tag_len;
	char tag_data[0];
} __attribute ((packed));

	struct pppoe_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		__u8 ver : 4;
		__u8 type : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
		__u8 type : 4;
		__u8 ver : 4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
		__u8 code;
		__be16 sid;
		__be16 length;
		struct pppoe_tag tag[0];
	} __attribute__ ((packed));


extern	unsigned x_static ,  x_dhcp ,  x_pppoe;

int udhcpc_main(int argc, char *argv[]);
int pppoe_main(int argc, char **argv);

#endif
