/*
 * =====================================================================================
 *
 *       Filename:  senddi.c
 *
 *    Description:  j
 *
 *        Version:  1.0
 *        Created:  09/25/2013 01:28:35 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Dr. Fritz Mehner (mn), mehner@fh-swf.de
 *        Company:  FH Südwestfalen, Iserlohn
 *
 * =====================================================================================
 */

#include <sys/time.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <time.h>
#include "pppoe.h"
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include "xmcheck.h"

UINT16_t Eth_PPPOE_Discovery = ETH_PPPOE_DISCOVERY;
UINT16_t Eth_PPPOE_Session   = ETH_PPPOE_SESSION;
#define DEFAULT_IF "eth0"
int persist = 0;
PPPoEConnection *Connection = NULL; /* Must be global -- used*/
	void
sysErr(char const *str)
{
	char buf[1024];
	sprintf(buf, "%.256s: %.256s", str, strerror(errno));
	printErr(buf);
}
	char *
strDup(char const *str)
{
	char *copy = malloc(strlen(str)+1);
	if (!copy) {
		rp_fatal("strdup failed");
	}
	strcpy(copy, str);
	return copy;
}

	void
printErr(char const *str)
{
	fprintf(stderr, "pppoe: %s\n", str);
	syslog(LOG_ERR, "%s", str);
}
	void
sendPADT(PPPoEConnection *conn, char const *msg)
{
	PPPoEPacket packet;
	unsigned char *cursor = packet.payload;

	UINT16_t plen = 0;

	/* Do nothing if no session established yet */
	if (!conn->session) return;

	/* Do nothing if no discovery socket */
	if (conn->discoverySocket < 0) return;

	memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
	memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

	packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
	packet.ver = 1;
	packet.type = 1;
	packet.code = CODE_PADT;
	packet.session = conn->session;

	/* Reset Session to zero so there is no possibility of
	   recursive calls to this function by any signal handler */
	conn->session = 0;

	/* If we're using Host-Uniq, copy it over */
	if (conn->useHostUniq) {
		PPPoETag hostUniq;
		pid_t pid = getpid();
		hostUniq.type = htons(TAG_HOST_UNIQ);
		hostUniq.length = htons(sizeof(pid));
		memcpy(hostUniq.payload, &pid, sizeof(pid));
		memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
		cursor += sizeof(pid) + TAG_HDR_SIZE;
		plen += sizeof(pid) + TAG_HDR_SIZE;
	}

	/* Copy error message */
	if (msg) {
		PPPoETag err;
		size_t elen = strlen(msg);
		err.type = htons(TAG_GENERIC_ERROR);
		err.length = htons(elen);
		strcpy((char *) err.payload, msg);
		memcpy(cursor, &err, elen + TAG_HDR_SIZE);
		cursor += elen + TAG_HDR_SIZE;
		plen += elen + TAG_HDR_SIZE;
	}

	/* Copy cookie and relay-ID if needed */
	if (conn->cookie.type) {
		CHECK_ROOM(cursor, packet.payload,
				ntohs(conn->cookie.length) + TAG_HDR_SIZE);
		memcpy(cursor, &conn->cookie, ntohs(conn->cookie.length) + TAG_HDR_SIZE);
		cursor += ntohs(conn->cookie.length) + TAG_HDR_SIZE;
		plen += ntohs(conn->cookie.length) + TAG_HDR_SIZE;
	}

	if (conn->relayId.type) {
		CHECK_ROOM(cursor, packet.payload,
				ntohs(conn->relayId.length) + TAG_HDR_SIZE);
		memcpy(cursor, &conn->relayId, ntohs(conn->relayId.length) + TAG_HDR_SIZE);
		cursor += ntohs(conn->relayId.length) + TAG_HDR_SIZE;
		plen += ntohs(conn->relayId.length) + TAG_HDR_SIZE;
	}

	packet.length = htons(plen);
	sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));
#ifdef DEBUGGING_ENABLED
	if (conn->debugFile) {
		dumpPacket(conn->debugFile, &packet, "SENT");
		fprintf(conn->debugFile, "\n");
		fflush(conn->debugFile);
	}
#endif
	syslog(LOG_INFO,"Sent PADT");
}


	void
sendPADTf(PPPoEConnection *conn, char const *fmt, ...)
{
	char msg[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	msg[511] = 0;

	sendPADT(conn, msg);
}


	void
fatalSys(char const *str)
{
	char buf[1024];
	sprintf(buf, "%.256s: Session %d: %.256s",
			str, (int) ntohs(Connection->session), strerror(errno));
	printErr(buf);
	sendPADTf(Connection, "RP-PPPoE: System call error: %s",
			strerror(errno));
	exit(EXIT_FAILURE);
}
	void
rp_fatal(char const *str)
{
	printErr(str);
	sendPADTf(Connection, "RP-PPPoE: Session %d: %.256s",
			(int) ntohs(Connection->session), str);
	exit(EXIT_FAILURE);
}



	int
sendPacket(PPPoEConnection *conn, int sock, PPPoEPacket *pkt, int size)
{
#if defined(USE_BPF)
	if (write(sock, pkt, size) < 0) {
		sysErr("write (sendPacket)");
		return -1;
	}
#elif defined(HAVE_STRUCT_SOCKADDR_LL)
	if (send(sock, pkt, size, 0) < 0 && (errno != ENOBUFS)) {
		sysErr("send (sendPacket)");
		return -1;
	}
#else
#ifdef USE_DLPI

#define ABS(x)          ((x) < 0 ? -(x) : (x))

	u_char  addr[MAXDLADDR];
	u_char  phys[MAXDLADDR];
	u_char  sap[MAXDLADDR];
	u_char    xmitbuf[MAXDLBUF];
	int	data_size;

	short	tmp_sap;

	tmp_sap = htons(pkt->ethHdr.h_proto);
	data_size = size - sizeof(struct ethhdr);

	memcpy((char *)phys, (char *)pkt->ethHdr.h_dest, ETHERADDRL);
	memcpy((char *)sap,  (char *)&tmp_sap, sizeof(ushort_t));
	memcpy((char *)xmitbuf, (char *)pkt + sizeof(struct ethhdr), data_size);

	if (dl_saplen > 0) {  /* order is sap+phys */
		(void) memcpy((char*)addr, (char*)&sap, dl_abssaplen);
		(void) memcpy((char*)addr+dl_abssaplen, (char*)phys, ETHERADDRL);
	} else {        /* order is phys+sap */
		(void) memcpy((char*)addr, (char*)phys, ETHERADDRL);
		(void) memcpy((char*)addr+ETHERADDRL, (char*)&sap, dl_abssaplen);
	}

#ifdef DL_DEBUG
	printf("%02x:%02x:%02x:%02x:%02x:%02x %02x:%02x\n",
			addr[0],addr[1],addr[2],addr[3],addr[4],addr[5],
			addr[6],addr[7]);
#endif

	dlunitdatareq(sock, addr, dl_addrlen, 0, 0, xmitbuf, data_size);


#else
	struct sockaddr sa;

	if (!conn) {
		rp_fatal("relay and server not supported on Linux 2.0 kernels");
	}
	strcpy(sa.sa_data, conn->ifName);
	if (sendto(sock, pkt, size, 0, &sa, sizeof(sa)) < 0) {
		sysErr("sendto (sendPacket)");
		return -1;
	}
#endif
#endif
	return 0;
}
	UINT16_t
etherType(PPPoEPacket *packet)
{
	UINT16_t type = (UINT16_t) ntohs(packet->ethHdr.h_proto);
	if (type != Eth_PPPOE_Discovery && type != Eth_PPPOE_Session) {
		syslog(LOG_ERR, "Invalid ether type 0x%x", type);
	}
	return type;
}
	void
dumpHex(FILE *fp, unsigned char const *buf, int len)
{
	int i;
	int base;

	if (!fp) return;

	/* do NOT dump PAP packets */
	if (len >= 2 && buf[0] == 0xC0 && buf[1] == 0x23) {
		fprintf(fp, "(PAP Authentication Frame -- Contents not dumped)\n");
		return;
	}

	for (base=0; base<len; base += 16) {
		for (i=base; i<base+16; i++) {
			if (i < len) {
				fprintf(fp, "%02x ", (unsigned) buf[i]);
			} else {
				fprintf(fp, "   ");
			}
		}
		fprintf(fp, "  ");
		for (i=base; i<base+16; i++) {
			if (i < len) {
				if (isprint(buf[i])) {
					fprintf(fp, "%c", buf[i]);
				} else {
					fprintf(fp, ".");
				}
			} else {
				break;
			}
		}
		fprintf(fp, "\n");
	}
}


	void
dumpPacket(FILE *fp, PPPoEPacket *packet, char const *dir)
{
	int len = ntohs(packet->length);

	/* Sheesh... printing times is a pain... */
	struct timeval tv;
	time_t now;
	int millisec;
	struct tm *lt;
	char timebuf[256];

	UINT16_t type = etherType(packet);
	if (!fp) return;
	gettimeofday(&tv, NULL);
	now = (time_t) tv.tv_sec;
	millisec = tv.tv_usec / 1000;
	lt = localtime(&now);
	strftime(timebuf, 256, "%H:%M:%S", lt);
	fprintf(fp, "%s.%03d %s PPPoE ", timebuf, millisec, dir);
	if (type == Eth_PPPOE_Discovery) {
		fprintf(fp, "Discovery (%x) ", (unsigned) type);
	} else if (type == Eth_PPPOE_Session) {
		fprintf(fp, "Session (%x) ", (unsigned) type);
	} else {
		fprintf(fp, "Unknown (%x) ", (unsigned) type);
	}

	switch(packet->code) {
		case CODE_PADI: fprintf(fp, "PADI "); break;
		case CODE_PADO: fprintf(fp, "PADO "); break;
		case CODE_PADR: fprintf(fp, "PADR "); break;
		case CODE_PADS: fprintf(fp, "PADS "); break;
		case CODE_PADT: fprintf(fp, "PADT "); break;
		case CODE_PADM: fprintf(fp, "PADM "); break;
		case CODE_PADN: fprintf(fp, "PADN "); break;
		case CODE_SESS: fprintf(fp, "SESS "); break;
	}

	fprintf(fp, "sess-id %d length %d\n",
			(int) ntohs(packet->session),
			len);

	/* Ugly... I apologize... */
	fprintf(fp,
			"SourceAddr %02x:%02x:%02x:%02x:%02x:%02x "
			"DestAddr %02x:%02x:%02x:%02x:%02x:%02x\n",
			(unsigned) packet->ethHdr.h_source[0],
			(unsigned) packet->ethHdr.h_source[1],
			(unsigned) packet->ethHdr.h_source[2],
			(unsigned) packet->ethHdr.h_source[3],
			(unsigned) packet->ethHdr.h_source[4],
			(unsigned) packet->ethHdr.h_source[5],
			(unsigned) packet->ethHdr.h_dest[0],
			(unsigned) packet->ethHdr.h_dest[1],
			(unsigned) packet->ethHdr.h_dest[2],
			(unsigned) packet->ethHdr.h_dest[3],
			(unsigned) packet->ethHdr.h_dest[4],
			(unsigned) packet->ethHdr.h_dest[5]);
	dumpHex(fp, packet->payload, ntohs(packet->length));
}


	static void
sendPADI(PPPoEConnection *conn)
{
	PPPoEPacket packet;
	unsigned char *cursor = packet.payload;
	PPPoETag *svc = (PPPoETag *) (&packet.payload);
	UINT16_t namelen = 0;
	UINT16_t plen;
	int omit_service_name = 0;

	if (conn->serviceName) {
		namelen = (UINT16_t) strlen(conn->serviceName);
		if (!strcmp(conn->serviceName, "NO-SERVICE-NAME-NON-RFC-COMPLIANT")) {
			omit_service_name = 1;
		}
	}

	/* Set destination to Ethernet broadcast address */
	memset(packet.ethHdr.h_dest, 0xFF, ETH_ALEN);
	memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

	packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
	packet.ver = 1;
	packet.type = 1;
	packet.code = CODE_PADI;
	packet.session = 0;

	if (!omit_service_name) {
		plen = TAG_HDR_SIZE + namelen;
		CHECK_ROOM(cursor, packet.payload, plen);

		svc->type = TAG_SERVICE_NAME;
		svc->length = htons(namelen);

		if (conn->serviceName) {
			memcpy(svc->payload, conn->serviceName, strlen(conn->serviceName));
		}
		cursor += namelen + TAG_HDR_SIZE;
	} else {
		plen = 0;
	}

	/* If we're using Host-Uniq, copy it over */
	if (conn->useHostUniq) {
		PPPoETag hostUniq;
		pid_t pid = getpid();
		hostUniq.type = htons(TAG_HOST_UNIQ);
		hostUniq.length = htons(sizeof(pid));
		memcpy(hostUniq.payload, &pid, sizeof(pid));
		CHECK_ROOM(cursor, packet.payload, sizeof(pid) + TAG_HDR_SIZE);
		memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
		cursor += sizeof(pid) + TAG_HDR_SIZE;
		plen += sizeof(pid) + TAG_HDR_SIZE;
	}

#ifdef PLUGIN
	/* Add our maximum MTU/MRU */
	if (MIN(lcp_allowoptions[0].mru, lcp_wantoptions[0].mru) > ETH_PPPOE_MTU) {
		PPPoETag maxPayload;
		UINT16_t mru = htons(MIN(lcp_allowoptions[0].mru, lcp_wantoptions[0].mru));
		maxPayload.type = htons(TAG_PPP_MAX_PAYLOAD);
		maxPayload.length = htons(sizeof(mru));
		memcpy(maxPayload.payload, &mru, sizeof(mru));
		CHECK_ROOM(cursor, packet.payload, sizeof(mru) + TAG_HDR_SIZE);
		memcpy(cursor, &maxPayload, sizeof(mru) + TAG_HDR_SIZE);
		cursor += sizeof(mru) + TAG_HDR_SIZE;
		plen += sizeof(mru) + TAG_HDR_SIZE;
	}
#endif

	packet.length = htons(plen);

	sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));
#ifdef DEBUGGING_ENABLED
	if (conn->debugFile) {
		dumpPacket(conn->debugFile, &packet, "SENT");
		fprintf(conn->debugFile, "\n");
		fflush(conn->debugFile);
	}
#endif
}
	int
parsePacket(PPPoEPacket *packet, ParseFunc *func, void *extra)
{
	UINT16_t len = ntohs(packet->length);
	unsigned char *curTag;
	UINT16_t tagType, tagLen;

	if (packet->ver != 1) {
		syslog(LOG_ERR, "Invalid PPPoE version (%d)", (int) packet->ver);
		return -1;
	}
	if (packet->type != 1) {
		syslog(LOG_ERR, "Invalid PPPoE type (%d)", (int) packet->type);
		return -1;
	}

	/* Do some sanity checks on packet */
	if (len > ETH_JUMBO_LEN - PPPOE_OVERHEAD) { /* 6-byte overhead for PPPoE header */
		syslog(LOG_ERR, "Invalid PPPoE packet length (%u)", len);
		return -1;
	}

	/* Step through the tags */
	curTag = packet->payload;
	while(curTag - packet->payload < len) {
		/* Alignment is not guaranteed, so do this by hand... */
		tagType = (((UINT16_t) curTag[0]) << 8) +
			(UINT16_t) curTag[1];
		tagLen = (((UINT16_t) curTag[2]) << 8) +
			(UINT16_t) curTag[3];
		if (tagType == TAG_END_OF_LIST) {
			return 0;
		}
		if ((curTag - packet->payload) + tagLen + TAG_HDR_SIZE > len) {
			syslog(LOG_ERR, "Invalid PPPoE tag length (%u)", tagLen);
			return -1;
		}
		func(tagType, tagLen, curTag+TAG_HDR_SIZE, extra);
		curTag = curTag + TAG_HDR_SIZE + tagLen;
	}
	return 0;
}
	void
pktLogErrs(char const *pkt,
		UINT16_t type, UINT16_t len, unsigned char *data,
		void *extra)
{
	char const *str;
	char const *fmt = "%s: %s: %.*s";
	switch(type) {
		case TAG_SERVICE_NAME_ERROR:
			str = "Service-Name-Error";
			break;
		case TAG_AC_SYSTEM_ERROR:
			str = "System-Error";
			break;
		default:
			str = "Generic-Error";
	}

	syslog(LOG_ERR, fmt, pkt, str, (int) len, data);
	fprintf(stderr, fmt, pkt, str, (int) len, data);
	fprintf(stderr, "\n");
}
	static void
parsePADOTags(UINT16_t type, UINT16_t len, unsigned char *data,
		void *extra)
{
	struct PacketCriteria *pc = (struct PacketCriteria *) extra;
	PPPoEConnection *conn = pc->conn;
	int i;
#ifdef PLUGIN
	UINT16_t mru;
#endif

	switch(type) {
		case TAG_AC_NAME:
			pc->seenACName = 1;
			if (conn->printACNames) {
				printf("Access-Concentrator: %.*s\n", (int) len, data);
			}
			if (conn->acName && len == strlen(conn->acName) &&
					!strncmp((char *) data, conn->acName, len)) {
				pc->acNameOK = 1;
			}
			break;
		case TAG_SERVICE_NAME:
			pc->seenServiceName = 1;
			if (conn->printACNames && len > 0) {
				printf("       Service-Name: %.*s\n", (int) len, data);
			}
			if (conn->serviceName && len == strlen(conn->serviceName) &&
					!strncmp((char *) data, conn->serviceName, len)) {
				pc->serviceNameOK = 1;
			}
			break;
		case TAG_AC_COOKIE:
			if (conn->printACNames) {
				printf("Got a cookie:");
				/* Print first 20 bytes of cookie */
				for (i=0; i<len && i < 20; i++) {
					printf(" %02x", (unsigned) data[i]);
				}
				if (i < len) printf("...");
				printf("\n");
			}
			conn->cookie.type = htons(type);
			conn->cookie.length = htons(len);
			memcpy(conn->cookie.payload, data, len);
			break;
		case TAG_RELAY_SESSION_ID:
			if (conn->printACNames) {
				printf("Got a Relay-ID:");
				/* Print first 20 bytes of relay ID */
				for (i=0; i<len && i < 20; i++) {
					printf(" %02x", (unsigned) data[i]);
				}
				if (i < len) printf("...");
				printf("\n");
			}
			conn->relayId.type = htons(type);
			conn->relayId.length = htons(len);
			memcpy(conn->relayId.payload, data, len);
			break;
		case TAG_SERVICE_NAME_ERROR:
			if (conn->printACNames) {
				printf("Got a Service-Name-Error tag: %.*s\n", (int) len, data);
			} else {
				pktLogErrs("PADO", type, len, data, extra);
				pc->gotError = 1;
				if (!persist) {
					exit(1);
				}
			}
			break;
		case TAG_AC_SYSTEM_ERROR:
			if (conn->printACNames) {
				printf("Got a System-Error tag: %.*s\n", (int) len, data);
			} else {
				pktLogErrs("PADO", type, len, data, extra);
				pc->gotError = 1;
				if (!persist) {
					exit(1);
				}
			}
			break;
		case TAG_GENERIC_ERROR:
			if (conn->printACNames) {
				printf("Got a Generic-Error tag: %.*s\n", (int) len, data);
			} else {
				pktLogErrs("PADO", type, len, data, extra);
				pc->gotError = 1;
				if (!persist) {
					exit(1);
				}
			}
			break;
#ifdef PLUGIN
		case TAG_PPP_MAX_PAYLOAD:
			if (len == sizeof(mru)) {
				memcpy(&mru, data, sizeof(mru));
				mru = ntohs(mru);
				if (mru >= ETH_PPPOE_MTU) {
					if (lcp_allowoptions[0].mru > mru) lcp_allowoptions[0].mru = mru;
					if (lcp_wantoptions[0].mru > mru) lcp_wantoptions[0].mru = mru;
					conn->seenMaxPayload = 1;
				}
			}
			break;
#endif
	}
}

	int
receivePacket(int sock, PPPoEPacket *pkt, int *size)
{
#ifdef USE_BPF
	struct bpf_hdr hdr;
	int seglen, copylen;

	if (bpfSize <= 0) {
		bpfOffset = 0;
		if ((bpfSize = read(sock, bpfBuffer, bpfLength)) < 0) {
			sysErr("read (receivePacket)");
			return -1;
		}
	}
	if (bpfSize < sizeof(hdr)) {
		syslog(LOG_ERR, "Truncated bpf packet header: len=%d", bpfSize);
		clearPacketHeader(pkt);		/* resets bpfSize and bpfOffset */
		return 0;
	}
	memcpy(&hdr, bpfBuffer + bpfOffset, sizeof(hdr));
	if (hdr.bh_caplen != hdr.bh_datalen) {
		syslog(LOG_ERR, "Truncated bpf packet: caplen=%d, datalen=%d",
				hdr.bh_caplen, hdr.bh_datalen);
		clearPacketHeader(pkt);		/* resets bpfSize and bpfOffset */
		return 0;
	}
	seglen = hdr.bh_hdrlen + hdr.bh_caplen;
	if (seglen > bpfSize) {
		syslog(LOG_ERR, "Truncated bpf packet: seglen=%d, bpfSize=%d",
				seglen, bpfSize);
		clearPacketHeader(pkt);		/* resets bpfSize and bpfOffset */
		return 0;
	}
	seglen = BPF_WORDALIGN(seglen);
	*size = copylen = ((hdr.bh_caplen < sizeof(PPPoEPacket)) ?
			hdr.bh_caplen : sizeof(PPPoEPacket));
	memcpy(pkt, bpfBuffer + bpfOffset + hdr.bh_hdrlen, copylen);
	if (seglen >= bpfSize) {
		bpfSize = bpfOffset = 0;
	} else {
		bpfSize -= seglen;
		bpfOffset += seglen;
	}
#else
#ifdef USE_DLPI
	struct strbuf data;
	int flags = 0;
	int retval;

	data.buf = (char *) pkt;
	data.maxlen = MAXDLBUF;
	data.len = 0;

	if ((retval = getmsg(sock, NULL, &data, &flags)) < 0) {
		sysErr("read (receivePacket)");
		return -1;
	}

	*size = data.len;

#else
	if ((*size = recv(sock, pkt, sizeof(PPPoEPacket), 0)) < 0) {
		sysErr("recv (receivePacket)");
		return -1;
	}
#endif
#endif
	return 0;
}
	static void
parseForHostUniq(UINT16_t type, UINT16_t len, unsigned char *data,
		void *extra)
{
	int *val = (int *) extra;
	if (type == TAG_HOST_UNIQ && len == sizeof(pid_t)) {
		pid_t tmp;
		memcpy(&tmp, data, len);
		if (tmp == getpid()) {
			*val = 1;
		}
	}
}
	static int
packetIsForMe(PPPoEConnection *conn, PPPoEPacket *packet)
{
	int forMe = 0;

	/* If packet is not directed to our MAC address, forget it */
	if (memcmp(packet->ethHdr.h_dest, conn->myEth, ETH_ALEN)) return 0;

	/* If we're not using the Host-Unique tag, then accept the packet */
	if (!conn->useHostUniq) return 1;

	parsePacket(packet, parseForHostUniq, &forMe);
	return forMe;
}

	static void
waitForPADO(PPPoEConnection *conn, int timeout)
{
	fd_set readable;
	int r;
	struct timeval tv;
	struct timeval expire_at;
	struct timeval now;

	PPPoEPacket packet;
	int len;

	struct PacketCriteria pc;
	pc.conn          = conn;
#ifdef PLUGIN
	conn->seenMaxPayload = 0;
#endif

	if (gettimeofday(&expire_at, NULL) < 0) {
		fatalSys("gettimeofday (waitForPADO)");
	}
	expire_at.tv_sec += timeout;

	do {
		if (BPF_BUFFER_IS_EMPTY) {
			if (gettimeofday(&now, NULL) < 0) {
				fatalSys("gettimeofday (waitForPADO)");
			}
			tv.tv_sec = expire_at.tv_sec - now.tv_sec;
			tv.tv_usec = expire_at.tv_usec - now.tv_usec;
			if (tv.tv_usec < 0) {
				tv.tv_usec += 1000000;
				if (tv.tv_sec) {
					tv.tv_sec--;
				} else {
					/* Timed out */
					return;
				}
			}
			if (tv.tv_sec <= 0 && tv.tv_usec <= 0) {
				/* Timed out */
				return;
			}

			FD_ZERO(&readable);
			FD_SET(conn->discoverySocket, &readable);

			while(1) {
				r = select(conn->discoverySocket+1, &readable, NULL, NULL, &tv);
				if (r >= 0 || errno != EINTR) break;
			}
			if (r < 0) {
				fatalSys("select (waitForPADO)");
			}
			if (r == 0) {
				/* Timed out */
				return;
			}
		}

		/* Get the packet */
		receivePacket(conn->discoverySocket, &packet, &len);

		/* Check length */
		if (ntohs(packet.length) + HDR_SIZE > len) {
			syslog(LOG_ERR, "Bogus PPPoE length field (%u)",
					(unsigned int) ntohs(packet.length));
			continue;
		}

#ifdef USE_BPF
		/* If it's not a Discovery packet, loop again */
		if (etherType(&packet) != Eth_PPPOE_Discovery) continue;
#endif

#ifdef DEBUGGING_ENABLED
		if (conn->debugFile) {
			dumpPacket(conn->debugFile, &packet, "RCVD");
			fprintf(conn->debugFile, "\n");
			fflush(conn->debugFile);
		}
#endif
		/* If it's not for us, loop again */
		if (!packetIsForMe(conn, &packet)) continue;

		if (packet.code == CODE_PADO) {
			if (NOT_UNICAST(packet.ethHdr.h_source)) {
				printErr("Ignoring PADO packet from non-unicast MAC address");
				continue;
			}else{
				x_pppoe = 1;
				lprint("Get PADO packet...\n");
			}
#ifdef PLUGIN
			if (conn->req_peer
					&& memcmp(packet.ethHdr.h_source, conn->req_peer_mac, ETH_ALEN) != 0) {
				warn("Ignoring PADO packet from wrong MAC address");
				continue;
			}
#endif
			pc.gotError = 0;
			pc.seenACName    = 0;
			pc.seenServiceName = 0;
			pc.acNameOK      = (conn->acName)      ? 0 : 1;
			pc.serviceNameOK = (conn->serviceName) ? 0 : 1;
			parsePacket(&packet, parsePADOTags, &pc);
			if (pc.gotError) {
				printErr("Error in PADO packet");
				continue;
			}

			if (!pc.seenACName) {
				printErr("Ignoring PADO packet with no AC-Name tag");
				continue;
			}
			if (!pc.seenServiceName) {
				printErr("Ignoring PADO packet with no Service-Name tag");
				continue;
			}
			conn->numPADOs++;
			if (pc.acNameOK && pc.serviceNameOK) {
				memcpy(conn->peerEth, packet.ethHdr.h_source, ETH_ALEN);
				if (conn->printACNames) {
					printf("AC-Ethernet-Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
							(unsigned) conn->peerEth[0],
							(unsigned) conn->peerEth[1],
							(unsigned) conn->peerEth[2],
							(unsigned) conn->peerEth[3],
							(unsigned) conn->peerEth[4],
							(unsigned) conn->peerEth[5]);
					printf("--------------------------------------------------\n");
					continue;
				}
				conn->discoveryState = STATE_RECEIVED_PADO;
				break;
			}
		}
	} while (conn->discoveryState != STATE_RECEIVED_PADO);
}

	static void
parsePADSTags(UINT16_t type, UINT16_t len, unsigned char *data,
		void *extra)
{
#ifdef PLUGIN
	UINT16_t mru;
#endif
	PPPoEConnection *conn = (PPPoEConnection *) extra;
	switch(type) {
		case TAG_SERVICE_NAME:
			syslog(LOG_DEBUG, "PADS: Service-Name: '%.*s'", (int) len, data);
			break;
		case TAG_GENERIC_ERROR:
		case TAG_AC_SYSTEM_ERROR:
		case TAG_SERVICE_NAME_ERROR:
			pktLogErrs("PADS", type, len, data, extra);
			conn->PADSHadError = 1;
			break;
		case TAG_RELAY_SESSION_ID:
			conn->relayId.type = htons(type);
			conn->relayId.length = htons(len);
			memcpy(conn->relayId.payload, data, len);
			break;
#ifdef PLUGIN
		case TAG_PPP_MAX_PAYLOAD:
			if (len == sizeof(mru)) {
				memcpy(&mru, data, sizeof(mru));
				mru = ntohs(mru);
				if (mru >= ETH_PPPOE_MTU) {
					if (lcp_allowoptions[0].mru > mru) lcp_allowoptions[0].mru = mru;
					if (lcp_wantoptions[0].mru > mru) lcp_wantoptions[0].mru = mru;
					conn->seenMaxPayload = 1;
				}
			}
			break;
#endif
	}
}


	static void
waitForPADS(PPPoEConnection *conn, int timeout)
{
	fd_set readable;
	int r;
	struct timeval tv;
	struct timeval expire_at;
	struct timeval now;

	PPPoEPacket packet;
	int len;

	if (gettimeofday(&expire_at, NULL) < 0) {
		fatalSys("gettimeofday (waitForPADS)");
	}
	expire_at.tv_sec += timeout;

	do {
		if (BPF_BUFFER_IS_EMPTY) {
			if (gettimeofday(&now, NULL) < 0) {
				fatalSys("gettimeofday (waitForPADS)");
			}
			tv.tv_sec = expire_at.tv_sec - now.tv_sec;
			tv.tv_usec = expire_at.tv_usec - now.tv_usec;
			if (tv.tv_usec < 0) {
				tv.tv_usec += 1000000;
				if (tv.tv_sec) {
					tv.tv_sec--;
				} else {
					/* Timed out */
					return;
				}
			}
			if (tv.tv_sec <= 0 && tv.tv_usec <= 0) {
				/* Timed out */
				return;
			}

			FD_ZERO(&readable);
			FD_SET(conn->discoverySocket, &readable);

			while(1) {
				r = select(conn->discoverySocket+1, &readable, NULL, NULL, &tv);
				if (r >= 0 || errno != EINTR) break;
			}
			if (r < 0) {
				fatalSys("select (waitForPADS)");
			}
			if (r == 0) {
				/* Timed out */
				return;
			}
		}

		/* Get the packet */
		receivePacket(conn->discoverySocket, &packet, &len);

		/* Check length */
		if (ntohs(packet.length) + HDR_SIZE > len) {
			syslog(LOG_ERR, "Bogus PPPoE length field (%u)",
					(unsigned int) ntohs(packet.length));
			continue;
		}

#ifdef USE_BPF
		/* If it's not a Discovery packet, loop again */
		if (etherType(&packet) != Eth_PPPOE_Discovery) continue;
#endif
#ifdef DEBUGGING_ENABLED
		if (conn->debugFile) {
			dumpPacket(conn->debugFile, &packet, "RCVD");
			fprintf(conn->debugFile, "\n");
			fflush(conn->debugFile);
		}
#endif
		/* If it's not from the AC, it's not for me */
		if (memcmp(packet.ethHdr.h_source, conn->peerEth, ETH_ALEN)) continue;

		/* If it's not for us, loop again */
		if (!packetIsForMe(conn, &packet)) continue;

		/* Is it PADS?  */
		if (packet.code == CODE_PADS) {
			/* Parse for goodies */
			conn->PADSHadError = 0;
			parsePacket(&packet, parsePADSTags, conn);
			if (!conn->PADSHadError) {
				conn->discoveryState = STATE_SESSION;
				break;
			}
		}
	} while (conn->discoveryState != STATE_SESSION);

	/* Don't bother with ntohs; we'll just end up converting it back... */
	conn->session = packet.session;

	syslog(LOG_INFO, "PPP session is %d (0x%x)", (int) ntohs(conn->session),
			(unsigned int) ntohs(conn->session));

	/* RFC 2516 says session id MUST NOT be zero or 0xFFFF */
	if (ntohs(conn->session) == 0 || ntohs(conn->session) == 0xFFFF) {
		syslog(LOG_ERR, "Access concentrator used a session value of %x -- the AC is violating RFC 2516", (unsigned int) ntohs(conn->session));
	}
}

	static void
sendPADR(PPPoEConnection *conn)
{
	PPPoEPacket packet;
	PPPoETag *svc = (PPPoETag *) packet.payload;
	unsigned char *cursor = packet.payload;

	UINT16_t namelen = 0;
	UINT16_t plen;

	if (conn->serviceName) {
		namelen = (UINT16_t) strlen(conn->serviceName);
	}
	plen = TAG_HDR_SIZE + namelen;
	CHECK_ROOM(cursor, packet.payload, plen);

	memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
	memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

	packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
	packet.ver = 1;
	packet.type = 1;
	packet.code = CODE_PADR;
	packet.session = 0;

	svc->type = TAG_SERVICE_NAME;
	svc->length = htons(namelen);
	if (conn->serviceName) {
		memcpy(svc->payload, conn->serviceName, namelen);
	}
	cursor += namelen + TAG_HDR_SIZE;

	/* If we're using Host-Uniq, copy it over */
	if (conn->useHostUniq) {
		PPPoETag hostUniq;
		pid_t pid = getpid();
		hostUniq.type = htons(TAG_HOST_UNIQ);
		hostUniq.length = htons(sizeof(pid));
		memcpy(hostUniq.payload, &pid, sizeof(pid));
		CHECK_ROOM(cursor, packet.payload, sizeof(pid)+TAG_HDR_SIZE);
		memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
		cursor += sizeof(pid) + TAG_HDR_SIZE;
		plen += sizeof(pid) + TAG_HDR_SIZE;
	}

	/* Copy cookie and relay-ID if needed */
	if (conn->cookie.type) {
		CHECK_ROOM(cursor, packet.payload,
				ntohs(conn->cookie.length) + TAG_HDR_SIZE);
		memcpy(cursor, &conn->cookie, ntohs(conn->cookie.length) + TAG_HDR_SIZE);
		cursor += ntohs(conn->cookie.length) + TAG_HDR_SIZE;
		plen += ntohs(conn->cookie.length) + TAG_HDR_SIZE;
	}

	if (conn->relayId.type) {
		CHECK_ROOM(cursor, packet.payload,
				ntohs(conn->relayId.length) + TAG_HDR_SIZE);
		memcpy(cursor, &conn->relayId, ntohs(conn->relayId.length) + TAG_HDR_SIZE);
		cursor += ntohs(conn->relayId.length) + TAG_HDR_SIZE;
		plen += ntohs(conn->relayId.length) + TAG_HDR_SIZE;
	}

#ifdef PLUGIN
	/* Add our maximum MTU/MRU */
	if (MIN(lcp_allowoptions[0].mru, lcp_wantoptions[0].mru) > ETH_PPPOE_MTU) {
		PPPoETag maxPayload;
		UINT16_t mru = htons(MIN(lcp_allowoptions[0].mru, lcp_wantoptions[0].mru));
		maxPayload.type = htons(TAG_PPP_MAX_PAYLOAD);
		maxPayload.length = htons(sizeof(mru));
		memcpy(maxPayload.payload, &mru, sizeof(mru));
		CHECK_ROOM(cursor, packet.payload, sizeof(mru) + TAG_HDR_SIZE);
		memcpy(cursor, &maxPayload, sizeof(mru) + TAG_HDR_SIZE);
		cursor += sizeof(mru) + TAG_HDR_SIZE;
		plen += sizeof(mru) + TAG_HDR_SIZE;
	}
#endif

	packet.length = htons(plen);
	sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));
#ifdef DEBUGGING_ENABLED
	if (conn->debugFile) {
		dumpPacket(conn->debugFile, &packet, "SENT");
		fprintf(conn->debugFile, "\n");
		fflush(conn->debugFile);
	}
#endif
}



	void
discovery(PPPoEConnection *conn)
{
	int padiAttempts;
	int padrAttempts;
	int timeout = conn->discoveryTimeout;

	/* Skip discovery? */
	if (conn->skipDiscovery) {
		conn->discoveryState = STATE_SESSION;
		if (conn->killSession) {
			sendPADT(conn, "RP-PPPoE: Session killed manually");
			exit(0);
		}
		return;
	}

SEND_PADI:
	padiAttempts = 0;
	do {
		padiAttempts++;
		if (padiAttempts > MAX_PADI_ATTEMPTS) {
			if (persist) {
				padiAttempts = 0;
				timeout = conn->discoveryTimeout;
				printErr("Timeout waiting for PADO packets");
				DB;
			} else {
				lprint("Timeout waiting for PADO packets\n");
				return; 
				DB;
				//rp_fatal("Timeout waiting for PADO packets");
			}
		}
		DB;
		sendPADI(conn);
		conn->discoveryState = STATE_SENT_PADI;
		waitForPADO(conn, timeout);

		/* If we're just probing for access concentrators, don't do
		   exponential backoff.  This reduces the time for an unsuccessful
		   probe to 15 seconds. */
		if (!conn->printACNames) {
			timeout *= 2;
		}
		if (conn->printACNames && conn->numPADOs) {
			break;
		}
	} while (conn->discoveryState == STATE_SENT_PADI);

	/* If we're only printing access concentrator names, we're done */
	if (conn->printACNames) {
		exit(0);    }

	timeout = conn->discoveryTimeout;
	padrAttempts = 0;
	do {
		padrAttempts++;
		if (padrAttempts > MAX_PADI_ATTEMPTS) {
			if (persist) {
				padrAttempts = 0;
				timeout = conn->discoveryTimeout;
				printErr("Timeout waiting for PADS packets");
				/* Go back to sending PADI again */
				goto SEND_PADI;
			} else {
				lprint("Timeout waiting for PADS packets");
				//rp_fatal("Timeout waiting for PADS packets");
			}
		}
		sendPADR(conn);
		conn->discoveryState = STATE_SENT_PADR;
		waitForPADS(conn, timeout);
		timeout *= 2;
	} while (conn->discoveryState == STATE_SENT_PADR);

#ifdef PLUGIN
	if (!conn->seenMaxPayload) {
		/* RFC 4638: MUST limit MTU/MRU to 1492 */
		if (lcp_allowoptions[0].mru > ETH_PPPOE_MTU) lcp_allowoptions[0].mru = ETH_PPPOE_MTU;
		if (lcp_wantoptions[0].mru > ETH_PPPOE_MTU)  lcp_wantoptions[0].mru = ETH_PPPOE_MTU;
	}
#endif
	/* We're done. */
	conn->discoveryState = STATE_SESSION;
	return;
}
	int
openInterface(char const *ifname, UINT16_t type, unsigned char *hwaddr, UINT16_t *mtu)
{
	int optval=1;
	int fd;
	struct ifreq ifr;
	int domain, stype;
#define HAVE_STRUCT_SOCKADDR_LL 1
#ifdef HAVE_STRUCT_SOCKADDR_LL
	struct sockaddr_ll sa;
#else
	struct sockaddr sa;
#endif

	memset(&sa, 0, sizeof(sa));

#ifdef HAVE_STRUCT_SOCKADDR_LL
	domain = PF_PACKET;
	stype = SOCK_RAW;
#else
	domain = PF_INET;
	stype = SOCK_PACKET;
#endif

	if ((fd = socket(domain, stype, htons(type))) < 0) {
		/* Give a more helpful message for the common error case */
		if (errno == EPERM) {
			rp_fatal("Cannot create raw socket -- pppoe must be run as root.");
		}
		fatalSys("socket");
	}

	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
		fatalSys("setsockopt");
	}

	/* Fill in hardware address */
	if (hwaddr) {
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
			fatalSys("ioctl(SIOCGIFHWADDR)");
		}
		memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
#ifdef ARPHRD_ETHER

		if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
			char buffer[256];
			sprintf(buffer, "Interface %.16s is not Ethernet", ifname);
			rp_fatal(buffer);
		}
#endif
		if (NOT_UNICAST(hwaddr)) {
			char buffer[256];
			sprintf(buffer,
					"Interface %.16s has broadcast/multicast MAC address??",
					ifname);
			rp_fatal(buffer);
		}
	}

	/* Sanity check on MTU */
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
		fatalSys("ioctl(SIOCGIFMTU)");
	}
	if (ifr.ifr_mtu < ETH_DATA_LEN) {
		char buffer[256];
		sprintf(buffer, "Interface %.16s has MTU of %d -- should be %d.  You may have serious connection problems.",
				ifname, ifr.ifr_mtu, ETH_DATA_LEN);
		printErr(buffer);
	}
	if (mtu) *mtu = ifr.ifr_mtu;

#ifdef HAVE_STRUCT_SOCKADDR_LL
	/* Get interface index */
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(type);

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		fatalSys("ioctl(SIOCFIGINDEX): Could not get interface index");
	}
	sa.sll_ifindex = ifr.ifr_ifindex;

#else
	strcpy(sa.sa_data, ifname);
#endif

	/* We're only interested in packets on specified interface */
	if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		fatalSys("bind");
	}

	return fd;
}


int pppoe_main(int argc, char **argv){
	//int main(int argc, char **argv){

	optarg = 0;
	optind = 0;
	int opt;
	char const *options;
	PPPoEConnection conn;
	memset(&conn, 0, sizeof(conn));
	conn.discoverySocket = -1;
	conn.sessionSocket = -1;
	conn.discoveryTimeout = PADI_TIMEOUT;
	/* For signal handler */
	Connection = &conn;
	options = "i:VAT:hS:C:Usm:np:e:kdf:F:t:";
	while((opt = getopt(argc, argv, options)) != -1) {
		switch(opt) {
			case 'i':
				SET_STRING(conn.ifName, optarg);
				break;
			default:
				lprint("help");
		}
	}
	if (!conn.ifName) {
		SET_STRING(conn.ifName, DEFAULT_IF);
	}
	lprint("pppoe:%s\n", conn.ifName);

	conn.discoverySocket = openInterface(conn.ifName, Eth_PPPOE_Discovery, conn.myEth, NULL);
	discovery(&conn);
	return 1;
}
