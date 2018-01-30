/*
*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "lwip/opt.h"

#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "netif/etharp.h"
#include "lwip/ethip6.h"

#if defined(LWIP_DEBUG) && defined(LWIP_TCPDUMP)
#include "netif/tcpdump.h"
#endif /* LWIP_DEBUG && LWIP_TCPDUMP */

#include "netif/netmapif.h"

#include <sys/ioctl.h>
#include <poll.h>

#define NETMAP_WITH_LIBS
#define BUSY_WAIT 0 

#include <net/netmap_user.h>
#include <net/netmap.h>
/*
 * Creating a tap interface requires special privileges. If the interfaces
 * is created in advance with `tunctl -u <user>` it can be opened as a regular
 * user. The network must already be configured. If DEVTAP_IF is defined it
 * will be opened instead of creating a new tap device.
 *
 * You can also use PRECONFIGURED_TAPIF environment variable to do so.
 */
#ifndef DEVNETMAP
#define DEVNETMAP "/dev/netmap"
#endif

/* Define those to better describe your network interface. */
#define IFNAME0 'n'
#define IFNAME1 'm'

#ifndef NETMAPIF_DEBUG
#define NETMAPIF_DEBUG LWIP_DBG_ON
#endif

#define VIRT_HDR_1 10 /*length of the base vnet-hdr*/
#define VIRT_HDR_2 12 /*length of the extended vnet-hdr*/
#define VIRT_HDR_MAX VIRT_HDR_2

struct netmapif {
  /* Add whatever per-interface state that is needed here. */
  struct nmreq base_nmd;
  struct nm_desc *nmd;
  int virt_header;
  uint16_t cur_tx_ring;
  uint8_t txing;
};

#if !NO_SYS
static void netmapif_thread(void *arg);
#endif /* !NO_SYS */

static void get_vnet_hdr_len(struct netmapif *netmapif)
{
  struct nmreq req;
  int err;

  memset(&req, 0, sizeof(req));
  bcopy(netmapif->nmd->req.nr_name,req.nr_name,sizeof(req.nr_name));
  req.nr_version = NETMAP_API;
  req.nr_cmd = NETMAP_VNET_HDR_GET;
  err = ioctl(netmapif->nmd->fd, NIOCREGIF, &req);
  if(err){
    LWIP_DEBUGF(NETMAPIF_DEBUG,("Unable to get virtio-net header length"));
    return;
  }

  netmapif->virt_header = req.nr_arg1;
  if(netmapif->virt_header){
    LWIP_DEBUGF(NETMAPIF_DEBUG,(("port requires virtio-net header, length = %d"),netmapif->virt_header));
  }
}
int parse_nmr_config(const char* conf, struct nmreq *nmr);

/*
 * parse the vale configuration in conf and put it in nmr.
 * Return the flag set if necessary.
 * The configuration may consist of 0 to 4 numbers separated
 * by commas: #tx-slots,#rx-slots,#tx-rings,#rx-rings.
 * Missing numbers or zeroes stand for default values.
 * As an additional convenience, if exactly one number
 * is specified, then this is assigned to both #tx-slots and #rx-slots.
 * If there is no 4th number, then the 3rd is assigned to both #tx-rings
 * and #rx-rings.
 */
int parse_nmr_config(const char* conf, struct nmreq *nmr)
{
	char *w, *tok;
	int i, v;

	nmr->nr_tx_rings = nmr->nr_rx_rings = 0;
	nmr->nr_tx_slots = nmr->nr_rx_slots = 0;
	if (conf == NULL || ! *conf)
		return 0;
	w = strdup(conf);
	for (i = 0, tok = strtok(w, ","); tok; i++, tok = strtok(NULL, ",")) {
		v = atoi(tok);
		switch (i) {
		case 0:
			nmr->nr_tx_slots = nmr->nr_rx_slots = v;
			break;
		case 1:
			nmr->nr_rx_slots = v;
			break;
		case 2:
			nmr->nr_tx_rings = nmr->nr_rx_rings = v;
			break;
		case 3:
			nmr->nr_rx_rings = v;
			break;
		default:
			D("ignored config: %s", tok);
			break;
		}
	}
	LWIP_DEBUGF(NETMAPIF_DEBUG,("txr %d txd %d rxr %d rxd %d",
			nmr->nr_tx_rings, nmr->nr_tx_slots,
			nmr->nr_rx_rings, nmr->nr_rx_slots));
	free(w);
	return (nmr->nr_tx_rings || nmr->nr_tx_slots ||
                        nmr->nr_rx_rings || nmr->nr_rx_slots) ?
		NM_OPEN_RING_CFG : 0;
}

static void
low_level_init(struct netif *netif)
{
  struct netmapif *netmapif;

  netmapif = (struct netmapif*)netif->state;

  /* Obtain MAC address from network interface. */

  /* (We just fake an address...) */
  netif->hwaddr[0] = 0x68;
  netif->hwaddr[1] = 0xf7;
  netif->hwaddr[2] = 0x28;
  netif->hwaddr[3] = 0x1f;
  netif->hwaddr[4] = 0xd9;
  netif->hwaddr[5] = 0x5f;
  netif->hwaddr_len = 6;
/*
netif->hwaddr[0] = 0xd0;
netif->hwaddr[1] = 0xff;
netif->hwaddr[2] = 0x98;
netif->hwaddr[3] = 0x56;
netif->hwaddr[4] = 0xf2;
netif->hwaddr[5] = 0x69;
netif->hwaddr_len = 6;*/

  /* device capabilities */
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

  bzero(&netmapif->base_nmd,sizeof(netmapif->base_nmd));

  parse_nmr_config("",&netmapif->base_nmd);

  netmapif->base_nmd.nr_flags |= NR_ACCEPT_VNET_HDR;

  /*
	 * Open the netmap device using nm_open().
	 *
	 * protocol stack and may cause a reset of the card,
	 * which in turn may take some time for the PHY to
	 * reconfigure. We do the open here to have time to reset.
	 */

	netmapif->nmd = nm_open("netmap:enp0s25", &netmapif->base_nmd, 0, NULL);
	if (netmapif->nmd == NULL) {
		LWIP_DEBUGF(NETMAPIF_DEBUG,("Unable to open %s: %s", "netmap:enp0s25", strerror(errno)));
    printf("exiiting the test");
		exit(-1);
	}

  get_vnet_hdr_len(netmapif);

  netmapif->cur_tx_ring = netmapif->nmd->first_tx_ring;

  netmapif->txing = 0;

  sleep(2);

  netif_set_link_up(netif);

#if !NO_SYS
  sys_thread_new("netmapif_thread",netmapif_thread,netif,DEFAULT_THREAD_STACKSIZE,DEFAULT_THREAD_PRIO);
#endif

}

/*
 * create and enqueue a batch of packets on a ring.
 * On the last one set NS_REPORT to tell the driver to generate
 * an interrupt when done.
 */
static int
send_packets(struct netmap_ring *ring, unsigned int cur_slot,struct pbuf *p,int virt_header)
{
  struct netmap_slot *slot = &ring->slot[cur_slot];
  char *buf = NETMAP_BUF(ring,slot->buf_idx);

  if(0 == nm_ring_space(ring))
  {
    //printf("ring is empty : %d\r\n",virt_header);
    return 0;
  }
  /*initiate transfer*/
  //memset(buf,0,virt_header);
  pbuf_copy_partial(p,&buf[virt_header],p->tot_len,0);

  slot->flags = 0;
  slot->len = p->tot_len + virt_header;
  slot->flags &= ~NS_MOREFRAG;
  slot->flags |= NS_REPORT;
  cur_slot = nm_ring_next(ring,cur_slot);

  ring->head = ring->cur = cur_slot;
  return 1;
}

static void netmapif_tx_timeout(void *arg)
{
  struct netmapif *netmapif = (struct netmapif *)arg;
  struct pollfd pfd;
  LWIP_DEBUGF(NETMAPIF_DEBUG,("-----------netmapif_tx_timeout"));

#if BUSY_WAIT
  ioctl(netmapif->nmd->fd,NIOCTXSYNC,NULL);
#else
  pfd.fd = netmapif->nmd->fd;
  pfd.events = POLLOUT;
  poll(&pfd,1,1000);
#endif
  netmapif->txing = 0;
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/
static err_t
low_level_output(struct netif *netif, struct pbuf *p)
{
  struct netmapif *netmapif = (struct netmapif *)netif->state;
  struct pollfd pfd;
  struct netmap_ring *txring = NULL;
  struct netmap_if *nifp;
  //static int count;
  int ret;

#if 0
  if (((double)rand()/(double)RAND_MAX) < 0.2) {
    printf("drop output\n");
    return ERR_OK;
  }
#endif

  nifp = netmapif->nmd->nifp;
  if(netmapif->txing == 0) {
txsync:
    pfd.fd = netmapif->nmd->fd;
    pfd.events = POLLOUT;
    //count++;
#if BUSY_WAIT
    /*if (ioctl(pfd.fd, NIOCTXSYNC, NULL) < 0) {
      LWIP_DEBUGF(NETMAPIF_DEBUG,("ioctl error on queue : %s",
          strerror(errno)));
      MIB2_STATS_NETIF_INC(netif,ifoutdiscards);
      return ERR_MEM;
    }*/
#else
   /*if(poll(&pfd,1,2000) <= 0){
        LWIP_DEBUGF(NETMAPIF_DEBUG,("poll error / timeout on queue"));
        MIB2_STATS_NETIF_INC(netif,ifoutdiscards);
        return ERR_MEM;
    }

    if(pfd.revents & POLLERR){
      LWIP_DEBUGF(NETMAPIF_DEBUG,("poll error"));
      MIB2_STATS_NETIF_INC(netif,ifoutdiscards);
      return ERR_MEM;
    }*/
#endif
    netmapif->cur_tx_ring = netmapif->nmd->first_tx_ring;
    txring = NETMAP_TXRING(nifp,netmapif->cur_tx_ring);
    //netmapif->txing = 1;
    ret = send_packets(txring,txring->cur,p,netmapif->virt_header);
    if (ret == 0)
    {
      if(poll(&pfd,1,2000) <= 0){
           LWIP_DEBUGF(NETMAPIF_DEBUG,("poll error / timeout on queue"));
           MIB2_STATS_NETIF_INC(netif,ifoutdiscards);
           return ERR_MEM;
      }

      if(pfd.revents & POLLERR){
         LWIP_DEBUGF(NETMAPIF_DEBUG,("poll error"));
         MIB2_STATS_NETIF_INC(netif,ifoutdiscards);
         return ERR_MEM;
      }

      send_packets(txring,txring->cur,p,netmapif->virt_header);
    }

#if BUSY_WAIT
    //if(count % 10 == 0 || count < 10)
    {
      if (ioctl(pfd.fd, NIOCTXSYNC, NULL) < 0) {
        LWIP_DEBUGF(NETMAPIF_DEBUG,("ioctl error on queue : %s",
            strerror(errno)));
        MIB2_STATS_NETIF_INC(netif,ifoutdiscards);
        return ERR_MEM;
      }
    }

    //netmapif->txing = 0;
    //sys_timeout(0,netmapif_tx_timeout,(void *)netmapif);
#else
    sys_timeout(1,netmapif_tx_timeout,(void *)netmapif);
#endif
  }else{
retry_next_tx_ring:
      txring = NETMAP_TXRING(nifp,netmapif->cur_tx_ring);
      if (nm_ring_empty(txring)){
        if (netmapif->cur_tx_ring < netmapif->nmd->last_tx_ring){
          netmapif->cur_tx_ring++;
          goto retry_next_tx_ring;
        }else{
          LWIP_DEBUGF(NETMAPIF_DEBUG,("retry txsync"));
          sys_untimeout(netmapif_tx_timeout,(void *)netmapif);
          goto txsync;
        }
      }

      send_packets(txring,txring->cur,p,netmapif->virt_header);
  }

  MIB2_STATS_NETIF_ADD(netif,ifoutoctets,p->tot_len);
  return ERR_OK;
}


/*-----------------------------------------------------------------------------------*/
/*
 * tapif_init():
 *
 *
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 *
 */
/*-----------------------------------------------------------------------------------*/
err_t netmapif_init(struct netif *netif)
{
  struct netmapif *netmapif = (struct netmapif *)mem_malloc(sizeof(struct netmapif));

  if(netmapif == NULL){
    LWIP_DEBUGF(NETIF_DEBUG,("netmapif_init : out of memory for netmapif\n"));
    return ERR_MEM;
  }
  netif->state = netmapif;
  MIB2_INIT_NETIF(netif,snmp_ifType_other,100000000);

  netif->name[0] = IFNAME0;
  netif->name[1] = IFNAME1;
#if LWIP_IPV4
  netif->output = etharp_output;
#endif
#if LWIP_IPV6
  netif->output_ip6 = ethip6_output;
#endif
  netif->linkoutput = low_level_output;
  netif->mtu = 1500;

  low_level_init(netif);

  return ERR_OK;
}


/*-----------------------------------------------------------------------------------*/
#if NO_SYS

int
tapif_select(struct netif *netif)
{
  fd_set fdset;
  int ret;
  struct timeval tv;
  struct tapif *tapif;
  u32_t msecs = sys_timeouts_sleeptime();

  tapif = (struct tapif *)netif->state;

  tv.tv_sec = msecs / 1000;
  tv.tv_usec = (msecs % 1000) * 1000;

  FD_ZERO(&fdset);
  FD_SET(tapif->fd, &fdset);

  ret = select(tapif->fd + 1, &fdset, NULL, NULL, &tv);
  if (ret > 0) {
    tapif_input(netif);
  }
  return ret;
}

#else /* NO_SYS */

static int receive_packets(struct netmap_ring *ring, int virt_header, struct netif *netif)
{
	unsigned int cur, rx, n;
  struct pbuf *p;

	cur = ring->cur;
	n = nm_ring_space(ring);
	for (rx = 0; rx < n; rx++) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *buf = NETMAP_BUF(ring, slot->buf_idx);

    /*We allocate a pbuf chain of pbufs from the pool*/
    //printf("slot->len :: %d\r\n",slot->len);
    p = pbuf_alloc(PBUF_RAW,slot->len - virt_header, PBUF_RAM);
    if (p != NULL) {
      pbuf_take(p,&buf[virt_header], slot->len - virt_header);

      if (netif->input(p,netif) != ERR_OK) {
        LWIP_DEBUGF(NETIF_DEBUG,("receive_packets: netif input error\n"));
        pbuf_free(p);
      }
      /*acknowledge that packet has been read(); */
    } else {
      /* drop packet(); */
      MIB2_STATS_NETIF_INC(netif, ifindiscards);
      LWIP_DEBUGF(NETIF_DEBUG,("receive_packets: could not allocate pbuf\n"));
    }

		cur = nm_ring_next(ring, cur);
	}
	ring->head = ring->cur = cur;

	return (rx);
}

static void netmapif_thread(void *arg)
{
  struct netif *netif;
  struct netmapif *netmapif;
  struct netmap_if *nifp;
  int ret, i;
  struct pollfd pfd;
  struct netmap_ring *rxring;

  netif = (struct netif *)arg;
  netmapif = (struct netmapif *)netif->state;
  pfd.fd = netmapif->nmd->fd;
  pfd.events = POLLIN;

  /*if(pthread_setaffinity_np(pthread_self(),sizeof(cpu_set_t),&cpumask) != 0)
  {
    printf("Unable to set affinity\r\n");
  }*/
  /*wait for the first packet to come after that read packets in busywait mode*/
  /*ret = poll(&pfd, 1,10000);
  if(ret < 0) {
      LWIP_DEBUGF(NETMAPIF_DEBUG,("poll() error: %s",strerror(errno)));
      exit(-1);
  }*/

  while(1) {
#if BUSY_WAIT
    if (ioctl(pfd.fd,NIOCRXSYNC, NULL) < 0) {
      LWIP_DEBUGF(NETMAPIF_DEBUG, ("ioctl error on queue %s", strerror(errno)));
      exit(-1);
    }
#else
    ret = poll(&pfd, 1,10000);
    if(ret < 0) {
        LWIP_DEBUGF(NETMAPIF_DEBUG,("poll() error: %s",strerror(errno)));
        exit(-1);
    }
    if (pfd.revents & POLLERR) {
      LWIP_DEBUGF(NETMAPIF_DEBUG,("fd error"));
      exit(-1);
    }
    if (ret == 0) {
      LWIP_DEBUGF(NETMAPIF_DEBUG, ("poll timeout"));
    }
#endif
    //printf("received packet\r\n");

    nifp = netmapif->nmd->nifp;

    for (i = netmapif->nmd->first_rx_ring; i <= netmapif->nmd->last_rx_ring; i++) {
      rxring = NETMAP_RXRING(nifp,i);
      /*compute free space in the ring*/
      if(nm_ring_empty(rxring))
        continue;
        //printf("packet given to lwip\r\n");
      receive_packets(rxring,netmapif->virt_header ,netif);
    }

    usleep(10);
  }
}

#endif /* NO_SYS */
