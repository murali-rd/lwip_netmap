/*
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
 * RT timer modifications by Christiaan Simons
 */

#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include "lwip/init.h"

#include "lwip/debug.h"

#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"

#include "lwip/stats.h"

#include "lwip/ip.h"
#include "lwip/tcpip.h"
#include "lwip/ip4_frag.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "netif/netmapif.h"
#include "netif/etharp.h"

#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_mib2.h"

#include "apps/snmp_private_mib/private_mib.h"
#include "apps/udpecho_raw/udpecho_raw.h"
#include "apps/tcpecho_raw/tcpecho_raw.h"

/* (manual) host IP configuration */
static ip4_addr_t ipaddr, netmask, gw;

int lwipinitdone = 0;
#if LWIP_SNMP
/* SNMP trap destination cmd option */
static unsigned char trap_flag;
static ip_addr_t trap_addr;

static const struct snmp_mib *mibs[] = {
  &mib2,
  &mib_private
};
#endif

/* nonstatic debug cmd option, exported in lwipopts.h */
unsigned char debug_flags;

#if LWIP_SNMP
/* enable == 1, disable == 2 */
u8_t snmpauthentraps_set = 2;
#endif

static struct option longopts[] = {
  /* turn on debugging output (if build with LWIP_DEBUG) */
  {"debug", no_argument,        NULL, 'd'},
  /* help */
  {"help", no_argument, NULL, 'h'},
  /* gateway address */
  {"gateway", required_argument, NULL, 'g'},
  /* ip address */
  {"ipaddr", required_argument, NULL, 'i'},
  /* netmask */
  {"netmask", required_argument, NULL, 'm'},
  /* ping destination */
  {"trap_destination", required_argument, NULL, 't'},
  /* new command line options go here! */
  {NULL,   0,                 NULL,  0}
};
#define NUM_OPTS ((sizeof(longopts) / sizeof(struct option)) - 1)

static void
usage(void)
{
  unsigned char i;

  printf("options:\n");
  for (i = 0; i < NUM_OPTS; i++) {
    printf("-%c --%s\n",longopts[i].val, longopts[i].name);
  }
}

static void
tcpip_init_done(void *arg)
{
  static struct netif netif;
  sys_sem_t *sem;
  sem = (sys_sem_t *)arg;

  netif_add(&netif,ip_2_ip4(&ipaddr),ip_2_ip4(&netmask),ip_2_ip4(&gw),NULL,netmapif_init,tcpip_input);
#if LWIP_NETIF_STATUS_CALLBACK
  netif_set_status_callback(&netif,netif_status_callback);
#endif  /* LWIP_NETIF_STATUS_CALLBACK */
  netif_set_default(&netif);
  netif_set_up(&netif);

  sys_sem_signal(sem);
  printf("Lwip init is done and netif add is done by adaptor\r\n");
  lwipinitdone = 1;
}

int do_lwip_init(void)
{
  char ip_str[16] = {0}, nm_str[16] = {0}, gw_str[16] = {0};
  sys_sem_t sem;

  if(sys_sem_new(&sem,0) != ERR_OK){
    LWIP_ASSERT("Failed to create semaphore",0);
    return -1;
  }
  /* startup defaults (may be overridden by one or more opts) */
  /*IP4_ADDR(&gw, 192,168,1,1);
  IP4_ADDR(&ipaddr, 192,168,43,217);
  IP4_ADDR(&netmask, 255,255,255,0);*/

  IP4_ADDR(&gw, 192,168,1,1);
  IP4_ADDR(&ipaddr, 192,168,100,1);
  IP4_ADDR(&netmask, 255,255,255,0);

  /* use debug flags defined by debug.h */
  debug_flags = LWIP_DBG_OFF;


  strncpy(ip_str, ip4addr_ntoa(&ipaddr), sizeof(ip_str));
  strncpy(nm_str, ip4addr_ntoa(&netmask), sizeof(nm_str));
  strncpy(gw_str, ip4addr_ntoa(&gw), sizeof(gw_str));
  printf("Host at %s mask %s gateway %s\n", ip_str, nm_str, gw_str);


#ifdef PERF
  perf_init("/tmp/minimal.perf");
#endif /* PERF */

  tcpip_init(tcpip_init_done,&sem);//lwip_init();

  while(!lwipinitdone)
  {
    continue;
  }
  printf("TCP/IP initialized.\n");

  //netif_add(&netif, &ipaddr, &netmask, &gw, NULL, tapif_init, ethernet_input);
  //netif_set_default(&netif);
  //netif_set_up(&netif);
#if LWIP_IPV6
  netif_create_ip6_linklocal_address(&netif, 1);
#endif

  printf("Applications started.\n");

  return 0;
}
