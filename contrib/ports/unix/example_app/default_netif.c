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
 *
 */

#include "lwip/opt.h"

#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "netif/tapif.h"
#include "examples/example_app/default_netif.h"

#include "lwip/ip.h"
#include "lwip/snmp.h"

static struct netif netif;


/*
static err_t
netif_loop_output_ipv4(struct netif *netifs, struct pbuf *p, const ip4_addr_t *addr)
{
  LWIP_UNUSED_ARG(addr);
  return netif_loop_output(netifs, p);
}*/

/*
static err_t
netif_loopif_init(struct netif *netifs)
{
  LWIP_ASSERT("netif_loopif_init: invalid netif", netifs != NULL);

  MIB2_INIT_NETIF(netifs, snmp_ifType_softwareLoopback, 0);

  netifs->name[0] = 'l';
  netifs->name[1] = 'o';
  netifs->output = netif_loop_output_ipv4;
#if LWIP_LOOPIF_MULTICAST
  netif_set_flags(netifs, NETIF_FLAG_IGMP);
#endif
  NETIF_SET_CHECKSUM_CTRL(netifs, NETIF_CHECKSUM_DISABLE_ALL);
  return ERR_OK;
}
*/


#if LWIP_IPV4
#define NETIF_ADDRS ipaddr, netmask, gw,
void init_default_netif(const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw)
#else
#define NETIF_ADDRS
void init_default_netif(void)
#endif
{
#if NO_SYS
netif_add(&netif, NETIF_ADDRS NULL, tapif_init, netif_input);
/*netif_add(&netif, NETIF_ADDRS NULL, netif_loopif_init, ip_input);*/
#else
  netif_add(&netif, NETIF_ADDRS NULL, netif_loopif_init, tcpip_input);
#endif
  netif_set_default(&netif);
}

void
default_netif_poll(void)
{
  tapif_poll(&netif);
}

void
default_netif_shutdown(void)
{
}
