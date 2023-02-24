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
#include <pcap.h>

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

#include "netif/tapif.h"

#define IFCONFIG_BIN "/sbin/ifconfig "

#if defined(LWIP_UNIX_LINUX)
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <pthread.h>
/*
 * Creating a tap interface requires special privileges. If the interfaces
 * is created in advance with `tunctl -u <user>` it can be opened as a regular
 * user. The network must already be configured. If DEVTAP_IF is defined it
 * will be opened instead of creating a new tap device.
 *
 * You can also use PRECONFIGURED_TAPIF environment variable to do so.
 */
#ifndef DEVTAP_DEFAULT_IF
#define DEVTAP_DEFAULT_IF "tap0"
#endif
#ifndef DEVTAP
#define DEVTAP "/dev/net/tun"
#endif
#define NETMASK_ARGS "netmask %d.%d.%d.%d"
#define IFCONFIG_ARGS "tap0 inet %d.%d.%d.%d " NETMASK_ARGS
#elif defined(LWIP_UNIX_OPENBSD)
#define DEVTAP "/dev/tun0"
#define NETMASK_ARGS "netmask %d.%d.%d.%d"
#define IFCONFIG_ARGS "tun0 inet %d.%d.%d.%d " NETMASK_ARGS " link0"
#else /* others */
#define DEVTAP "/dev/tap0"
#define NETMASK_ARGS "netmask %d.%d.%d.%d"
#define IFCONFIG_ARGS "tap0 inet %d.%d.%d.%d " NETMASK_ARGS
#endif

/* Define those to better describe your network interface. */
#define IFNAME0 't'
#define IFNAME1 'p'

#ifndef TAPIF_DEBUG
#define TAPIF_DEBUG LWIP_DBG_OFF
#endif

struct tapif {
  /* Add whatever per-interface state that is needed here. */
  int fd;
};

/* Forward declarations. */
static void tapif_input(struct netif *netif);
#if !NO_SYS
/*static void tapif_thread(void *arg);*/
#endif /* !NO_SYS */

/*-----------------------------------------------------------------------------------*/

static char errbuf[PCAP_ERRBUF_SIZE];
static pcap_t * pxOpenedInterfaceHandle = NULL;
static long xInvalidInterfaceDetected = 0;

u_char *uip_buf;
int uip_len;


static void print_hex(unsigned const char * const bin_data, size_t len ){
    size_t i;
    for(i = 0; i < len; i++){
        printf("%.2X ", bin_data[i]);
    }
    printf("\n");
}

static uint8_t print_output(void *p, ssize_t len){
    if(len > 0) {
        printf( "Sending  => data send package %li \n ", len);
        print_hex((unsigned const char *)p, len);
        if(pcap_sendpacket(pxOpenedInterfaceHandle, (const u_char*) p, (int)len) != 0 ){
            printf( "pcap_sendpackeet: send failed\n");
        }
    }
    return 0;
}

/*!
 * @brief  get network interfaces from the system
 * @returns the structure list containing all found devices
 */
static pcap_if_t * prvGetAvailableNetworkInterfaces(void){
    pcap_if_t * pxAllNetworkInterfaces = NULL;
    if(xInvalidInterfaceDetected == 0){
        int ret;
        ret = pcap_findalldevs( &pxAllNetworkInterfaces, errbuf );
        if( ret == PCAP_ERROR ){
            printf("Could not obtain a list of network interfaces\n%s\n", errbuf);
            pxAllNetworkInterfaces = NULL;
        } else {
            printf( "\n\nThe following network interfaces are available:\n\n" );
        }
    }
    return pxAllNetworkInterfaces;
}

/*!
 * @brief remove spaces from pcMessage into pcBuffer
 * @param [out] pcBuffer buffer to fill up
 * @param [in] aBuflen length of pcBuffer
 * @param [in] pcMessage original message
 * @returns
 */
static const char * prvRemoveSpaces(char *pcBuffer, int aBuflen, const char *pcMessage){
    char *pcTarget = pcBuffer;
    while((*pcMessage != 0) && (pcTarget < (&pcBuffer[aBuflen - 1]))){
        *(pcTarget++) = *pcMessage;
        if(isspace( *pcMessage ) != 0){
            while(isspace(*pcMessage) != 0) {
                pcMessage++;
            }
        } else {
            pcMessage++;
        }
    }
    *pcTarget = '\0';
    return pcBuffer;
}

/*!
 * @brief  print network interfaces available on the system
 * @param[in]   pxAllNetworkInterfaces interface structure list to print
 */
static void prvPrintAvailableNetworkInterfaces(pcap_if_t * pxAllNetworkInterfaces){
    pcap_if_t * xInterface;
    int32_t lInterfaceNumber = 1;
    char cBuffer[ 512 ];

    if( pxAllNetworkInterfaces != NULL ) {
        /* Print out the list of network interfaces.  The first in the list
         * is interface '1', not interface '0'. */
        for( xInterface = pxAllNetworkInterfaces; xInterface != NULL; xInterface = xInterface->next ) {
            /* The descriptions of the devices can be full of spaces, clean them
             * a little.  printf() can only be used here because the network is not
             * up yet - so no other network tasks will be running. */
            printf( "Interface %d - %s\n", lInterfaceNumber, prvRemoveSpaces( cBuffer, sizeof( cBuffer ), xInterface->name ) );
            printf( "              (%s)\n", prvRemoveSpaces( cBuffer, sizeof( cBuffer ), xInterface->description ? xInterface->description : "No description" ) );
            printf( "\n" );
            lInterfaceNumber++;
        }
    }

    if( lInterfaceNumber == 1 ) {
        /* The interface number was never incremented, so the above for() loop
         * did not execute meaning no interfaces were found. */
        printf( " \nNo network interfaces were found.\n" );
        pxAllNetworkInterfaces = NULL;
    }

    printf("\nThe interface that will be opened is set by ");
    printf("\"configNETWORK_INTERFACE_TO_USE\", which\nshould be defined in FreeRTOSConfig.h\n");
    printf("Attempting to open interface tun0.\n");
}

/*!
 * @brief  set device operation modes
 * @returns pdPASS on success pdFAIL on failure
 */
static int prvSetDeviceModes(void){
    int ret = 0;
    printf("setting device modes of operation...\n");
    do {
        ret = pcap_set_promisc(pxOpenedInterfaceHandle, 1);
        if((ret != 0) && (ret != PCAP_ERROR_ACTIVATED)){
            printf( "couldn't not activate promisuous mode\n" );
            break;
        }
        ret = pcap_set_snaplen(pxOpenedInterfaceHandle, 1222);
        if((ret != 0) && (ret != PCAP_ERROR_ACTIVATED)) {
            printf("coult not set snaplen\n");
            break;
        }
        ret = pcap_set_timeout(pxOpenedInterfaceHandle, 200);
        if((ret != 0) && (ret != PCAP_ERROR_ACTIVATED)) {
            printf("couldn't not set timeout\n");
            break;
        }
        ret = pcap_set_buffer_size(pxOpenedInterfaceHandle, 1222 * 1100);
        if((ret != 0) && (ret != PCAP_ERROR_ACTIVATED)) {
            printf("couldn't not set buffer size\n" );
            break;
        }
        ret = 1;
    } while(0);
    return ret;
}


/*!
 * @brief  open selected interface given its name
 * @param [in] pucName interface  name to pen
 * @returns pdPASS on success pdFAIL on failure
 */
static int prvOpenInterface(const char * pucName){
    static char pucInterfaceName[256];
    int ret = 0;
    if(pucName != NULL) {
        (void) strncpy(pucInterfaceName, pucName, sizeof(pucInterfaceName));
        pucInterfaceName[sizeof(pucInterfaceName) - (size_t) 1] = '\0';
        printf("opening interface %s \n", pucInterfaceName);
        pxOpenedInterfaceHandle = pcap_create(pucInterfaceName, errbuf);
        if(pxOpenedInterfaceHandle != NULL) {
            ret = prvSetDeviceModes();
            if(ret == 1) {
                if(pcap_activate( pxOpenedInterfaceHandle) == 0) {
                } else {
                    printf("pcap activate error %s\n", pcap_geterr(pxOpenedInterfaceHandle));
                    ret = 0;
                }
            }
        } else {
            printf("\n%s is not supported by pcap and cannot be opened %s\n", pucInterfaceName, errbuf);
        }
    } else {
        printf("could not open interface: name is null\n");
    }

    return ret;
}

/*!
 * @brief Open the network interface. The number of the interface to be opened is
 *	       set by the configNETWORK_INTERFACE_TO_USE constant in FreeRTOSConfig.h
 *	       Calling this function will set the pxOpenedInterfaceHandle variable
 *	       If, after calling this function, pxOpenedInterfaceHandle
 *	       is equal to NULL, then the interface could not be opened.
 * @param [in] pxAllNetworkInterfaces network interface list to choose from
 * @returns pdPASS on success or pdFAIL when something goes wrong
 */
static int prvOpenSelectedNetworkInterface(pcap_if_t * pxAllNetworkInterfaces){
    int ret = 0;
    printf("Print pointer of allNetwork Interfaces %p: \n", (void *)pxAllNetworkInterfaces);
    if(prvOpenInterface("tap0") == 1) {
        printf( "Successfully opened interface tun0.\n");
        ret = 1;
    } else {
        printf("Failed to open interface tun0.\n");
    }
    return ret;
}

/*!
 * @brief  callback function called from pcap_dispatch function when new
 *         data arrives on the interface
 * @param [in] user data sent to pcap_dispatch
 * @param [in] pkt_header received packet header
 * @param [in] pkt_data received packet data
 * @warning this is called from a Linux thread, do not attempt any FreeRTOS calls
 */
static void pcap_callback(unsigned char * user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    printf("Receiving <=  network callback user: %s len: %d caplen: %d\n", user, pkt_header->len, pkt_header->caplen);
    print_hex(pkt_data, pkt_header->len);
    if (pkt_header->caplen <= 1214) {
        memcpy(uip_buf, pkt_data, pkt_header->len);
        printf("TUN data incoming read: %d\n", pkt_header->len);
        uip_len = (int) pkt_header->len;
        /*tcpip_input();*/
    }
}

/*!
 * @brief infinite loop pthread to read from pcap
 * @param [in] pvParam not used
 * @returns NULL
 * @warning this is called from a Linux thread, do not attempt any FreeRTOS calls
 * @remarks This function disables signal, to prevent it from being put into
 *          sleep byt the posix port
 */
static void *prvLinuxPcapRecvThread(void *pvParam) {
    int ret;
    (void) pvParam;
    for(;;) {
        unsigned char name[6] = {'m', 'y' , 'd', 'a', 't', 'a'};
        ret = pcap_dispatch( pxOpenedInterfaceHandle, 1, pcap_callback, name);
        if(ret == -1) {
            printf( "pcap_dispatch error received: %s\n", pcap_geterr( pxOpenedInterfaceHandle));
        }
    }
    return NULL;
}

/*!
 * @brief launch 2 linux threads, one for Tx and one for Rx
 *        and one FreeRTOS thread that will simulate an interrupt
 *        and notify the tcp/ip stack of new data
 * @return pdPASS on success otherwise pdFAIL
 */
static int prvCreateWorkerThreads(void) {
    pthread_t vPcapRecvThreadHandle;
    int ret = 1;
    ret = pthread_create(&vPcapRecvThreadHandle, NULL, prvLinuxPcapRecvThread, NULL);
    if(ret != 0) {
        printf("pthread error %d", ret);
    }
    return ret;
}

static err_t tun_init(struct netif* netif){
    long ret = 0;
    pcap_if_t *pxAllNetworkInterfaces;
    printf("Print netif pointer: %p\n", (void *)netif);
    uip_buf = (u_char *) malloc(1024); /*TODO: free this allocated memory*/
    uip_len = 0;
    pxAllNetworkInterfaces = prvGetAvailableNetworkInterfaces();
    if(pxAllNetworkInterfaces != NULL){
        prvPrintAvailableNetworkInterfaces(pxAllNetworkInterfaces);
        ret = prvOpenSelectedNetworkInterface(pxAllNetworkInterfaces);

        if(ret == 1){
            /* ret = prvCreateThreadSafeBuffers();*/

            /* if( ret == pdPASS )*/
            /* {*/
            ret = prvCreateWorkerThreads();
            /* } */
        }
        pcap_freealldevs(pxAllNetworkInterfaces);
    }
    if((pxOpenedInterfaceHandle != NULL) && (ret == 1)){
        ret = 1;
    }
    printf("tun_init returned %ld....\n", ret);
    return 0;

}

/*===========================================================================================*/
/*static void
low_level_init(struct netif *netif)
{
  struct tapif *tapif;
#if LWIP_IPV4
  int ret;
  char buf[1024];
#endif
  char *preconfigured_tapif = getenv("PRECONFIGURED_TAPIF");

  tapif = (struct tapif *)netif->state;

  netif->hwaddr[0] = 0x02;
  netif->hwaddr[1] = 0x12;
  netif->hwaddr[2] = 0x34;
  netif->hwaddr[3] = 0x56;
  netif->hwaddr[4] = 0x78;
  netif->hwaddr[5] = 0xab;
  netif->hwaddr_len = 6;


  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

  tapif->fd = open(DEVTAP, O_RDWR);
  LWIP_DEBUGF(TAPIF_DEBUG, ("tapif_init: fd %d\n", tapif->fd));
  if (tapif->fd == -1) {
#ifdef LWIP_UNIX_LINUX
    perror("tapif_init: try running \"modprobe tun\" or rebuilding your kernel with CONFIG_TUN; cannot open "DEVTAP);
#else
    perror("tapif_init: cannot open "DEVTAP);
#endif
    exit(1);
  }

#ifdef LWIP_UNIX_LINUX
  {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    if (preconfigured_tapif) {
      strncpy(ifr.ifr_name, preconfigured_tapif, sizeof(ifr.ifr_name) - 1);
    } else {
      strncpy(ifr.ifr_name, DEVTAP_DEFAULT_IF, sizeof(ifr.ifr_name) - 1);
    }
    ifr.ifr_name[sizeof(ifr.ifr_name)-1] = 0;

    ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
    if (ioctl(tapif->fd, TUNSETIFF, (void *) &ifr) < 0) {
      perror("tapif_init: "DEVTAP" ioctl TUNSETIFF");
      exit(1);
    }
  }
#endif

  netif_set_link_up(netif);

  if (preconfigured_tapif == NULL) {
#if LWIP_IPV4
    snprintf(buf, 1024, IFCONFIG_BIN IFCONFIG_ARGS,
             ip4_addr1(netif_ip4_gw(netif)),
             ip4_addr2(netif_ip4_gw(netif)),
             ip4_addr3(netif_ip4_gw(netif)),
             ip4_addr4(netif_ip4_gw(netif))
#ifdef NETMASK_ARGS
             ,
             ip4_addr1(netif_ip4_netmask(netif)),
             ip4_addr2(netif_ip4_netmask(netif)),
             ip4_addr3(netif_ip4_netmask(netif)),
             ip4_addr4(netif_ip4_netmask(netif))
#endif
             );

    LWIP_DEBUGF(TAPIF_DEBUG, ("tapif_init: system(\"%s\");\n", buf));
    ret = system(buf);
    if (ret < 0) {
      perror("ifconfig failed");
      exit(1);
    }
    if (ret != 0) {
      printf("ifconfig returned %d\n", ret);
    }
#else
    perror("todo: support IPv6 support for non-preconfigured tapif");
    exit(1);
#endif
  }

#if !NO_SYS
  sys_thread_new("tapif_thread", tapif_thread, netif, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
#endif
}*/
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
  /*struct tapif *tapif = (struct tapif *)netif->state;*/
  char buf[1518]; /* max packet size including VLAN excluding CRC */
  ssize_t written;

#if 0
  if (((double)rand()/(double)RAND_MAX) < 0.2) {
    printf("drop output\n");
    return ERR_OK; /* ERR_OK because we simulate packet loss on cable */
  }
#endif

  if (p->tot_len > sizeof(buf)) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    perror("tapif: packet too large");
    return ERR_IF;
  }

  /* initiate transfer(); */
  pbuf_copy_partial(p, buf, p->tot_len, 0);

  /* signal that packet should be sent(); */
  /*written = write(tapif->fd, buf, p->tot_len);*/
  written = print_output(buf, p->tot_len);
  if (written < p->tot_len) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    perror("tapif: write");
    return ERR_IF;
  } else {
    MIB2_STATS_NETIF_ADD(netif, ifoutoctets, (u32_t)written);
    return ERR_OK;
  }
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_input():
 *
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 */
/*-----------------------------------------------------------------------------------*/
static struct pbuf *
low_level_input(struct netif *netif)
{
  struct pbuf *p;
  u16_t len;
  ssize_t readlen;
  char buf[1518]; /* max packet size including VLAN excluding CRC */
  struct tapif *tapif = (struct tapif *)netif->state;

  /* Obtain the size of the packet and put it into the "len"
     variable. */
  readlen = read(tapif->fd, buf, sizeof(buf));
  if (readlen < 0) {
    perror("read returned -1");
    exit(1);
  }
  len = (u16_t)readlen;

  MIB2_STATS_NETIF_ADD(netif, ifinoctets, len);

#if 0
  if (((double)rand()/(double)RAND_MAX) < 0.2) {
    printf("drop\n");
    return NULL;
  }
#endif

  /* We allocate a pbuf chain of pbufs from the pool. */
  p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
  if (p != NULL) {
    pbuf_take(p, buf, len);
    /* acknowledge that packet has been read(); */
  } else {
    /* drop packet(); */
    MIB2_STATS_NETIF_INC(netif, ifindiscards);
    LWIP_DEBUGF(NETIF_DEBUG, ("tapif_input: could not allocate pbuf\n"));
  }

  return p;
}

/*-----------------------------------------------------------------------------------*/
/*
 * tapif_input():
 *
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 *
 */
/*-----------------------------------------------------------------------------------*/
static void
tapif_input(struct netif *netif)
{
  struct pbuf *p = low_level_input(netif);

  if (p == NULL) {
#if LINK_STATS
    LINK_STATS_INC(link.recv);
#endif /* LINK_STATS */
    LWIP_DEBUGF(TAPIF_DEBUG, ("tapif_input: low_level_input returned NULL\n"));
    return;
  }

  if (netif->input(p, netif) != ERR_OK) {
    LWIP_DEBUGF(NETIF_DEBUG, ("tapif_input: netif input error\n"));
    pbuf_free(p);
  }
}
/*-----------------------------------------------------------------------------------*/
/*
 * tapif_init():
 *
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 */
/*-----------------------------------------------------------------------------------*/
err_t
tapif_init(struct netif *netif)
{
  struct tapif *tapif = (struct tapif *)mem_malloc(sizeof(struct tapif));

  if (tapif == NULL) {
    LWIP_DEBUGF(NETIF_DEBUG, ("tapif_init: out of memory for tapif\n"));
    return ERR_MEM;
  }
  netif->state = tapif;
  MIB2_INIT_NETIF(netif, snmp_ifType_other, 100000000);

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

  tun_init(netif);

  return ERR_OK;
}


/*-----------------------------------------------------------------------------------*/
void
tapif_poll(struct netif *netif)
{
  tapif_input(netif);
}

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

/*static void
tapif_thread(void *arg)
{
  struct netif *netif;
  struct tapif *tapif;
  fd_set fdset;
  int ret;

  netif = (struct netif *)arg;
  tapif = (struct tapif *)netif->state;

  while(1) {
    FD_ZERO(&fdset);
    FD_SET(tapif->fd, &fdset);

    ret = select(tapif->fd + 1, &fdset, NULL, NULL, NULL);

    if(ret == 1) {
      tapif_input(netif);
    } else if(ret == -1) {
      perror("tapif_thread: select");
    }
  }
}*/

#endif /* NO_SYS */
