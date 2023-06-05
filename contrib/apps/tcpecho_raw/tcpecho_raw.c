/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * This file is part of and a contribution to the lwIP TCP/IP stack.
 *
 * Credits go to Adam Dunkels (and the current maintainers) of this software.
 *
 * Christiaan Simons rewrote this file to get a more stable echo example.
 */

/**
 * @file
 * TCP echo server example using raw API.
 *
 * Echos all bytes sent by connecting client,
 * and passively closes when client is done.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <netinet/in.h>

#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/tcp.h"
#include "tcpecho_raw.h"
#include "lwip/sys.h"
#include "portability_layer.h"

#include <dlfcn.h>

#define TCP_PORT 8080

struct EventCallbackData {
    void *arg;
    struct tcp_pcb *pcb;
    err_t err;
    int len;
};


static struct SyscallResponsePackage syscallResponse;
static struct EventCallbackData event_data;
static sys_sem_t event_sem;
int ip_version;

#define MAX_SOCKET_ARRAY 10

struct tcp_pcb socketArray[MAX_SOCKET_ARRAY];
int socketCounter = 3;

static void tcp_free(struct tcp_raw_state *state){
    if (state != NULL) {
        if (state->p) {
            pbuf_free(state->p);
        }
        mem_free(state);
    }
}

char *getSocketName() {
    char *socket_name;
    const char *interface_name = getenv("TAP_INTERFACE_NAME");
    if (interface_name != NULL) {

        int len = strlen(interface_name) + strlen("/tmp/socket-") + 1;
        socket_name = malloc(len * sizeof(char));
        snprintf(socket_name, len, "/tmp/socket-%s", interface_name);
    } else {
        socket_name = strdup("/tmp/socket-default");
    }

    return socket_name;
}

static void tcp_raw_close(struct tcp_pcb *tpcb, struct tcp_raw_state *state) {
    tcp_arg(tpcb, NULL);
    tcp_sent(tpcb, NULL);
    tcp_recv(tpcb, NULL);
    tcp_err(tpcb, NULL);
    tcp_poll(tpcb, NULL, 0);
    tcp_free(state);
    tcp_close(tpcb);
}

static void tcp_raw_send(struct tcp_pcb *tpcb, struct tcp_raw_state *state) {
    struct pbuf *ptr;
    err_t wr_err = ERR_OK;
    while ((wr_err == ERR_OK) && (state->p != NULL) && (state->p->len <= tcp_sndbuf(tpcb))) {
        ptr = state->p;
        wr_err = tcp_write(tpcb, ptr->payload, ptr->len, 1);
        if (wr_err == ERR_OK) {
            unsigned short int plen;
            plen = ptr->len;
            state->p = ptr->next;
            if(state->p != NULL) {
                pbuf_ref(state->p);
            }
            pbuf_free(ptr);
            tcp_recved(tpcb, plen);
            event_data.pcb = tpcb;
            event_data.err = ERR_OK;
            event_data.len += plen;
        } else if(wr_err == ERR_MEM) {
            state->p = ptr;
        }
    }
    sys_sem_signal(&event_sem);
}

static void tcp_raw_error(void *arg, err_t err) {
    struct tcp_raw_state *state;
    LWIP_UNUSED_ARG(err);
    state = (struct tcp_raw_state *)arg;
    tcp_free(state);
}

static err_t tcp_raw_poll(void *arg, struct tcp_pcb *tpcb) {
    err_t ret_err;
    struct tcp_raw_state *state;
    state = (struct tcp_raw_state *)arg;
    if (state != NULL) {
        if (state->p != NULL) {
            tcp_raw_send(tpcb, state);
        } else {
            if(state->state == ES_CLOSING) {
                tcp_raw_close(tpcb, state);
            }
        }
        ret_err = ERR_OK;
    } else {
        tcp_abort(tpcb);
        ret_err = ERR_ABRT;
    }
    return ret_err;
}

static err_t tcp_connect_callback(void *arg, struct tcp_pcb *pcb, err_t err){
    printf("CONNECT!\n");
    event_data.arg = arg;
    event_data.pcb = pcb;
    event_data.err = err;
    sys_sem_signal(&event_sem);
    return err;
}

static err_t tcp_sent_callback(void *arg, struct tcp_pcb *tpcb, unsigned short int len) {
    struct tcp_raw_state *state;
    LWIP_UNUSED_ARG(len);
    state = (struct tcp_raw_state *)arg;
    state->retries = 0;

    if(state->p != NULL) {
        tcp_sent(tpcb, tcp_sent_callback);
        tcp_raw_send(tpcb, state);
    } else {
        if(state->state == ES_CLOSING) {
            tcp_raw_send(tpcb, state);
        }
    }
    return ERR_OK;
}

static err_t tcp_recv_callback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err){
    struct tcp_raw_state *state;
    err_t ret_err;

    LWIP_ASSERT("arg != NULL",arg != NULL);
    state = (struct tcp_raw_state *) arg;
    if (p == NULL) {
        state->state = ES_CLOSING;
        if(state->p == NULL) {
            tcp_raw_close(tpcb, state);
        }
        ret_err = ERR_OK;
    } else if(err != ERR_OK) {
        LWIP_ASSERT("no pbuf expected here", p == NULL);
        ret_err = err;
    } else if(state->state == ES_ACCEPTED) {
        state->state = ES_RECEIVED;
        state->p = p;
        ret_err = ERR_OK;
        event_data.arg = arg;
        event_data.pcb = tpcb;
        event_data.err = ret_err;
        event_data.len = p->len;
    } else if (state->state == ES_RECEIVED) {
        if(state->p == NULL) {
            state->p = p;
            tcp_raw_send(tpcb, state);
        } else {
            struct pbuf *ptr;
            ptr = state->p;
            pbuf_cat(ptr,p);
        }
        ret_err = ERR_OK;
        event_data.arg = arg;
        event_data.pcb = tpcb;
        event_data.err = ret_err;
        event_data.len = p->len;
    } else {
        tcp_recved(tpcb, p->tot_len);
        event_data.arg = arg;
        event_data.pcb = tpcb;
        event_data.err = ERR_OK;
        event_data.len = p->len;
        pbuf_free(p);
        ret_err = ERR_OK;
    }
    sys_sem_signal(&event_sem);
    return ret_err;
}

static err_t tcp_accept_callback(void *arg, struct tcp_pcb *new_pcb, err_t err) {
    err_t ret_err;
    struct tcp_raw_state *state;

    LWIP_UNUSED_ARG(arg);
    if ((err != ERR_OK) || (new_pcb == NULL)) {
        return ERR_VAL;
    }
    tcp_setprio(new_pcb, TCP_PRIO_MIN);
    state = (struct tcp_raw_state *) mem_malloc(sizeof(struct tcp_raw_state));
    if (state != NULL) {
        state->state = ES_ACCEPTED;
        state->pcb = new_pcb;
        state->retries = 0;
        state->p = NULL;
        tcp_arg(new_pcb, state);
        tcp_recv(new_pcb, tcp_recv_callback);
        tcp_err(new_pcb, tcp_raw_error);
        tcp_poll(new_pcb, tcp_raw_poll, 0);
        tcp_sent(new_pcb, tcp_sent_callback);
        ret_err = ERR_OK;
        event_data.arg = arg;
        event_data.pcb = new_pcb;
        event_data.err = ret_err;
    } else {
        ret_err = ERR_MEM;
    }

    sys_sem_signal(&event_sem);
    return ret_err;
}

static int reset_socket_array(void){
    int sizeSocketArray = socketCounter - 3;
    if (sizeSocketArray > 0) {
        int counter;
        for (counter = 3; counter < socketCounter; counter++) {
            struct tcp_pcb *pcb = &socketArray[counter];
            LOCK_TCPIP_CORE();
            tcp_close(pcb);
            UNLOCK_TCPIP_CORE();
        }
        memset(socketArray, 0, MAX_SOCKET_ARRAY * sizeof(struct tcp_pcb));
    }
    socketCounter = 3;
    printf("PacketDrill Handler Task Reset..\n");
    return sizeSocketArray;
}

int socket_syscall(int domain){
    printf("Socket create in LwIP\n");

    struct tcp_pcb *pcb;
    struct SocketPackage p;

    LOCK_TCPIP_CORE();
    pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    UNLOCK_TCPIP_CORE();

    ip_version = domain == AF_INET ? 4 : 6;

    if (pcb == NULL) {
        printf("Error in \"socket_create\" instruction");
        return -1;
    } else {
        socketArray[socketCounter] = *pcb;
        return socketCounter++;
    }
}

int bind_syscall(int index, unsigned short int port){
    printf("Socket bind in LwIP\n");

    struct tcp_pcb *pcb;
    err_t err;

    pcb = &socketArray[index];

    LOCK_TCPIP_CORE();
    err = tcp_bind(pcb, IP_ANY_TYPE, lwip_htons(port));
    UNLOCK_TCPIP_CORE();

    if (err != ERR_OK) {
        printf("Error in \"socket_bind\" instruction");
        return -1;
    } else {
        return 0;
    }
}

int listen_syscall(int index){
    printf("Socket listen in LwIP\n");

    struct tcp_pcb *pcb;
    err_t err;

    pcb = &socketArray[index];

    LOCK_TCPIP_CORE();
    pcb = tcp_listen_with_backlog_and_err(pcb, 0, &err);
    UNLOCK_TCPIP_CORE();

    LOCK_TCPIP_CORE();
    tcp_accept(pcb, tcp_accept_callback);
    UNLOCK_TCPIP_CORE();

    if(err != ERR_OK){
        printf("Error in \"socket_listen\" instruction");
        return -1;
    } else {
        return 0;
    }

}

struct SyscallResponsePackage accept_syscall(int index){
    printf("Socket accept in LwIP\n");

    struct tcp_pcb *pcb;
    struct AcceptResponsePackage acceptResponse;
    struct sockaddr_in add4;
    struct sockaddr_in6 add6;

    pcb = &socketArray[index];

    printf("About to yield in accept ... \n");
    sys_sem_wait(&event_sem);
    printf("Waking up from yield in accept ... \n");

    if(event_data.pcb == NULL){
        printf("Error in \"socket_accept\" instruction");
    }

    socketArray[socketCounter] = *event_data.pcb;

    if(ip_version == 4){
        add4.sin_family = AF_INET;
        add4.sin_port = htons(event_data.pcb->remote_port);
        memcpy(&add4.sin_addr.s_addr, &event_data.pcb->remote_ip.u_addr.ip4.addr, sizeof(struct in_addr));
        acceptResponse.addr = add4;
        acceptResponse.addrlen = sizeof(struct sockaddr_in);
    }else if (ip_version == 6){
        add6.sin6_family = AF_INET6;
        add6.sin6_port = htons(event_data.pcb->remote_port);
        memcpy(&add6.sin6_addr.s6_addr, &event_data.pcb->remote_ip.u_addr.ip6.addr, sizeof(struct in6_addr));
        acceptResponse.addr6 = add6;
        acceptResponse.addrlen = sizeof(struct sockaddr_in6);
    }

    syscallResponse.acceptResponse = acceptResponse;

    if(event_data.err != ERR_OK){
        printf("Error in \"socket_accept\" instruction: Exit");
        syscallResponse.result = -1;
    }else{
        syscallResponse.result = socketCounter++;
    }
    event_data.pcb = NULL;
    return syscallResponse;
}

int connect_syscall(int index, struct in_addr address, unsigned short int port){
    struct tcp_pcb *pcb;
    struct ip_addr dest_ipaddr;

    pcb = &socketArray[index];

    memcpy(&dest_ipaddr.u_addr.ip4.addr, &address, sizeof(struct in_addr));

    LOCK_TCPIP_CORE();
    tcp_connect(pcb, &dest_ipaddr, htons(port), tcp_connect_callback);
    UNLOCK_TCPIP_CORE();

    printf("About to yield in connect ... \n");
    sys_sem_wait(&event_sem);
    printf("Waking up from yield in connect ... \n");

    if(event_data.pcb == NULL){
        printf("Error in \"socket_connect\" instruction");
    }
    event_data.pcb = NULL;
    if(event_data.err != ERR_OK){
        printf("Error in \"socket_connect\" instruction");
        return -1;
    } else {
        return 0;
    }

}

int write_syscall(int index, void *buffer, unsigned long size){
    printf("Socket write in LwIP\n");
    struct tcp_pcb *pcb;
    struct tcp_raw_state *state;

    state = (struct tcp_raw_state *) mem_malloc(sizeof(struct tcp_raw_state));

    pcb = &socketArray[index];

    state->state = ES_ACCEPTED;
    state->p = pbuf_alloc(PBUF_RAW, size, PBUF_POOL); /*@todo: pbuf.c line 251, could not allocate 50k, segmentation fault*/
    if(state->p == NULL){
        printf("Error allocating memory.\n");
        return -1;
    } else {
        state->p->payload = buffer;

        LOCK_TCPIP_CORE();
        tcp_raw_send(pcb, state);
        UNLOCK_TCPIP_CORE();

        printf("About to yield in write ... \n");
        sys_sem_wait(&event_sem);
        printf("Waking up from yield in write ... \n");

        event_data.pcb = NULL;
        event_data.len = 0;

        if(event_data.err != ERR_OK){
            printf("Error in \"socket_write\" instruction");
            return -1;
        }else{
            return event_data.len;
        }
    }
}

int read_syscall(int index){
    struct tcp_pcb *pcb;
    pcb = &socketArray[index];
    LWIP_UNUSED_ARG(pcb);

    printf("About to yield in read ... \n");
    sys_sem_wait(&event_sem);
    printf("Waking up from yield in read ... \n");
    event_data.pcb = NULL;

    if(event_data.err != ERR_OK){
        printf("Error in \"socket_read\" instruction");
        return -1;
    }else{
        return event_data.len;
    }
}

int close_syscall(int index){
    struct tcp_pcb *pcb;
    err_t err;

    pcb = &socketArray[index];

    LOCK_TCPIP_CORE();
    err = tcp_close(pcb);
    UNLOCK_TCPIP_CORE();

    if(err != ERR_OK){
        printf("Error in \"socket_close\" instruction");
        return -1;
    }else{
        return 0;
    }
}

int init_syscall(void){
    return reset_socket_array();
}

void tcp_server_init(void){
    void *handle = dlopen(getenv("PORTABILITY_LAYER_PATH"), RTLD_NOW | RTLD_LOCAL | RTLD_NODELETE);
    if(!handle){
        printf("Error importing portability layer");
    }
    packetdrill_run_syscalls_fn run_syscalls = dlsym(handle, "run_syscalls");
    struct packetdrill_syscalls args;
    sys_sem_new(&event_sem, 0);
    args.socket_syscall = socket_syscall;
    args.bind_syscall = bind_syscall;
    args.listen_syscall = listen_syscall;
    args.accept_syscall = accept_syscall;
    args.connect_syscall = connect_syscall;
    args.write_syscall = write_syscall;
    args.read_syscall = read_syscall;
    args.close_syscall = close_syscall;
    args.init_syscall = init_syscall;
    run_syscalls(&args);
}
