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

#define TCP_PORT 7
#define SOCKET_NAME "/tmp/mysocket1"


struct SocketPackage {
    int domain;
    int type;
    int protocol;
};

struct AcceptPackage {
    int sockfd;
};

struct BindPackage {
    int sockfd;
    union {
        struct sockaddr_in addr;
        struct sockaddr_in6 addr6;
    };
    socklen_t addrlen;
};

struct ListenPackage {
    int sockfd;
    int backlog;
};

struct WritePackage {
    int sockfd;
    int count;
};

struct SendToPackage {
    int sockfd;
    int flags;
    union {
        struct sockaddr_in addr;
        struct sockaddr_in6 addr6;
    };
    socklen_t addrlen;
};

struct ReadPackage {
    int sockfd;
    int count;
};

struct RecvFromPackage {
    int sockfd;
    int count;
    int flags;
};

struct ClosePackage {
    int sockfd;
};

struct AcceptResponsePackage {
    union {
        struct sockaddr_in addr;
        struct sockaddr_in6 addr6;
    };

    socklen_t addrlen;
};

struct SyscallResponsePackage {
    int result;
    union {
        struct AcceptResponsePackage acceptResponse;
    };
};


struct SyscallPackage {
    char syscallId[20];
    int bufferedMessage;
    int bufferedCount;
    void *buffer;
    union {
        struct SocketPackage socketPackage;
        struct BindPackage bindPackage;
        struct ListenPackage listenPackage;
        struct AcceptPackage acceptPackage;
        struct BindPackage connectPackage;
        struct WritePackage writePackage;
        struct SendToPackage sendToPackage;
        struct ClosePackage closePackage;
        struct ReadPackage readPackage;
        struct RecvFromPackage recvFromPackage;
    };
};


static struct tcp_pcb *pcb;


static void tcp_free(struct tcp_raw_state *state){
    if (state != NULL) {
        if (state->p) {
            pbuf_free(state->p);
        }
        mem_free(state);
    }
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
        } else if(wr_err == ERR_MEM) {
            state->p = ptr;
        } else {
        }
    }
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
        } else {
            tcp_raw_send(tpcb, state);
        }
        ret_err = ERR_OK;
    } else if(err != ERR_OK) {
        LWIP_ASSERT("no pbuf expected here", p == NULL);
        ret_err = err;
    } else if(state->state == ES_ACCEPTED) {
        state->state = ES_RECEIVED;
        state->p = p;
        tcp_raw_send(tpcb, state);
        ret_err = ERR_OK;
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
    } else {
        tcp_recved(tpcb, p->tot_len);
        pbuf_free(p);
        ret_err = ERR_OK;
    }
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
    } else {
        ret_err = ERR_MEM;
    }
    return ret_err;
}

/**
 * Function to initialize tcp server
 */
void tcp_server_init(void) {

    struct sockaddr_un addr;
    struct SyscallPackage syscallPackage;
    struct tcp_raw_state *state;
    int sfd, cfd;
    ssize_t numRead;

    printf("Creating socket to PacketDrill ... \n");

    unlink(SOCKET_NAME);
    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd == -1) {
        printf("Error creating socket to PacketDrill ... \n");
        exit(EXIT_FAILURE);
    }
    printf("Socket to PacketDrill created! \n");
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCKET_NAME);

    printf("Binding ports in socket to PacketDrill ... \n");
    if (bind(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == -1) {
        printf("Error binding PacketDrill socket to port ... \n");
        exit(EXIT_FAILURE);
    }
    printf("Ports to PacketDrill bound! \n");

    printf("Listen for incoming connection from PacketDrill ... \n");
    if (listen(sfd, TCP_LISTEN_BACKLOG) == -1) {
        printf("Error listening on PacketDrill socket ... \n");
        exit(EXIT_FAILURE);
    }

    for (;;) {
        cfd = accept(sfd, NULL, NULL);
        if (cfd == -1) {
            printf("Error accepting connection from PacketDrill ... \n");
            exit(EXIT_FAILURE);
        }
        state = (struct tcp_raw_state *) mem_malloc(sizeof(struct tcp_raw_state));

        while ((numRead = read(cfd, &syscallPackage, sizeof(struct SyscallPackage))) > 0) {
            if (syscallPackage.bufferedMessage == 1) {
                void *buffer = malloc(syscallPackage.bufferedCount);
                ssize_t bufferCount = read(cfd, buffer, syscallPackage.bufferedCount);
                if (bufferCount <= 0) {
                    printf("Error reading buffer content from socket\n");
                } else if (bufferCount != syscallPackage.bufferedCount) {
                    printf("Count of buffer not equal to expected count.\n");
                } else {
                    printf("Successfully read buffer count from socket.\n");
                }
                syscallPackage.buffer = buffer;
            }
            printf("Packetdrill command received: %s\n", syscallPackage.syscallId);

            if (strcmp(syscallPackage.syscallId, "socket_create") == 0) {
                struct SocketPackage socketPackage = syscallPackage.socketPackage;
                if (socketPackage.protocol == 6) {
                    pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
                }
            } else if (strcmp(syscallPackage.syscallId, "socket_bind") == 0) {
                tcp_bind(pcb, IP_ANY_TYPE, TCP_PORT);
            } else if (strcmp(syscallPackage.syscallId, "socket_listen") == 0) {
                pcb = tcp_listen(pcb);
            } else if (strcmp(syscallPackage.syscallId, "socket_accept") == 0) {
                tcp_accept(pcb, tcp_accept_callback);
            } else if (strcmp(syscallPackage.syscallId, "socket_connect") == 0) {

            } else if (strcmp(syscallPackage.syscallId, "socket_write") == 0) {
                tcp_sent_callback(state, pcb,0);
            } else if (strcmp(syscallPackage.syscallId, "socket_read") == 0) {
                tcp_recv_callback(state, pcb, state->p, 0);
            } else if (strcmp(syscallPackage.syscallId, "socket_close") == 0){
                tcp_raw_close(pcb, state);
            }
            /*TODO: possible missing else if statement*/
        }
    }

}
