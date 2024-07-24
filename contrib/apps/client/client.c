#include "lwip/opt.h"

#if LWIP_RAW /* don't build if not configured for use in lwipopts.h */

#include "client.h"
#include "lwip/mem.h"
#include "lwip/raw.h"
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "lwip/icmp.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "lwip/inet_chksum.h"
#include "lwip/prot/ip4.h"
#include "lwip/timeouts.h"
#include <time.h>
#include <stdio.h>
#include <string.h>




/* ping variables */
#ifdef LWIP_DEBUG
#endif /* LWIP_DEBUG */
#if !PING_USE_SOCKETS
#endif /* PING_USE_SOCKETS */

/** Prepare a echo ICMP request */

#if PING_USE_SOCKETS

/* Ping using the socket ip */

#endif /* PING_USE_SOCKETS */

/**
 * Initialize thread (socket mode) or timer (callback mode) to cyclically send pings
 * to a target.
 * Running ping is implicitly stopped.
 */
enum client_states
{
  ES_NONE = 0,
  ES_ACCEPTED,
  ES_RECEIVED,
  ES_CLOSING
};


struct client_state
{
  u8_t state;
  u8_t retries;
  struct tcp_pcb *pcb;
  struct pbuf *p;
};


struct tcp_pcb *client;
int counter = 0;

uint8_t data[100];

/* create a struct to store data */
struct client_state *esTx = 0;
struct tcp_pcb *pcbTx = 0;

static err_t tcp_client_raw_connected(void *arg, struct tcp_pcb *newpcb, err_t err);
static err_t tcp_client_raw_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static err_t tcp_client_raw_poll(void *arg, struct tcp_pcb *tpcb);
static err_t tcp_client_raw_sent(void *arg, struct tcp_pcb *tpcb, u16_t len);


static void tcp_client_raw_send(struct tcp_pcb *tpcb, struct client_state *es);

static void tcp_client_connection_close(struct tcp_pcb *tpcb, struct client_state *es);

static void tcp_client_handle(struct tcp_pcb *tpcb, struct client_state *es);

struct netif loop_netif;

void client_init(void)
{
  ip_addr_t destIPADDR;
  err_t err;
  client = tcp_new();

  IP_ADDR4(&destIPADDR, 192, 168, 1, 100);

  err = tcp_connect(client, &destIPADDR, 7, tcp_client_raw_connected);
  if (err == ERR_ISCONN) {

  }
}



/* tcp를 연결 */
/* tcp client connect callback function */
static err_t tcp_client_raw_connected(void *arg, struct tcp_pcb *newpcb, err_t err) {
  err_t ret;
  struct client_state *es = esTx; 

  LWIP_UNUSED_ARG(arg);
  LWIP_UNUSED_ARG(err);

  /* tcp 정보를 유지하기 위해서는 메모리 할당을 통한 유지 필요 */
  es = (struct client_state *)mem_malloc(sizeof(struct client_state));

  printf("tcp client raw connected try\n");
  if (es != NULL) {
    es->state = ES_ACCEPTED;
    es->pcb = newpcb;
    es->retries = 0;
    es->p = NULL;

    tcp_arg(newpcb, es);
    tcp_recv(newpcb, tcp_client_raw_recv);
    tcp_poll(newpcb, tcp_client_raw_poll, 0);
    tcp_sent(newpcb, tcp_client_raw_sent);

    tcp_client_handle(newpcb, es);

	es->p = pbuf_alloc(PBUF_TRANSPORT, strlen((char*)data), PBUF_POOL);
	printf("tcp client open connection success\n");

    ret = ERR_OK;
  } else {
    tcp_client_connection_close(newpcb, es);
    ret = ERR_MEM;
	  printf("Error occur at open connection\n");
  }
  return ret;
}


/* 클라이언트 recv */
static err_t tcp_client_raw_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
  struct client_state *es;
  err_t ret;

  LWIP_ASSERT("arg != NULL", arg != NULL);
  es = (struct client_state *)arg;

  if (p == NULL) {
    es->state = ES_CLOSING;
    if (es->p == NULL) {
      tcp_client_connection_close(tpcb, es);
    } else {
      tcp_client_raw_send(tpcb, es);
    }
    ret = ERR_OK;
  } else if (err != ERR_OK) { /* packet not null but error detect */
    LWIP_ASSERT("no pbuf expected here", p == NULL);
    ret = err;
  } else if (es->state == ES_ACCEPTED) { /* packet not null and state Accepted */
    es->state = ES_RECEIVED;
    es->p = p;
    tcp_client_raw_send(tpcb, es);
    ret = ERR_OK;
	printf("tcp client recv callback function\n");
  } else if (es->state == ES_RECEIVED) {
    /* read some more data */
    if(es->p == NULL) {
      es->p = p;
      tcp_client_raw_send(tpcb, es);
    } else {
      struct pbuf *ptr;

      /* chain pbufs to the end of what we recv'ed previously  */
      ptr = es->p;
      pbuf_cat(ptr,p);
    }
    ret = ERR_OK;
  } else {
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    ret = ERR_OK;
  }
  printf("client raw recv callback");
  return ret;
}

static err_t tcp_client_raw_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
  struct client_state *es;
  LWIP_UNUSED_ARG(len);

  es = (struct client_state *)arg;
  es->retries = 0;

  if (es->p != NULL) {
    tcp_sent(tpcb, tcp_client_raw_sent);
    tcp_client_raw_send(tpcb, es);
  } else {
    if (es->state == ES_CLOSING) {
      tcp_client_connection_close(tpcb, es);
    }
  }
  return ERR_OK;
}



/* 할당된 메모리를 해제 */
static void tcp_client_raw_free(struct client_state *es) { 
  if (es != NULL) {
    if (es->p) {
      pbuf_free(es->p);
    }
    mem_free(es);
  }
}

static void tcp_client_connection_close(struct tcp_pcb *tpcb, struct client_state *es) {
  tcp_arg(tpcb, NULL);
  tcp_recv(tpcb, NULL);
  tcp_sent(tpcb, NULL);
  tcp_err(tpcb, NULL);
  tcp_poll(tpcb, NULL, 0);
  tcp_client_raw_free(es);
  tcp_close(tpcb);
}

void tcp_client_send(void) {
	if (esTx == NULL) return;
	if (esTx->state != ES_ACCEPTED) return;
	tcp_client_raw_send(client, esTx);
}



/* 페이로드의 데이터를 전달 */
static void tcp_client_raw_send(struct tcp_pcb *tpcb, struct client_state *es) {
  struct pbuf *ptr;
  size_t msg_len;
  err_t ret = ERR_OK;
  char msg[30] = "";

  if (scanf("%s", msg) != 1) {
	  printf("input error\n");
	  return;
  }

  msg_len = strlen((char *)msg);	

  if (es->p != NULL) {
	  pbuf_free(es->p);
  }

  
  es->p = pbuf_alloc(PBUF_RAW, msg_len, PBUF_POOL); /* packet buffer allocation */

  if (es->p == NULL) {
	  printf("packet buffer allocation error\n");
	  return;
  }

  ptr = es->p; /* 전달할 패킷의 패이로드를 포인팅 */
  /*strncpy((char *)ptr->payload, msg, ptr->len);*/ /* string copy msg to payload */
  memset(ptr->payload, 0, 30);
  memcpy(ptr->payload, msg, msg_len);

  while ((ret == ERR_OK) && (ptr != NULL) && (ptr->len <= tcp_sndbuf(tpcb))) {
	  printf("%s\n", (char *)ptr->payload); 
	
	  ret = tcp_write(tpcb, ptr->payload, ptr->len, TCP_WRITE_FLAG_COPY); /* 페이로드 부분을 이용하여 tcp_write를 수행 */
	  if (ret == ERR_OK) {
		/* u16_t plen = ptr->len;  보내야 할 데이터가 fragmentation이 발생하는 경우 */
		es->p = ptr->next;

		if (es->p != NULL) {
			pbuf_ref(es->p);
		}

		if (ptr == NULL) {printf("nullllll\n");}
/*		pbuf_free(ptr);*/
/*
		if (ptr->next != NULL) {
			ptr = ptr->next;
		}
		else {
			ptr = NULL;
		}

		tcp_output(tpcb);

		pbuf_free(es->p); current packet free 
		es->p = ptr;
		if (es->p != NULL) { 
			pbuf_ref(es->p);
		}

		if (ptr != NULL) {
			pbuf_free(ptr); chop first pbuf from chain 
		}*/
		printf("client send packet to server\n");
	/*	tcp_recved(tpcb, plen); we can read more data now */
		} else if (ret == ERR_MEM) {
			es->p = ptr;
		} else {

		}
	}
  
}



static err_t tcp_client_raw_poll(void *arg, struct tcp_pcb *tpcb) {
  err_t ret;
  struct client_state *es;

  es = (struct client_state *)arg;
  if (es != NULL) { /* arg 파라미터가 NULL이 아닌 경우 */
    if (es->p != NULL) {
		tcp_client_raw_send(tpcb, es);
    } else {
      if (es->state == ES_CLOSING) /* 상태가 닫혀있는 상태인 경우 */
      {
        tcp_client_connection_close(tpcb, es);
      }
    }
    ret = ERR_OK;
  }
  else { /* arg 파라미터가 NULL인 경우 */
    tcp_abort(tpcb); 
    ret = ERR_ABRT;
  }
  return ret;
}





static void tcp_client_handle (struct tcp_pcb *tpcb, struct client_state *es)
{
	/* get the Remote IP */
	ip_addr_t inIP = tpcb->remote_ip;
	uint16_t inPort = tpcb->remote_port;

	/* Extract the IP */
	char *remIP = ipaddr_ntoa(&inIP);
	printf("%s", remIP);
	printf("%d", inPort);
/*	esTx->state = es->state; */
/*	esTx->pcb = es->pcb; */
/*	esTx->p = es->p; */

	esTx = es;
}


/**
 * Stop sending more pings.
 */

#endif /* LWIP_RAW */
