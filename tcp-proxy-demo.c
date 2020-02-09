/*

    COPYRIGHT AND PERMISSION NOTICE
    Copyright (c) 2019-2020 Mark Griffiths
    All rights reserved.
    Permission to use, copy, modify, and distribute this software for any
    purpose with or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    USE OR OTHER DEALINGS IN THE SOFTWARE.

    Except as contained in this notice, the name of a copyright holder shall
    not be used in advertising or otherwise to promote the sale, use or other
    dealings in this Software without prior written authorization of the
    copyright holder.

    Simple single-threaded, multi-connect non-blocking TCP Proxy application
    demonstrating usage of mg-skt non-blocking library.

	Listens to port 8080 on local machine and connects to port 80 on remote
	machine.

 */

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <assert.h>
#include "mg-skt.h"

#define HP_DATA_CONN_MAX 256

/* data connection record */
typedef struct {
	struct tp_conn *conn;
	void *sock;
} tp_sock_data_t;

/* connection record */
typedef struct tp_conn {
	struct tp *tp;
	int idx;
	tp_sock_data_t client_sock_data;
	tp_sock_data_t server_sock_data;
	struct {
		struct in_addr ip;
		in_port_t port;
	} client;
	int age;
} tp_conn_t;

/* tcp proxy record */
typedef struct tp {
	void *listen_handle;
	struct in_addr srv_ip_loc;
	struct in_addr srv_ip_rem;
	tp_conn_t *conn[HP_DATA_CONN_MAX];
} tp_t;

/* Print active client-server connections */
static void tp_conn_list_print(tp_t *tp)
{
	tp_conn_t *c;
	int i;
	char ip_c[INET_ADDRSTRLEN];
	printf("--------------------------------\n");
	printf("|   Client IP    / Port  | Age |\n");
	printf("--------------------------------\n");
	for (i = 0; i < HP_DATA_CONN_MAX; i++) {
		if ((c = tp->conn[i])) {
			inet_ntop(AF_INET, &c->client.ip, ip_c, sizeof(ip_c));
			printf("|%17s/%5d |%4d |\n",
			       ip_c, c->client.port, c->age);
		}
	}
	printf("--------------------------------\n");
}

/* Return a free connection */
static tp_conn_t *tp_conn_add(tp_t *tp, struct sockaddr *accept)
{
	int i;
	struct sockaddr_in *a = (struct sockaddr_in*)accept;
	for (i = 0; i < HP_DATA_CONN_MAX; i++) {
		if (tp->conn[i] == NULL) {
			tp_conn_t *c = tp->conn[i] = calloc(10, sizeof(*c));
			assert(c);
			c->idx = i;
			c->tp = tp;
			c->client.ip.s_addr = a->sin_addr.s_addr;
			c->client.port = a->sin_port;
			return c;
		}
	}
	return NULL;
}

/* Data received from the server -  send to the client */
static void tp_conn_server_rx(void *handle, struct sockaddr *rx_skt, unsigned char *buf, int buflen)
{
	tp_sock_data_t *ds = handle;
	tp_conn_t *c = ds->conn;
	tp_sock_data_t *dc = &c->client_sock_data;
	if (mg_skt_tx(dc->sock, buf, buflen)) {
		printf("could not sent %d bytes from server to client\n", buflen);
	};
}

/* Data received from the client - send to the server */
static void tp_conn_client_rx(void *handle, struct sockaddr *rx_skt, unsigned char *buf, int buflen)
{
	tp_sock_data_t *dc = handle;
	tp_conn_t *c = dc->conn;
	tp_sock_data_t *ds = &c->server_sock_data;
	if (mg_skt_tx(ds->sock, buf, buflen)) {
		printf("could not sent %d bytes from client to server\n", buflen);
	};
}

static void tp_conn_close(tp_sock_data_t *d)
{
	tp_conn_t *c = d->conn;
	mg_skt_close(d->sock);
	c->tp->conn[c->idx] = NULL;
	free(c);
}

/* Client is closing the connection - close the server side */
static void tp_conn_client_close(void *handle)
{
	tp_sock_data_t *dc = handle;
	tp_conn_close(&dc->conn->server_sock_data);
}

/* Server is closing the connection - close the client side */
static void tp_conn_server_close(void *handle)
{
	tp_sock_data_t *ds = handle;
	tp_conn_close(&ds->conn->client_sock_data);
}

/* Process inbound connection request from client and make it to the server */
static void **tp_conn_accept(void *tp_conn_handle, mg_skt_param_t *cp, struct sockaddr *accept_addr)
{
	tp_t *tp = (tp_t*)tp_conn_handle;
	tp_conn_t *c = tp_conn_add(tp, accept_addr);
	if (c) {
		/* found a free data connection - now open a data socket to the server */
		tp_sock_data_t *dc = &c->client_sock_data;
		tp_sock_data_t *ds = &c->server_sock_data;
		struct sockaddr_in connect_addr = {
			.sin_family = AF_INET,
			.sin_port = htons(80),
			.sin_addr = tp->srv_ip_rem,
		};
		mg_skt_param_t server_data_skt_param = {
			.handle = ds,
			.family = AF_INET,
			.type = SOCK_STREAM,
			.connect_addr = (struct sockaddr*)&connect_addr,
			.connect_addr_len = sizeof(connect_addr),
			.rx = tp_conn_server_rx,
			.close = tp_conn_server_close
		};
		ds->conn = c;
		ds->sock = mg_skt_open(&server_data_skt_param);
		assert(ds->sock);
		/* fill in client params */
		cp->handle = (void*)dc;
		cp->rx = tp_conn_client_rx;
		cp->close = tp_conn_client_close;
		dc->conn = c;
		/* return the *address* of the client's data connection handle */
		return &dc->sock;
	}
	return NULL;
}

/* Accept console input. Any key input generates a list of active connections */
static void tp_console_rx(void *handle, struct sockaddr *rx_skt, unsigned char *rx_buf, int rx_buflen)
{
	tp_t *tp = (tp_t*)handle;
	tp_conn_list_print(tp);
}

/* 1 second timeout */
static void tp_timeout(void *handle)
{
	int i;
	tp_t *tp = (tp_t*)handle;
	for (i = 0; i < HP_DATA_CONN_MAX; i++) {
		if (tp->conn[i]) {
			tp->conn[i]->age++;
		}
	}
}

int main(int argc, char *argv[])
{
	tp_t tp = {};
	if (argc != 3 ||
	    inet_pton(AF_INET, argv[1], &tp.srv_ip_rem) != 1 ||
	    inet_pton(AF_INET, argv[2], &tp.srv_ip_loc) != 1) {
		/* couldn't parse IP address(es) */
		printf("usage: tp <remote IPv4 address> <my IPv4 address>\n");
		exit(1);
	}
	struct sockaddr_in listen_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(8080),
		.sin_addr.s_addr = tp.srv_ip_loc.s_addr
	};
	mg_listen_param_t listen_param = {
		.handle = (void*)&tp,
		.accept = tp_conn_accept,
		.family = AF_INET,
		.type = SOCK_STREAM,
		.sock_addr = (struct sockaddr*)&listen_addr,
		.slen = sizeof(listen_addr)
	};
	/* listen on local server */
	tp.listen_handle = mg_listen_open(&listen_param);
	assert(tp.listen_handle);
	/* allow console input */
	mg_param_t tpp = {
		.console = { .rx = tp_console_rx, .handle = &tp }
	};
	/* add a 1-sec periodic timer */
	mg_timer_add((void*) &tp, tp_timeout);
	/* start waiting for events */
	return mg_dispatch(&tpp);
}
