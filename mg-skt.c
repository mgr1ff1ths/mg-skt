/*

    COPYRIGHT AND PERMISSION NOTICE
    Copyright (c) 2015-2020 Mark Griffiths
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

	"mg-skt" non-blocking sockets abstraction layer.

 */

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/un.h>
#include <assert.h>
#include "mg-skt.h"

#define MG_RX_BUF_SIZE   5000
#define MG_FD_LIST_SIZE  32
#define MG_TXQ_ENTRY_MAX 4

#define MG_TXQ_ENTRIES(s, e) \
		(((s) - (e)) + MG_TXQ_ENTRY_MAX) % MG_TXQ_ENTRY_MAX)

#if (0)	// set to 1 for debug messages
#define MG_LOG_DBG(...) printf(__VA_ARGS__)
#else
#define MG_LOG_DBG(...)
#endif

#if (0)	// set to 1 for error messages
#define MG_LOG_ERR(...) printf(__VA_ARGS__)
#else
#define MG_LOG_ERR(...)
#endif

typedef struct mg_timer_cb {
	struct mg_timer_cb *next;
	void *handle;
	void (*callback)(void*);
} mg_timer_cb_t;

typedef struct mg_fd_list_entry {
	struct mg_skt *mg_skt;
	int fd;
	int deleting;
} mg_fd_list_entry_t;

typedef struct {
	unsigned char *buf, *bufptr;
	int buflen;
} txq_entry_t;

typedef struct mg_skt {
	union {
		mg_skt_param_t		skt;
		mg_listen_param_t	listen;
	} params;
	int fd;
	void (*rx)(struct mg_fd_list_entry*);
	int txq_s;
	int txq_e;
	txq_entry_t txq[MG_TXQ_ENTRY_MAX];
	int tx_watch;
} mg_skt_t;

/* global structure */
static struct {
	void *console_handle;
	mg_timer_cb_t *timer_cb_first;
	int fd_list_count;
	int fd_isset_in_progress;
	struct timeval timeout;
	mg_fd_list_entry_t fd_list[MG_FD_LIST_SIZE];
} mg = { .timeout.tv_sec = 1 };

static int mg_fd_add(int fd, mg_skt_t *mg_skt)
{
	mg_fd_list_entry_t *le;
	assert(mg.fd_list_count < MG_FD_LIST_SIZE);
	le = &mg.fd_list[mg.fd_list_count];
	le->fd = fd;
	le->mg_skt = mg_skt;
	le->deleting = 0;
	mg.fd_list_count++;
	return 0;
}

static int mg_fd_del(int fd)
{
	mg_fd_list_entry_t *le;
	int i;
	assert(mg.fd_list_count);
	for (i = 0, le = mg.fd_list; i < mg.fd_list_count; i++, le++) {
		if (le->fd == fd) {
			/* found it */
			if (mg.fd_isset_in_progress) {
				le->deleting = 1;
			}
			else {
				mg.fd_list_count--;
				memmove(le, le + 1, mg.fd_list_count - i);
			}
			return 0;
		}
	}
	/* not found */
	assert(0);
	return 1;
}

static int mg_skt_write(mg_skt_t *mg_skt, unsigned char **buf, int *buflen)
{
	int l;
	while (*buflen) {
		if ((l = write(mg_skt->fd, *buf, *buflen)) < 0) {
			if (errno == EAGAIN) {
				/* write buffer full, enqueue the rest */
				mg_skt->tx_watch = 1;
				MG_LOG_DBG("mg_skt_write[%d]: tx_watch = 1\n", mg_skt->fd);
				break;
			}
			MG_LOG_ERR("mg_skt_write[%d]: write failed <%s>\n", mg_skt->fd, strerror(errno));
			assert(0);
		}
		else {
			*buf += l;
			*buflen -= l;
		}
	}
	/* return the number of unwritten bytes */
	return *buflen;
}

static int mg_dequeue(mg_skt_t *mg_skt)
{
	MG_LOG_DBG("mg_dequeue[%d]: %d entries\n",
	           mg_skt->fd, MG_TXQ_ENTRIES(mg_skt->txq_s, mg_skt->txq_e));
	while (mg_skt->txq_s != mg_skt->txq_e) {
		/* something to dequeue */
		txq_entry_t *txq = &mg_skt->txq[mg_skt->txq_s];
		unsigned char *bufptr = txq->bufptr;
		int buflen = txq->buflen;
		mg_skt_write(mg_skt, &bufptr, &buflen);
		if (buflen == 0) {
			/* all data sent successfully, dequeue item */
			free(txq->buf);
			txq->buf = NULL;
			txq->bufptr = NULL;
			if (++mg_skt->txq_s == MG_TXQ_ENTRY_MAX) {
				/* wrap */
				mg_skt->txq_s = 0;
			}
		}
		else {
			/* not all the data was sent, save the rest */
			txq->bufptr = bufptr;
			txq->buflen = buflen;
			break;
		}
	}
	return 0;
}

static int mg_enqueue(mg_skt_t *mg_skt, unsigned char *bufptr, int buflen)
{
	int qe = mg_skt->txq_e;
	int qe_next = qe + 1;
	txq_entry_t *txq = &mg_skt->txq[qe];
	if (qe_next == MG_TXQ_ENTRY_MAX) {
		qe_next = 0;
	}
	if (qe_next == mg_skt->txq_s) {
		MG_LOG_DBG("mg_enqueue[%d]: queue is full\n", mg_skt->fd);
		return -1;	// full
	}
	if ((txq->buf = malloc(buflen))) {
		memcpy(txq->buf, bufptr, buflen);
		txq->bufptr = txq->buf;
		txq->buflen = buflen;
		mg_skt->txq_e = qe_next;
		return 0;
	}
	assert(0);
	return -1;
}

int mg_skt_tx(void *handle, unsigned char *bufptr, int buflen)
{
	mg_skt_t *mg_skt = (mg_skt_t*)handle;
	MG_LOG_DBG("mg_skt_tx[%d]: sending %d bytes\n", mg_skt->fd, buflen);
	if (mg_skt->txq_s == mg_skt->txq_e) {
		/* currently nothing enqueued, send it straight out */
		mg_skt_write(mg_skt, &bufptr, &buflen);
	}
	if (buflen) {
		/* queue remaining data */
		MG_LOG_DBG("mg_skt_tx[%d]: enqueued %d bytes\n", mg_skt->fd, buflen);
		return mg_enqueue(mg_skt, bufptr, buflen);
	}
	return 0;
}

static void mg_skt_rx(mg_fd_list_entry_t *le)
{
	struct sockaddr_storage addr;
	socklen_t slen = sizeof(addr);
	unsigned char rx_buf[MG_RX_BUF_SIZE];
	int l = recvfrom(le->mg_skt->fd, rx_buf, sizeof(rx_buf),
	                 0, (struct sockaddr*)&addr, &slen);
	mg_skt_param_t *p = &le->mg_skt->params.skt;
	MG_LOG_DBG("mg_skt_rx[%d]: receiving %d bytes\n", le->mg_skt->fd, l);
	switch (l) {
	case -1:
		MG_LOG_ERR("mg_skt_rx: read failed <%s>\n", strerror(errno));
	/* drop through */
	case 0:
		/*  connection is closed */
		if (p->close) {
			p->close(p->handle);
		}
		mg_skt_close(le->mg_skt);
		le->mg_skt = NULL;
		break;
	default:
		p->rx(p->handle, (void*)&addr, rx_buf, l);
		break;
	}
}

static void mg_read(mg_fd_list_entry_t *le)
{
	unsigned char rx_buf[MG_RX_BUF_SIZE];
	int l = read(le->mg_skt->fd, rx_buf, sizeof(rx_buf) - 1);
	if (l < 0) {
		MG_LOG_ERR("mg_skt_rx[%d]: read failed <%s>\n", le->mg_skt->fd, strerror(errno));
	}
	else {
		mg_skt_param_t *p = &le->mg_skt->params.skt;
		if (l > 0) {
			rx_buf[l] = 0;
			p->rx(p->handle, NULL, rx_buf, l);
		}
	}
}

void *mg_skt_open(mg_skt_param_t *p)
{
	mg_skt_t *mg_skt = calloc(1, sizeof(mg_skt_t));
	int r, on = 1;
	assert(mg_skt);
	mg_skt->rx = mg_skt_rx;
	if ((mg_skt->fd = socket(p->family, p->type | SOCK_NONBLOCK, p->protocol)) < 0) {
		MG_LOG_ERR("mg_skt_open: socket failed <%s>\n", strerror(errno));
		assert(0);
	};
	MG_LOG_DBG("mg_skt_open: opening socket %d\n", mg_skt->fd);
	r = setsockopt(mg_skt->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	assert(r == 0);
	if (p->tx_buf_size) {
		r = setsockopt(mg_skt->fd, SOL_SOCKET, SO_SNDBUFFORCE,
		               &p->tx_buf_size, sizeof(p->tx_buf_size));
		assert(r == 0);
	}
	if (p->rx_buf_size) {
		r = setsockopt(mg_skt->fd, SOL_SOCKET, SO_RCVBUFFORCE,
		               &p->rx_buf_size, sizeof(p->rx_buf_size));
		assert(r == 0);
	}
	if (p->sock_addr && bind(mg_skt->fd, p->sock_addr, p->slen) < 0) {
		MG_LOG_ERR("mg_skt_open: bind failed <%s>\n", strerror(errno));
		assert(0);
	}
	mg_skt->params.skt = *p;
	mg_fd_add(mg_skt->fd, (void*)mg_skt);
	if (p->connect_addr &&
		connect(mg_skt->fd, p->connect_addr, p->connect_addr_len) < 0) {
		switch (errno) {
		case EAGAIN:
		case EINPROGRESS:
			/* connection setup in progress */
			mg_skt->tx_watch = 1;
			break;
		default:
			MG_LOG_ERR("mg_skt_open[%d]: connect failed <%s>\n",
					   mg_skt->fd, strerror(errno));
			assert(0);
			break;
		}
	}
	return (void*)mg_skt;
}

void mg_skt_close(void *handle)
{
	mg_skt_t *mg_skt = (mg_skt_t*)handle;
	mg_fd_del(mg_skt->fd);
	close(mg_skt->fd);
	free(mg_skt);
}

int mg_skt_fd(void *handle)
{
	mg_skt_t *mg_skt = handle;
	return mg_skt->fd;
}

static void *mg_fd_open(int fd, mg_skt_param_t *p)
{
	mg_skt_t *mg_fd = calloc(1, sizeof(mg_skt_t));
	int r, on = 1;
	assert(mg_fd);
	mg_fd->fd = fd;
	assert(mg_fd->fd >= 0);
	mg_fd->params.skt.rx = p->rx;
	mg_fd->params.skt.close = p->close;
	mg_fd->params.skt.handle = p->handle;
	if (p->sock_addr) {
		mg_fd->rx = mg_skt_rx;
		r = setsockopt(mg_fd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		assert(r == 0);
		if (p->tx_buf_size) {
			r = setsockopt(mg_fd->fd, SOL_SOCKET, SO_SNDBUFFORCE,
			               &p->tx_buf_size, sizeof(p->tx_buf_size));
			assert(r == 0);
		}
		if (p->rx_buf_size) {
			r = setsockopt(mg_fd->fd, SOL_SOCKET, SO_RCVBUFFORCE,
			               &p->rx_buf_size, sizeof(p->rx_buf_size));
			assert(r == 0);
		}
	}
	else {
		mg_fd->rx = mg_read;
	}
	mg_fd_add(mg_fd->fd, (void*)mg_fd);
	return (void*)mg_fd;
}

static void mg_accept(mg_fd_list_entry_t *le)
{
	struct sockaddr_storage addr_;
	struct sockaddr *addr = (struct sockaddr*)&addr_;
	socklen_t addr_len = sizeof(struct sockaddr_storage);
	int fd = accept(le->mg_skt->fd, addr, &addr_len);
	if (fd < 0) {
		MG_LOG_ERR("mg_accept[%d]: accept failed <%s>\n",
				   le->mg_skt->fd, strerror(errno));
		assert(0);
	}
	else {
		mg_listen_param_t *lp = &le->mg_skt->params.listen;
		mg_skt_param_t p = {
			.sock_addr = addr,
		};
		void **client_handle;
		if ((client_handle = lp->accept(lp->handle, &p, addr))) {
			*client_handle = mg_fd_open(fd, &p);
		}
	}
}

void *mg_listen_open(mg_listen_param_t *p)
{
	mg_skt_t *mg_skt = calloc(1, sizeof(mg_skt_t));
	int r, on = 1;
	assert(mg_skt);
	assert(p->accept);
	mg_skt->rx = mg_accept;
	mg_skt->fd = socket(p->family, p->type, p->protocol);
	assert(mg_skt->fd >= 0);
	r = setsockopt(mg_skt->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	assert(r == 0);
	if (bind(mg_skt->fd, p->sock_addr, p->slen) < 0) {
		MG_LOG_ERR("mg_listen_open: bind failed <%s>\n", strerror(errno));
		assert(0);
	}
	mg_skt->params.listen = *p;
	mg_fd_add(mg_skt->fd, (void*)mg_skt);
	MG_LOG_DBG("mg_listen_open: opening socket %d\n", mg_skt->fd);
	r = listen(mg_skt->fd, 10);	// 10 is an arbitrary queue length
	assert(r == 0);
	return (void*)mg_skt;
}

void mg_listen_close(void *handle)
{
	mg_skt_t *mg_skt = (mg_skt_t*)handle;
	mg_fd_del(mg_skt->fd);
	close(mg_skt->fd);
	free(mg_skt);
}

void *mg_timer_add(void *handle, void (*callback)(void*))
{
	mg_timer_cb_t *t = (mg_timer_cb_t*)calloc(1, sizeof(mg_timer_cb_t));
	assert(t);
	t->next = mg.timer_cb_first;
	mg.timer_cb_first = t;
	t->callback = callback;
	t->handle = handle;
	return (void*)t;
}

static int mg_fd_set(fd_set *rx_fds, fd_set *tx_fds)
{
	int i;
	int max_fd = 0;
	mg_fd_list_entry_t *le;
	FD_ZERO(rx_fds);
	FD_ZERO(tx_fds);
	for (i = 0, le = mg.fd_list; i < mg.fd_list_count; i++, le++) {
		assert(le->deleting == 0);
		FD_SET(le->fd, rx_fds);
		if (le->mg_skt->tx_watch) {
			FD_SET(le->fd, tx_fds);
			fcntl(le->fd, F_SETFL, (fcntl(le->fd, F_GETFL) | O_NONBLOCK));
		}
		if (le->fd > max_fd) {
			max_fd = le->fd;
		}
	}
	return max_fd;
}

static int mg_fd_isset(fd_set *rx_fds, fd_set *tx_fds)
{
	int i, j;
	mg_fd_list_entry_t *le;
	mg.fd_isset_in_progress = 1;
	for (i = 0, le = mg.fd_list; i < mg.fd_list_count; i++, le++) {
		if (le->deleting) {
			continue;
		}
		if (FD_ISSET(le->fd, tx_fds)) {
			mg_dequeue(le->mg_skt);
			FD_CLR(le->fd, tx_fds);
			le->mg_skt->tx_watch = 0;
		}
		if (FD_ISSET(le->fd, rx_fds)) {
			assert(le->mg_skt->rx);
			le->mg_skt->rx(le);
			FD_CLR(le->fd, rx_fds);
		}
	}
	mg.fd_isset_in_progress = 0;
	/* clean up deleted fds */
	for (i = j = 0, le = mg.fd_list; i < mg.fd_list_count; i++, le++) {
		if (i > j) {
			mg.fd_list[j] = mg.fd_list[i];
		}
		if (le->deleting == 0) {
			j++;
		}
	}
	mg.fd_list_count -= (i - j);
	return 0;
}

int mg_dispatch(mg_param_t *p)
{
	int err = 0;
	if (p && p->console.rx) {
		/* std_in support requested */
		mg_skt_param_t pc = {
			.handle = p->console.handle,
			.rx = p->console.rx
		};
		mg.console_handle = mg_fd_open(fileno(stdin), &pc);
	}
	while (!err) {
		fd_set rx_fds, tx_fds;
		int max_fd = mg_fd_set(&rx_fds, &tx_fds);
		int n = select(max_fd + 1, &rx_fds, &tx_fds, NULL, &mg.timeout);
		if (n < 0) {
			if (errno == EINTR) {
				MG_LOG_DBG("mg_poll: signal interrupt...resuming\n");
			}
			else {
				MG_LOG_ERR("mg_poll: select err %s\n", strerror(errno));
				err = errno;
				assert(0);
			}
		}
		else if (n > 0) {
			mg_fd_isset(&rx_fds, &tx_fds);
		}
		else {
			mg_timer_cb_t *t;
			for (t = mg.timer_cb_first; t; t = t->next) {
				t->callback(t->handle);
			}
			mg.timeout.tv_sec = 1;
		}
	}
	return err;
}
