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

 */

#ifndef __MG_SKT_H__
#define __MG_SKT_H__

typedef struct {
	void *handle;
	void (*rx)(void*, struct sockaddr *, unsigned char*, int);
	void (*close)(void*);
	int family;
	int type;
	int protocol;
	struct sockaddr *sock_addr;
	socklen_t slen;
	struct sockaddr *connect_addr;
	socklen_t connect_addr_len;
	uint32_t tx_buf_size;
	uint32_t rx_buf_size;
} mg_skt_param_t;

typedef struct {
	void *handle;
	void **(*accept)(void*, mg_skt_param_t*, struct sockaddr *accept_addr);
	int family;
	int type;
	int protocol;
	struct sockaddr *sock_addr;
	socklen_t slen;
} mg_listen_param_t;

typedef struct {
	struct {
		void (*rx)(void*, struct sockaddr *, unsigned char*, int);
		void *handle;
	} console;
} mg_param_t;

int mg_dispatch(mg_param_t*);
void *mg_skt_open(mg_skt_param_t *p);
void mg_skt_close(void*);
void *mg_listen_open(mg_listen_param_t *p);
void mg_listen_close(void*);
int mg_skt_tx(void *handle, unsigned char *buf, int len);
int mg_skt_fd(void *handle);
void *mg_timer_add(void *handle, void (*callback)(void*));

#endif // __MG_SKT_H__
