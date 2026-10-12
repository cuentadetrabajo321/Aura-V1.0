/*
 ============================================================================
 Name        : hev-socks5-session-tcp.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2023 hev
 Description : Socks5 Session TCP
 ============================================================================
 */

#include <errno.h>
#ifdef __ANDROID__
#include <stdlib.h>
#endif
#include <string.h>

#include <lwip/tcp.h>
#include <lwip/ip_addr.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-task-mutex.h>
#include <hev-memory-allocator.h>
#include <hev-socks5-misc.h>

#include "hev-utils.h"
#include "hev-config.h"
#include "hev-logger.h"
#include "hev-config-const.h"
#include "hev-socks5-tunnel.h"

#include "hev-socks5-session-tcp.h"
#ifdef __ANDROID__
#include "aura_sni_firewall.h"

#define AURA_TLS_INSPECTION_LIMIT (65535U + 5U * 5U)

extern void hev_jni_report_dns_event (const char *domain, int action,
                                      uint32_t source_ipv4,
                                      uint16_t source_port);
extern void hev_jni_report_sni_event (const char *domain,
                                      const char *destination_address,
                                      uint16_t destination_port);

static void
report_blocked_sni (HevSocks5SessionTCP *self, const char *sni)
{
    if (sni && sni[0] && self->pcb) {
        const uint32_t source_ipv4 =
            self->pcb->remote_ip.type == IPADDR_TYPE_V4
                ? ip_2_ip4 (&self->pcb->remote_ip)->addr
                : 0;
        hev_jni_report_dns_event (sni, 3, source_ipv4,
                                  self->pcb->remote_port);
    }
}

static void
report_observed_sni (HevSocks5SessionTCP *self, const char *sni)
{
    char destination_address[IP6ADDR_STRLEN_MAX] = { 0 };

    if (!sni || !sni[0] || !self->pcb)
        return;
    if (!ipaddr_ntoa_r (&self->pcb->local_ip, destination_address,
                        sizeof (destination_address)))
        return;
    hev_jni_report_sni_event (sni, destination_address,
                              self->pcb->local_port);
}

static int
tls_inspection_append (HevSocks5SessionTCP *self, const struct pbuf *p)
{
    size_t required;
    size_t capacity;
    uint8_t *buffer;
    AuraTlsSniResult result;
    char sni[254] = { 0 };

    if (p->tot_len > AURA_TLS_INSPECTION_LIMIT - self->tls_inspection_length)
        return -1;
    required = self->tls_inspection_length + p->tot_len;
    if (required > self->tls_inspection_capacity) {
        capacity = self->tls_inspection_capacity
                       ? self->tls_inspection_capacity
                       : 1024;
        while (capacity < required && capacity < AURA_TLS_INSPECTION_LIMIT)
            capacity *= 2;
        if (capacity > AURA_TLS_INSPECTION_LIMIT)
            capacity = AURA_TLS_INSPECTION_LIMIT;
        buffer = realloc (self->tls_inspection_buffer, capacity);
        if (!buffer)
            return -1;
        self->tls_inspection_buffer = buffer;
        self->tls_inspection_capacity = capacity;
    }
    if (pbuf_copy_partial (p,
                           self->tls_inspection_buffer +
                               self->tls_inspection_length,
                           p->tot_len, 0) != p->tot_len)
        return -1;
    self->tls_inspection_length = required;

    result = aura_inspect_tls_sni (self->tls_inspection_buffer,
                                   (uint32_t)self->tls_inspection_length,
                                   sni, sizeof (sni));
    if (result == AURA_TLS_SNI_INCOMPLETE) {
        if (self->tls_inspection_length == AURA_TLS_INSPECTION_LIMIT)
            return -1;
        return 0;
    }
    if (result == AURA_TLS_SNI_BLOCKED ||
        result == AURA_TLS_SNI_MALFORMED) {
        report_blocked_sni (self, sni);
        return -1;
    }

    report_observed_sni (self, sni);
    self->tls_inspection_complete = 1;
    return 1;
}

static void
abort_tcp_session (HevSocks5SessionTCP *self)
{
    struct tcp_pcb *pcb = self->pcb;

    if (self->queue) {
        pbuf_free (self->queue);
        self->queue = NULL;
    }
    free (self->tls_inspection_buffer);
    self->tls_inspection_buffer = NULL;
    self->tls_inspection_length = 0;
    self->tls_inspection_capacity = 0;
    self->pcb = NULL;

    if (pcb) {
        tcp_arg (pcb, NULL);
        tcp_recv (pcb, NULL);
        tcp_sent (pcb, NULL);
        tcp_err (pcb, NULL);
        tcp_abort (pcb);
    }
}
#endif

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    HevSocks5Session *self = data;
    HevListNode *node;
    int res;

    res = hev_socks5_task_io_yielder (type, data);
    node = hev_socks5_session_get_node (self);
    hev_socks5_tunnel_update_session (node);

    return res;
}

static int
tcp_splice_f (HevSocks5SessionTCP *self)
{
    struct iovec iov[64];
    struct pbuf *p;
    int iovc = 0;
    int res = 1;

#ifdef __ANDROID__
    if (self->tls_inspection_required &&
        !self->tls_inspection_complete)
        return 0;

    if (self->tls_inspection_required &&
        !self->tls_sni_checked_before_forwarding) {
        if (aura_should_block_tls_sni (self->tls_inspection_buffer,
                                       (uint32_t)self->tls_inspection_length)) {
            char sni[254] = { 0 };
            const AuraTlsSniResult result =
                aura_inspect_tls_sni (self->tls_inspection_buffer,
                                      (uint32_t)self->tls_inspection_length,
                                      sni, sizeof (sni));
            report_blocked_sni (self, result == AURA_TLS_SNI_BLOCKED
                                          ? sni
                                          : NULL);
            LOG_W ("%p tcp SNI firewall blocked the connection", self);
            hev_task_mutex_lock (self->mutex);
            abort_tcp_session (self);
            hev_task_mutex_unlock (self->mutex);
            return -1;
        }
        self->tls_sni_checked_before_forwarding = 1;
        free (self->tls_inspection_buffer);
        self->tls_inspection_buffer = NULL;
        self->tls_inspection_length = 0;
        self->tls_inspection_capacity = 0;
    }
#endif

    if (self->queue) {
        for (p = self->queue; p && (iovc < 64); p = p->next, iovc++) {
            iov[iovc].iov_base = p->payload;
            iov[iovc].iov_len = p->len;
        }
    } else if (self->pcb_eof) {
        res = -1;
    } else {
        res = 0;
    }

    if (iovc) {
        ssize_t s = writev (HEV_SOCKS5 (self)->fd, iov, iovc);
        if (0 >= s) {
            if ((0 > s) && (EAGAIN == errno))
                res = 0;
            else
                res = -1;
        } else {
            hev_task_mutex_lock (self->mutex);
            self->queue = pbuf_free_header (self->queue, s);
            if (self->pcb) {
#ifdef __ANDROID__
                size_t newly_received = (size_t)s;
                if (self->tls_preacknowledged) {
                    const size_t already_received =
                        self->tls_preacknowledged < newly_received
                            ? self->tls_preacknowledged
                            : newly_received;
                    self->tls_preacknowledged -= already_received;
                    newly_received -= already_received;
                }
                if (newly_received)
                    tcp_recved (self->pcb, newly_received);
#else
                tcp_recved (self->pcb, s);
#endif
            }
            hev_task_mutex_unlock (self->mutex);
            res = 1;
        }
    } else if (res < 0) {
        shutdown (HEV_SOCKS5 (self)->fd, SHUT_WR);
    }

    return res;
}

static int
tcp_splice_b (HevSocks5SessionTCP *self)
{
    struct iovec iov[2];
    err_t err = ERR_OK;
    int res = 1, iovc;

    iovc = hev_ring_buffer_writing (self->buffer, iov);
    if (iovc) {
        ssize_t s = readv (HEV_SOCKS5 (self)->fd, iov, iovc);
        if (0 >= s) {
            if ((0 > s) && (EAGAIN == errno))
                res = 0;
            else
                res = -1;
        } else {
            hev_ring_buffer_write_finish (self->buffer, s);
        }
    } else {
        res = 0;
    }

    hev_task_mutex_lock (self->mutex);
    if (self->pcb) {
        iovc = hev_ring_buffer_reading (self->buffer, iov);
        if (iovc) {
            ssize_t s = 0;
            int i;
            for (i = 0; i < iovc; i++) {
                void *ptr = iov[i].iov_base;
                size_t len = iov[i].iov_len;
                err |= tcp_write (self->pcb, ptr, len, 0);
                s += len;
            }
            hev_ring_buffer_read_finish (self->buffer, s);
            err |= tcp_output (self->pcb);
            res = 1;
        } else if (res < 0) {
            tcp_shutdown (self->pcb, 0, 1);
        }
    }
    hev_task_mutex_unlock (self->mutex);
    if (!self->pcb || (err != ERR_OK))
        res = -1;

    return res;
}

static err_t
tcp_recv_handler (void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    HevSocks5SessionTCP *self = arg;

    if (p) {
#ifdef __ANDROID__
        if (self->tls_inspection_required &&
            !self->tls_inspection_complete) {
            if (tls_inspection_append (self, p) < 0) {
                LOG_W ("%p tcp SNI inspection rejected the connection", self);
                pbuf_free (p);
                abort_tcp_session (self);
                hev_task_wakeup (self->data.task);
                return ERR_ABRT;
            }
            tcp_recved (pcb, p->tot_len);
            self->tls_preacknowledged += p->tot_len;
        }
#endif
        if (self->queue)
            pbuf_cat (self->queue, p);
        else
            self->queue = p;
    } else {
        self->pcb_eof = 1;
#ifdef __ANDROID__
        self->tls_inspection_complete = 1;
#endif
    }

    hev_task_wakeup (self->data.task);
    return ERR_OK;
}

static err_t
tcp_sent_handler (void *arg, struct tcp_pcb *pcb, u16_t len)
{
    HevSocks5SessionTCP *self = arg;

    hev_ring_buffer_read_release (self->buffer, len);
    hev_task_wakeup (self->data.task);

    return ERR_OK;
}

static void
tcp_err_handler (void *arg, err_t err)
{
    HevSocks5SessionTCP *self = arg;

    self->pcb = NULL;
    hev_socks5_session_terminate (HEV_SOCKS5_SESSION (self));
}

HevSocks5SessionTCP *
hev_socks5_session_tcp_new (struct tcp_pcb *pcb, HevTaskMutex *mutex)
{
    HevSocks5SessionTCP *self;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5SessionTCP));
    if (!self)
        return NULL;

    res = hev_socks5_session_tcp_construct (self, pcb, mutex);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 session tcp new", self);

    return self;
}

static void
hev_socks5_session_tcp_splice (HevSocks5Session *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);
    int tcp_buffer_size;
    int res_f = 1;
    int res_b = 1;

    LOG_D ("%p socks5 session tcp splice", self);

    if (!self->pcb)
        return;

    tcp_buffer_size = hev_config_get_misc_tcp_buffer_size ();
    self->buffer = hev_ring_buffer_alloca (tcp_buffer_size);
    if (!self->buffer)
        return;

    for (;;) {
        HevTaskYieldType type;

        if (res_f >= 0)
            res_f = tcp_splice_f (self);
        if (res_b >= 0)
            res_b = tcp_splice_b (self);

        if (res_f > 0 || res_b > 0)
            type = HEV_TASK_YIELD;
        else if ((res_f & res_b) == 0)
            type = HEV_TASK_WAITIO;
        else
            break;

        if (task_io_yielder (type, base) < 0)
            break;
    }

    while (self->pcb) {
        if (hev_ring_buffer_get_use_size (self->buffer) == 0)
            break;

        if (task_io_yielder (HEV_TASK_WAITIO, base) < 0)
            break;
    }
}

static HevTask *
hev_socks5_session_tcp_get_task (HevSocks5Session *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    return self->data.task;
}

static void
hev_socks5_session_tcp_set_task (HevSocks5Session *base, HevTask *task)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    self->data.task = task;
}

static HevListNode *
hev_socks5_session_tcp_get_node (HevSocks5Session *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    return &self->data.node;
}

int
hev_socks5_session_tcp_construct (HevSocks5SessionTCP *self,
                                  struct tcp_pcb *pcb, HevTaskMutex *mutex)
{
    HevSocks5Addr addr;
    int res;

    res = hev_socks5_addr_from_lwip (&addr, &pcb->local_ip, pcb->local_port);
    if (res < 0)
        return -1;

    res = hev_socks5_client_tcp_construct (&self->base, &addr);
    if (res < 0)
        return -1;

    LOG_D ("%p socks5 session tcp construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_SESSION_TCP_TYPE;

    tcp_arg (pcb, self);
    tcp_recv (pcb, tcp_recv_handler);
    tcp_sent (pcb, tcp_sent_handler);
    tcp_err (pcb, tcp_err_handler);

    self->pcb = pcb;
    self->mutex = mutex;
    self->data.self = self;
#ifdef __ANDROID__
    self->tls_inspection_required =
        pcb->local_port == 443 || pcb->local_port == 853;
    self->tls_inspection_complete = !self->tls_inspection_required;
#endif

    return 0;
}

void
hev_socks5_session_tcp_destruct (HevObject *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    LOG_D ("%p socks5 session tcp destruct", self);

    hev_task_mutex_lock (self->mutex);
    if (self->pcb) {
        tcp_recv (self->pcb, NULL);
        tcp_sent (self->pcb, NULL);
        tcp_err (self->pcb, NULL);
        tcp_abort (self->pcb);
    }

    if (self->queue)
        pbuf_free (self->queue);
#ifdef __ANDROID__
    free (self->tls_inspection_buffer);
#endif
    hev_task_mutex_unlock (self->mutex);

    HEV_SOCKS5_CLIENT_TCP_TYPE->destruct (base);
}

static void *
hev_socks5_session_tcp_iface (HevObject *base, void *type)
{
    if (type == HEV_SOCKS5_SESSION_TYPE) {
        HevSocks5SessionTCPClass *klass = HEV_OBJECT_GET_CLASS (base);
        return &klass->session;
    }

    return HEV_SOCKS5_CLIENT_TCP_TYPE->iface (base, type);
}

HevObjectClass *
hev_socks5_session_tcp_class (void)
{
    static HevSocks5SessionTCPClass klass;
    HevSocks5SessionTCPClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        HevSocks5Class *skptr;
        HevSocks5SessionIface *siptr;
        void *ptr;

        ptr = HEV_SOCKS5_CLIENT_TCP_TYPE;
        memcpy (kptr, ptr, sizeof (HevSocks5ClientTCPClass));

        okptr->name = "HevSocks5SessionTCP";
        okptr->destruct = hev_socks5_session_tcp_destruct;
        okptr->iface = hev_socks5_session_tcp_iface;

        skptr = HEV_SOCKS5_CLASS (kptr);
        skptr->binder = hev_socks5_session_bind;

        siptr = &kptr->session;
        siptr->splicer = hev_socks5_session_tcp_splice;
        siptr->get_task = hev_socks5_session_tcp_get_task;
        siptr->set_task = hev_socks5_session_tcp_set_task;
        siptr->get_node = hev_socks5_session_tcp_get_node;
    }

    return okptr;
}
