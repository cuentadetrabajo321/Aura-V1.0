/*
 ============================================================================
 Name        : hev-socks5-tunnel.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2025 hev
 Description : Socks5 Tunnel
 ============================================================================
 */

#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <lwip/nd6.h>
#include <lwip/netif.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>
#include <lwip/priv/tcp_priv.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-mutex.h>
#include <hev-task-system.h>
#include <hev-memory-allocator.h>

#include "hev-exec.h"
#include "hev-config.h"
#include "hev-logger.h"
#include "hev-tunnel.h"
#include "hev-compiler.h"
#include "hev-mapped-dns.h"
#include "hev-config-const.h"
#include "hev-socks5-session-tcp.h"
#include "hev-socks5-session-udp.h"

#include "hev-socks5-tunnel.h"

#ifdef __ANDROID__
extern void hev_jni_report_dns_event (const char *domain, int action,
                                      uint32_t source_ipv4,
                                      uint16_t source_port);
extern void hev_jni_report_encrypted_dns_event (
    const char *destination_address, uint16_t destination_port,
    const char *transport_protocol);
#endif

enum
{
    SYNC_SEND = 1 << 0,
    SYNC_SENT = 1 << 1,
    SYNC_WAIT = 1 << 2,
    SYNC_STOP = 1 << 3,
};

static int run;
static atomic_int tsync;

static int tun_fd = -1;
static int tun_fd_local;
static int session_count;
static int event_fds[2] = { -1, -1 };

static atomic_size_t stat_tx_packets;
static atomic_size_t stat_rx_packets;
static atomic_size_t stat_tx_bytes;
static atomic_size_t stat_rx_bytes;

static struct netif *netif;

#define MAX_BLOCKED_IPV4 8192
#define MAX_BLOCKED_IPV6 8192
static uint32_t blocked_ipv4[MAX_BLOCKED_IPV4];
static size_t blocked_ipv4_count;
static uint8_t blocked_ipv6[MAX_BLOCKED_IPV6][16];
static size_t blocked_ipv6_count;
static pthread_mutex_t blocked_ipv4_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct tcp_pcb *tcp;
static struct udp_pcb *udp;

static HevTaskMutex mutex;
static HevTask *task_event;
static HevTask *task_lwip_io;
static HevTask *task_lwip_timer;
static HevList session_set;

static int
compare_ipv4 (const void *left, const void *right)
{
    const uint32_t a = *(const uint32_t *)left;
    const uint32_t b = *(const uint32_t *)right;

    return (a > b) - (a < b);
}

static int
compare_ipv6 (const void *left, const void *right)
{
    return memcmp (left, right, 16);
}

void
hev_socks5_tunnel_set_blocked_ipv4 (const uint32_t *addresses, size_t count)
{
    if (count > MAX_BLOCKED_IPV4)
        count = MAX_BLOCKED_IPV4;

    pthread_mutex_lock (&blocked_ipv4_mutex);
    if (addresses && count) {
        memcpy (blocked_ipv4, addresses, count * sizeof (uint32_t));
        qsort (blocked_ipv4, count, sizeof (uint32_t), compare_ipv4);
    }
    blocked_ipv4_count = addresses ? count : 0;
    pthread_mutex_unlock (&blocked_ipv4_mutex);
}

void
hev_socks5_tunnel_set_blocked_ipv6 (const uint8_t (*addresses)[16],
                                    size_t count)
{
    if (count > MAX_BLOCKED_IPV6)
        count = MAX_BLOCKED_IPV6;

    pthread_mutex_lock (&blocked_ipv4_mutex);
    if (addresses && count) {
        memcpy (blocked_ipv6, addresses, count * sizeof (blocked_ipv6[0]));
        qsort (blocked_ipv6, count, sizeof (blocked_ipv6[0]),
               compare_ipv6);
    }
    blocked_ipv6_count = addresses ? count : 0;
    pthread_mutex_unlock (&blocked_ipv4_mutex);
}

int
hev_socks5_tunnel_block_domain (const char *domain)
{
    if (!READ_ONCE (run))
        return 0;
    return hev_mapped_dns_block_domain (domain);
}

static int
packet_ipv4_is_blocked (const struct pbuf *packet)
{
    uint8_t header[20];
    uint32_t destination;
    size_t low, high;
    int blocked = 0;

    if (packet->tot_len < sizeof (header) ||
        pbuf_copy_partial (packet, header, sizeof (header), 0) != sizeof (header) ||
        (header[0] >> 4) != 4 || (header[0] & 0x0F) < 5)
        return 0;

    memcpy (&destination, header + 16, sizeof (destination));
    pthread_mutex_lock (&blocked_ipv4_mutex);
    low = 0;
    high = blocked_ipv4_count;
    while (low < high) {
        const size_t middle = low + ((high - low) / 2);
        if (blocked_ipv4[middle] < destination) {
            low = middle + 1;
        } else if (blocked_ipv4[middle] > destination) {
            high = middle;
        } else {
            blocked = 1;
            break;
        }
    }
    pthread_mutex_unlock (&blocked_ipv4_mutex);

    return blocked;
}

static int
packet_ipv6_is_blocked (const struct pbuf *packet)
{
    uint8_t header[40];
    size_t low, high;
    int blocked = 0;

    if (packet->tot_len < sizeof (header) ||
        pbuf_copy_partial (packet, header, sizeof (header), 0) != sizeof (header) ||
        (header[0] >> 4) != 6)
        return 0;

    pthread_mutex_lock (&blocked_ipv4_mutex);
    low = 0;
    high = blocked_ipv6_count;
    while (low < high) {
        const size_t middle = low + ((high - low) / 2);
        const int comparison = memcmp (blocked_ipv6[middle], header + 24, 16);
        if (comparison < 0) {
            low = middle + 1;
        } else if (comparison > 0) {
            high = middle;
        } else {
            blocked = 1;
            break;
        }
    }
    pthread_mutex_unlock (&blocked_ipv4_mutex);

    return blocked;
}

static int
is_ipv4_doh_resolver (const uint8_t *address)
{
    static const uint8_t resolvers[][4] = {
        { 1, 1, 1, 1 }, { 1, 0, 0, 1 }, { 8, 8, 8, 8 },
        { 8, 8, 4, 4 }, { 9, 9, 9, 9 }, { 149, 112, 112, 112 },
        { 208, 67, 222, 222 }, { 208, 67, 220, 220 },
        { 94, 140, 14, 14 }, { 94, 140, 15, 15 },
    };
    size_t i;

    for (i = 0; i < sizeof (resolvers) / sizeof (resolvers[0]); i++) {
        if (memcmp (address, resolvers[i], sizeof (resolvers[i])) == 0)
            return 1;
    }
    return 0;
}

static int
is_ipv6_doh_resolver (const uint8_t *address)
{
    static const uint8_t resolvers[][16] = {
        { 0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0,
          0, 0, 0, 0, 0, 0, 0x11, 0x11 },
        { 0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0,
          0, 0, 0, 0, 0, 0, 0x10, 0x01 },
        { 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0,
          0, 0, 0, 0, 0, 0, 0x88, 0x88 },
        { 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0,
          0, 0, 0, 0, 0, 0, 0x88, 0x44 },
        { 0x26, 0x20, 0x00, 0xfe, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0xfe },
        { 0x26, 0x20, 0x00, 0xfe, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0x09 },
        { 0x26, 0x20, 0x01, 0x19, 0, 0x35, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0x35 },
        { 0x26, 0x20, 0x01, 0x19, 0, 0x35, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0x53 },
    };
    size_t i;

    for (i = 0; i < sizeof (resolvers) / sizeof (resolvers[0]); i++) {
        if (memcmp (address, resolvers[i], sizeof (resolvers[i])) == 0)
            return 1;
    }
    return 0;
}

static int
packet_is_encrypted_dns (const struct pbuf *packet, char *destination_address,
                         size_t address_capacity, uint16_t *port,
                         const char **transport_protocol)
{
    uint8_t header[60];
    uint8_t transport[4];
    uint8_t version;
    uint8_t protocol;
    uint16_t destination_port;
    size_t ip_header_length;
    int resolver_match = 0;
    int address_family;
    const uint8_t *destination;

    if (packet->tot_len < 1 ||
        pbuf_copy_partial (packet, header, 1, 0) != 1)
        return 0;

    version = header[0] >> 4;
    if (version == 4) {
        uint16_t fragment;

        if (packet->tot_len < 20 ||
            pbuf_copy_partial (packet, header, 20, 0) != 20 ||
            (header[0] & 0x0F) < 5)
            return 0;
        ip_header_length = (size_t)(header[0] & 0x0F) * 4;
        if (packet->tot_len < ip_header_length + sizeof (transport) ||
            pbuf_copy_partial (packet, header, ip_header_length, 0) !=
                ip_header_length)
            return 0;
        protocol = header[9];
        destination = header + 16;
        address_family = AF_INET;
        resolver_match = is_ipv4_doh_resolver (destination);
        fragment = ((uint16_t)header[6] << 8) | header[7];
        if ((fragment & 0x1FFF) != 0)
            return 0;
    } else if (version == 6) {
        size_t offset = 40;
        unsigned int extensions = 0;

        if (packet->tot_len < 40 ||
            pbuf_copy_partial (packet, header, 40, 0) != 40)
            return 0;
        destination = header + 24;
        address_family = AF_INET6;
        resolver_match = is_ipv6_doh_resolver (destination);
        protocol = header[6];
        while (protocol == 0 || protocol == 43 || protocol == 44 ||
               protocol == 51 || protocol == 60) {
            uint8_t extension[8];
            size_t extension_length;

            if (++extensions > 8 || offset + sizeof (extension) > packet->tot_len ||
                pbuf_copy_partial (packet, extension, sizeof (extension), offset) !=
                    sizeof (extension))
                return 0;
            if (protocol == 44) {
                const uint16_t fragment =
                    ((uint16_t)extension[2] << 8) | extension[3];
                if ((fragment & 0xFFF8) != 0)
                    return 0;
                extension_length = 8;
            } else if (protocol == 51) {
                extension_length = ((size_t)extension[1] + 2) * 4;
            } else {
                extension_length = ((size_t)extension[1] + 1) * 8;
            }
            protocol = extension[0];
            offset += extension_length;
            if (offset > packet->tot_len || offset > 296)
                return 0;
        }
        ip_header_length = offset;
        if (packet->tot_len < ip_header_length + sizeof (transport))
            return 0;
    } else {
        return 0;
    }

    if (protocol != 6 && protocol != 17)
        return 0;
    if (pbuf_copy_partial (packet, transport, sizeof (transport),
                           ip_header_length) != sizeof (transport))
        return 0;
    destination_port = ((uint16_t)transport[2] << 8) | transport[3];
    if (protocol != 17 ||
        (destination_port != 853 &&
         !(destination_port == 443 && resolver_match)))
        return 0;
    if (!inet_ntop (address_family, destination, destination_address,
                    (socklen_t)address_capacity))
        return 0;
    *port = destination_port;
    *transport_protocol = "UDP";
    return 1;
}

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    hev_task_yield (type);

    return READ_ONCE (run) ? 0 : -1;
}

static err_t
netif_output_handler (struct netif *netif, struct pbuf *p)
{
    ssize_t s;

    s = hev_tunnel_write (tun_fd, p);
    if (s <= 0) {
        if (errno == EAGAIN)
            return ERR_WOULDBLOCK;
        LOG_W ("socks5 tunnel write");
        return ERR_IF;
    }

    atomic_fetch_add_explicit (&stat_rx_packets, 1, memory_order_relaxed);
    atomic_fetch_add_explicit (&stat_rx_bytes, (size_t)s, memory_order_relaxed);

    return ERR_OK;
}

static err_t
netif_output_v4_handler (struct netif *netif, struct pbuf *p,
                         const ip4_addr_t *ipaddr)
{
    return netif_output_handler (netif, p);
}

static err_t
netif_output_v6_handler (struct netif *netif, struct pbuf *p,
                         const ip6_addr_t *ipaddr)
{
    return netif_output_handler (netif, p);
}

static err_t
netif_init_handler (struct netif *netif)
{
    netif->output = netif_output_v4_handler;
    netif->output_ip6 = netif_output_v6_handler;

    return ERR_OK;
}

static void
hev_socks5_tunnel_insert_session (HevListNode *node)
{
    HevSocks5SessionData *sd;
    int max_session_count;

    hev_list_add_tail (&session_set, node);
    session_count++;

    max_session_count = hev_config_get_misc_max_session_count ();
    if (!max_session_count || session_count < max_session_count)
        return;

    node = hev_list_first (&session_set);
    sd = container_of (node, HevSocks5SessionData, node);
    hev_socks5_session_terminate (sd->self);
}

static void
hev_socks5_tunnel_delete_session (HevListNode *node)
{
    hev_list_del (&session_set, node);
    session_count--;
}

void
hev_socks5_tunnel_update_session (HevListNode *node)
{
    int max_session_count;

    max_session_count = hev_config_get_misc_max_session_count ();
    if (!max_session_count)
        return;

    hev_list_del (&session_set, node);
    hev_list_add_tail (&session_set, node);
}

static void
hev_socks5_session_task_entry (void *data)
{
    HevSocks5Session *s = data;

    hev_socks5_session_run (s);

    hev_socks5_tunnel_delete_session (hev_socks5_session_get_node (s));
    hev_object_unref (HEV_OBJECT (s));
}

static err_t
tcp_accept_handler (void *arg, struct tcp_pcb *pcb, err_t err)
{
    HevSocks5SessionTCP *tcp;
    HevListNode *node;
    int stack_size;
    HevTask *task;

    if (err != ERR_OK)
        return err;

    if (!READ_ONCE (run))
        return ERR_RST;

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp)
        return ERR_MEM;

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        hev_object_unref (HEV_OBJECT (tcp));
        return ERR_MEM;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (tcp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (tcp));
    hev_socks5_tunnel_insert_session (node);
    hev_task_run (task, hev_socks5_session_task_entry, tcp);
    hev_task_wakeup (task_lwip_timer);

    return ERR_OK;
}

static void
dns_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                  const ip_addr_t *addr, u16_t port)
{
    HevMappedDNS *dns = arg;
    struct pbuf *b;
    uint8_t packet[UDP_BUF_SIZE];
    int res;

    LOG_D ("%p mapped dns handle", dns);

    b = pbuf_alloc (PBUF_TRANSPORT, UDP_BUF_SIZE, PBUF_RAM);
    if (!b)
        goto exit;
    if (p->tot_len > sizeof (packet) ||
        pbuf_copy_partial (p, packet, p->tot_len, 0) != p->tot_len)
        goto free;

    res = hev_mapped_dns_handle (
        dns, packet, p->tot_len, b->payload, b->len,
        pcb->remote_ip.type == IPADDR_TYPE_V4
            ? ip_2_ip4 (&pcb->remote_ip)->addr : 0,
        pcb->remote_port);
    if (res < 0)
        goto free;

    b->len = res;
    b->tot_len = res;
    udp_sendfrom (pcb, b, &pcb->local_ip, pcb->local_port);

free:
    pbuf_free (b);
exit:
    pbuf_free (p);
    udp_recv (pcb, NULL, NULL);
    udp_remove (pcb);
}

static void
udp_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                  const ip_addr_t *addr, u16_t port)
{
    HevSocks5SessionUDP *udp;
    HevListNode *node;
    HevMappedDNS *dns;
    int stack_size;
    HevTask *task;

    if (!READ_ONCE (run)) {
        udp_remove (pcb);
        return;
    }

    dns = hev_mapped_dns_get ();
    if (dns && addr->type == IPADDR_TYPE_V4) {
        int faddr = hev_config_get_mapdns_address ();
        int fport = hev_config_get_mapdns_port ();
        if (fport == port && (uint32_t)faddr == ip_2_ip4 (addr)->addr) {
            udp_recv (pcb, dns_recv_handler, dns);
            return;
        }
    }

    udp = hev_socks5_session_udp_new (pcb, &mutex);
    if (!udp) {
        udp_remove (pcb);
        return;
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        hev_object_unref (HEV_OBJECT (udp));
        return;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (udp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (udp));
    hev_socks5_tunnel_insert_session (node);
    hev_task_run (task, hev_socks5_session_task_entry, udp);
    hev_task_wakeup (task_lwip_timer);
}

static void
event_task_entry (void *data)
{
    HevListNode *node;
    int val;

    LOG_D ("socks5 tunnel event task run");

    hev_task_add_fd (task_event, event_fds[0], POLLIN);

    hev_task_io_read (event_fds[0], &val, sizeof (val), NULL, NULL);

    WRITE_ONCE (run, 0);
    atomic_fetch_and (&tsync, ~SYNC_SENT);

    node = hev_list_first (&session_set);
    for (; node; node = hev_list_node_next (node)) {
        HevSocks5SessionData *sd;

        sd = container_of (node, HevSocks5SessionData, node);
        hev_socks5_session_terminate (sd->self);
    }

    hev_task_join (task_lwip_io);
    hev_task_join (task_lwip_timer);
    hev_task_del_fd (task_event, event_fds[0]);
}

static void
lwip_io_task_entry (void *data)
{
    const unsigned int mtu = hev_config_get_tunnel_mtu ();

    LOG_D ("socks5 tunnel lwip task run");

    hev_tunnel_add_task (tun_fd, task_lwip_io);

    for (; READ_ONCE (run);) {
        struct pbuf *buf;

        buf = hev_tunnel_read (tun_fd, mtu, task_io_yielder, NULL);
        if (!buf)
            continue;

        if (packet_ipv4_is_blocked (buf) || packet_ipv6_is_blocked (buf)) {
            pbuf_free (buf);
            continue;
        }

        char destination_address[INET6_ADDRSTRLEN];
        const char *transport_protocol = NULL;
        uint16_t destination_port = 0;

        if (packet_is_encrypted_dns (buf, destination_address,
                                     sizeof (destination_address),
                                     &destination_port,
                                     &transport_protocol)) {
#ifdef __ANDROID__
            hev_jni_report_encrypted_dns_event (destination_address,
                                                destination_port,
                                                transport_protocol);
#endif
            pbuf_free (buf);
            continue;
        }

        atomic_fetch_add_explicit (&stat_tx_packets, 1, memory_order_relaxed);
        atomic_fetch_add_explicit (&stat_tx_bytes, buf->tot_len, memory_order_relaxed);

        hev_task_mutex_lock (&mutex);
        if (netif->input (buf, netif) != ERR_OK)
            pbuf_free (buf);
        hev_task_mutex_unlock (&mutex);
    }

    hev_tunnel_del_task (tun_fd, task_lwip_io);
}

static void
lwip_timer_task_entry (void *data)
{
    unsigned int i;

    LOG_D ("socks5 tunnel timer task run");

    for (i = 1; READ_ONCE (run); i++) {
        hev_task_mutex_lock (&mutex);
        tcp_tmr ();

        if ((i & 3) == 0) {
#if IP_REASSEMBLY
            ip_reass_tmr ();
#endif
#if LWIP_IPV6
            nd6_tmr ();
#if LWIP_IPV6_REASS
            ip6_reass_tmr ();
#endif
#endif
        }
        hev_task_mutex_unlock (&mutex);

        if (hev_list_first (&session_set))
            hev_task_sleep (TCP_TMR_INTERVAL);
        else
            hev_task_yield (HEV_TASK_WAITIO);
    }
}

static int
tunnel_init (int extern_tun_fd)
{
    const char *script_path, *name, *guid, *ipv4, *ipv6;
    int multi_queue, res;
    unsigned int mtu;

    if (extern_tun_fd >= 0) {
        int nonblock = 1;

        res = ioctl (extern_tun_fd, FIONBIO, (char *)&nonblock);
        if (res < 0) {
            LOG_E ("socks5 tunnel non-blocking");
            return -1;
        }

        tun_fd = extern_tun_fd;
        return 0;
    }

    tun_fd_local = 1;
    name = hev_config_get_tunnel_name ();
    multi_queue = hev_config_get_tunnel_multi_queue ();
    guid = hev_config_get_tunnel_guid ();
    tun_fd = hev_tunnel_open (name, multi_queue, guid);
    if (tun_fd < 0) {
        LOG_E ("socks5 tunnel open (%s)", strerror (errno));
        return -1;
    }

    mtu = hev_config_get_tunnel_mtu ();
    res = hev_tunnel_set_mtu (mtu);
    if (res < 0) {
        LOG_E ("socks5 tunnel mtu");
        return -1;
    }

    ipv4 = hev_config_get_tunnel_ipv4_address ();
    if (ipv4) {
        res = hev_tunnel_set_ipv4 (ipv4, 32);
        if (res < 0) {
            LOG_E ("socks5 tunnel ipv4");
            return -1;
        }
    }

    ipv6 = hev_config_get_tunnel_ipv6_address ();
    if (ipv6) {
        res = hev_tunnel_set_ipv6 (ipv6, 128);
        if (res < 0) {
            LOG_E ("socks5 tunnel ipv6");
            return -1;
        }
    }

    res = hev_tunnel_set_state (1);
    if (res < 0) {
        LOG_E ("socks5 tunnel state");
        return -1;
    }

    script_path = hev_config_get_tunnel_post_up_script ();
    if (script_path)
        hev_exec_run (script_path, hev_tunnel_get_name (),
                      hev_tunnel_get_index (), 0);

    return 0;
}

static void
tunnel_fini (void)
{
    const char *script_path;

    if (!tun_fd_local)
        return;

    script_path = hev_config_get_tunnel_pre_down_script ();
    if (script_path)
        hev_exec_run (script_path, hev_tunnel_get_name (),
                      hev_tunnel_get_index (), 1);

    if (tun_fd >= 0) {
        hev_tunnel_close (tun_fd);
        tun_fd_local = 0;
        tun_fd = -1;
    }
}

static int
gateway_init (void)
{
    static struct netif _netif;
    ip4_addr_t addr4, mask, gw;
    ip6_addr_t addr6;

    netif = netif_add_noaddr (&_netif, NULL, netif_init_handler, ip_input);
    if (!netif) {
        LOG_E ("socks5 tunnel netif");
        return -1;
    }

    ip4_addr_set_loopback (&addr4);
    ip4_addr_set_any (&mask);
    ip4_addr_set_any (&gw);
    netif_set_addr (netif, &addr4, &mask, &gw);

    ip6_addr_set_loopback (&addr6);
    netif_add_ip6_address (netif, &addr6, NULL);

    netif_set_up (netif);
    netif_set_link_up (netif);
    netif_set_default (netif);
    netif_set_flags (netif, NETIF_FLAG_PRETEND_TCP);
    netif_set_flags (netif, NETIF_FLAG_PRETEND_UDP);

    if (hev_config_get_tunnel_icmp ())
        netif_set_flags (netif, NETIF_FLAG_PRETEND_ICMP);

    tcp = tcp_new_ip_type (IPADDR_TYPE_ANY);
    if (!tcp) {
        LOG_E ("socks5 tunnel tcp");
        return -1;
    }

    tcp_bind_netif (tcp, netif);
    tcp_bind (tcp, NULL, 0);
    tcp = tcp_listen (tcp);
    tcp_accept (tcp, tcp_accept_handler);

    udp = udp_new_ip_type (IPADDR_TYPE_ANY);
    if (!udp) {
        LOG_E ("socks5 tunnel udp");
        return -1;
    }

    udp_bind_netif (udp, netif);
    udp_bind (udp, NULL, 0);
    udp_recv (udp, udp_recv_handler, NULL);

    return 0;
}

static void
gateway_fini (void)
{
    if (udp) {
        udp_remove (udp);
        udp = NULL;
    }
    if (tcp) {
        tcp_close (tcp);
        tcp = NULL;
    }
    if (netif) {
        netif_remove (netif);
        netif = NULL;
    }
}

static int
event_task_init (void)
{
    int nonblock = 1;
    int res;

    res = socketpair (PF_LOCAL, SOCK_STREAM, 0, event_fds);
    if (res < 0) {
        LOG_E ("socks5 tunnel event");
        return -1;
    }

    res = ioctl (event_fds[0], FIONBIO, (char *)&nonblock);
    if (res < 0) {
        LOG_E ("socks5 tunnel event nonblock");
        return -1;
    }

    task_event = hev_task_new (-1);
    if (!task_event) {
        LOG_E ("socks5 tunnel task event");
        return -1;
    }

    return 0;
}

static void
event_task_fini (void)
{
    if (task_event) {
        hev_task_unref (task_event);
        task_event = NULL;
    }

    if (event_fds[0] >= 0) {
        close (event_fds[0]);
        event_fds[0] = -1;
    }
    if (event_fds[1] >= 0) {
        close (event_fds[1]);
        event_fds[1] = -1;
    }
}

static int
lwip_io_task_init (void)
{
    task_lwip_io = hev_task_new (-1);
    if (!task_lwip_io) {
        LOG_E ("socks5 tunnel task lwip");
        return -1;
    }
    hev_task_set_priority (task_lwip_io, 1);

    return 0;
}

static void
lwip_io_task_fini (void)
{
    if (task_lwip_io) {
        hev_task_unref (task_lwip_io);
        task_lwip_io = NULL;
    }
}

static int
lwip_timer_task_init (void)
{
    task_lwip_timer = hev_task_new (-1);
    if (!task_lwip_timer) {
        LOG_E ("socks5 tunnel task timer");
        return -1;
    }
    hev_task_set_priority (task_lwip_timer, 1);

    return 0;
}

static void
lwip_timer_task_fini (void)
{
    if (task_lwip_timer) {
        hev_task_unref (task_lwip_timer);
        task_lwip_timer = NULL;
    }
}

static int
mapped_dns_init (void)
{
    HevMappedDNS *dns;
    int cache_size;
    int network;
    int netmask;

    network = hev_config_get_mapdns_network ();
    netmask = hev_config_get_mapdns_netmask ();
    cache_size = hev_config_get_mapdns_cache_size ();

    if (!cache_size)
        return 0;

    dns = hev_mapped_dns_new (network, netmask, cache_size);
    if (!dns)
        return -1;

    hev_mapped_dns_put (dns);

    return 0;
}

static void
mapped_dns_fini (void)
{
    HevMappedDNS *dns;

    dns = hev_mapped_dns_get ();
    if (dns) {
        hev_object_unref (HEV_OBJECT (dns));
        hev_mapped_dns_put (NULL);
    }
}

int
hev_socks5_tunnel_init (int tun_fd)
{
    int res;

    LOG_D ("socks5 tunnel init");

    res = tunnel_init (tun_fd);
    if (res < 0)
        goto exit;

    res = gateway_init ();
    if (res < 0)
        goto exit;

    res = event_task_init ();
    if (res < 0)
        goto exit;

    res = lwip_io_task_init ();
    if (res < 0)
        goto exit;

    res = lwip_timer_task_init ();
    if (res < 0)
        goto exit;

    res = mapped_dns_init ();
    if (res < 0)
        goto exit;

    signal (SIGPIPE, SIG_IGN);

    hev_task_mutex_init (&mutex);

    atomic_fetch_or (&tsync, SYNC_SEND);

    return 0;

exit:
    hev_socks5_tunnel_fini ();
    return -1;
}

void
hev_socks5_tunnel_fini (void)
{
    LOG_D ("socks5 tunnel fini");

retry:
    if (atomic_fetch_and (&tsync, ~(SYNC_SEND | SYNC_SENT)) & SYNC_WAIT) {
        usleep (500);
        goto retry;
    }

    mapped_dns_fini ();
    lwip_timer_task_fini ();
    lwip_io_task_fini ();
    event_task_fini ();
    gateway_fini ();
    tunnel_fini ();

    atomic_store_explicit (&stat_tx_packets, 0, memory_order_relaxed);
    atomic_store_explicit (&stat_rx_packets, 0, memory_order_relaxed);
    atomic_store_explicit (&stat_tx_bytes, 0, memory_order_relaxed);
    atomic_store_explicit (&stat_rx_bytes, 0, memory_order_relaxed);
}

int
hev_socks5_tunnel_run (void)
{
    LOG_D ("socks5 tunnel run");

    if (atomic_fetch_and (&tsync, ~SYNC_STOP) & SYNC_STOP)
        return 0;

    task_event = hev_task_ref (task_event);
    hev_task_run (task_event, event_task_entry, NULL);

    task_lwip_io = hev_task_ref (task_lwip_io);
    hev_task_run (task_lwip_io, lwip_io_task_entry, NULL);

    task_lwip_timer = hev_task_ref (task_lwip_timer);
    hev_task_run (task_lwip_timer, lwip_timer_task_entry, NULL);

    WRITE_ONCE (run, 1);
    hev_task_system_run ();

    return 0;
}

void
hev_socks5_tunnel_stop (void)
{
    int res;

    LOG_D ("socks5 tunnel stop");

retry:
    res = atomic_fetch_or (&tsync, SYNC_WAIT);
    if (res & SYNC_WAIT) {
        usleep (500);
        goto retry;
    }

    if (res & SYNC_SEND) {
        res = atomic_fetch_or (&tsync, SYNC_SENT);
        if (!(res & SYNC_SENT)) {
            res = write (event_fds[1], &res, 1);
            assert (res > 0 && "socks5 tunnel write event");
        }
    } else {
        atomic_fetch_or (&tsync, SYNC_STOP);
    }

    atomic_fetch_and (&tsync, ~SYNC_WAIT);
}

void
hev_socks5_tunnel_stats (size_t *tx_packets, size_t *tx_bytes,
                         size_t *rx_packets, size_t *rx_bytes)
{
    LOG_D ("socks5 tunnel stats");

    if (tx_packets)
        *tx_packets = atomic_load_explicit (&stat_tx_packets, memory_order_relaxed);

    if (tx_bytes)
        *tx_bytes = atomic_load_explicit (&stat_tx_bytes, memory_order_relaxed);

    if (rx_packets)
        *rx_packets = atomic_load_explicit (&stat_rx_packets, memory_order_relaxed);

    if (rx_bytes)
        *rx_bytes = atomic_load_explicit (&stat_rx_bytes, memory_order_relaxed);
}
