/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <daemon.h>
#include <utils/debug.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>
#include <collections/hashtable.h>
#include <threading/mutex.h>

#include "vpp/model/rpc/rpc.grpc-c.h"
#include "kernel_vpp_ipsec.h"
#include "kernel_vpp_grpc.h"

#define PRIO_BASE 384

typedef struct private_kernel_vpp_ipsec_t private_kernel_vpp_ipsec_t;

/**
 * Private variables of kernel_vpp_ipsec class.
 */
struct private_kernel_vpp_ipsec_t {

    /**
     * Public interface
     */
    kernel_vpp_ipsec_t public;

    /**
     * Mutex to lock access to installed policies
     */
    mutex_t *mutex;

    /**
     * Hash table containing Security Association Database (SAD)
     * kernel_ipsec_sa_id_t => sa_t
     */
    hashtable_t *sad;

    /**
     * Hash table containing Security Policy Database (SPD)
     * iterface => spd_t
     */
    hashtable_t *spd;

    /**
     * Linked list of installed routes
     */
    linked_list_t *routes;

    /**
     * Next SPI to allocate
     */
    refcount_t nextspi;

    /**
     * Mix value to distribute SPI allocation randomly
     */
    uint32_t mixspi;

    /**
     * Whether to install routes along policies
     */
    bool install_routes;
};

// interface esn - extended sequence number
// interface replay - anti replay option
// interface name
// interface enabled
// interface ip_addresses ?? (repeated, use of ?)
//  - if we need to setup interface ip address ?
//  interface vrf - ??

// TODO: review if security association shouldn't contain
// src or dst ?!

/**
 * Security association entry
 */
typedef struct {
    // TODO: test if it is the same as in ipsec_sa_cfg_t
    // and that would meen it is usable for us to match
    // SA to SP
    /** kernel_ipsec_add_sa_t reqid */
    /** unique ID */ 
    uint32_t reqid;
    /** SPI */
    uint32_t spi;
    /** VPP Encryption algorithm */
    uint16_t vpp_enc_alg;
    /** Encryption key */ 
    chunk_t enc_key;
    /** VPP Integrity Protection algorithm */
    uint16_t vpp_int_alg;
    /** Integrity protection key */
    chunk_t int_key;

    // TODO:
    // ADD SRC/DST - guess those will be reversed based on OUTPUT/INPUT
    // interface - this has to be checked out
} sa_t;

/**
 * Security policy entry
 */
typedef struct {
    /** Direction of traffic */
    policy_dir dir;
    /** Networking interface ID */
    uint32_t sw_if_index;
    /** kernel_ipsec_add_sa_t reqid */
    /** unique ID */ 
    uint32_t reqid;
    /** Source address */
    host_t *src; // !!! those may not be what you think they are
    /** Destination address */
    host_t *dst; // !!! those may not be what you think they are
} sp_t;

/**
 */
typedef struct {
    /** Name of the interface the route is bound to */
    char *if_name;
    /** Gateway of route */
    host_t *gateway;
    /** Destination network of route */
    host_t *dst_net;
    /** Prefix length of dst_net */
    uint8_t prefixlen;
    /** References for route */
    int refs;
} route_entry_t;

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))

CALLBACK(route_equals, bool, route_entry_t *a, va_list args)
{
    host_t *dst_net, *gateway;
    uint8_t *prefixlen;
    char *if_name;

    VA_ARGS_VGET(args, if_name, gateway, dst_net, prefixlen);

    return a->if_name && if_name && streq(a->if_name, if_name) &&
           a->gateway->ip_equals(a->gateway, gateway) &&
           a->dst_net->ip_equals(a->dst_net, dst_net) &&
           a->prefixlen == *prefixlen;
}

/**
 * Clean up a route entry
 */
static void route_destroy(route_entry_t *this)
{
    this->dst_net->destroy(this->dst_net);
    this->gateway->destroy(this->gateway);
    free(this->if_name);
    free(this);
}

/**
 * (Un)-install a single route
 */
// REVIEW: how is the route used in this logic we will have to find out
// if there is point in using it for tunnel interface
#if 0
static void manage_route(private_kernel_vpp_ipsec_t *this, bool add,
                         traffic_selector_t *dst_ts, host_t *src, host_t *dst)
{
    host_t *dst_net, *gateway;
    uint8_t prefixlen;
    char *if_name;
    route_entry_t *route;
    bool route_exist = FALSE;

    if (dst->is_anyaddr(dst))
    {
        return;
    }
    gateway = charon->kernel->get_nexthop(charon->kernel, dst, -1, NULL, &if_name);
    dst_ts->to_subnet(dst_ts, &dst_net, &prefixlen);
    if (!if_name)
    {
        if (src->is_anyaddr(src))
        {
            return;
        }
        if (!charon->kernel->get_interface(charon->kernel, src, &if_name))
        {
            return;
        }
    }
    route_exist = this->routes->find_first(this->routes, route_equals,
        (void**)&route, if_name, gateway, dst_net, &prefixlen);
    if (add)
    {
        if (route_exist)
        {
            route->refs++;
        }
        else
        {
            DBG2(DBG_KNL, "installing route: %H/%d via %H dev %s",
                 dst_net, prefixlen, gateway, if_name);
            INIT(route,
                .if_name = strdup(if_name),
                .gateway = gateway->clone(gateway),
                .dst_net = dst_net->clone(dst_net),
                .prefixlen = prefixlen,
                .refs = 1,
            );
            this->routes->insert_last(this->routes, route);
            charon->kernel->add_route(charon->kernel,
                 dst_net->get_address(dst_net), prefixlen, dst, NULL, if_name);
        }
    }
    else
    {
        if (!route_exist || --route->refs > 0)
        {
            return;
        }
        DBG2(DBG_KNL, "uninstalling route: %H/%d via %H dev %s",
             dst_net, prefixlen, gateway, if_name);
        this->routes->remove(this->routes, route, NULL);
        route_destroy(route);
        charon->kernel->del_route(charon->kernel, dst_net->get_address(dst_net),
             prefixlen, dst, NULL, if_name);
    }
}
#endif

/**
 * Hash function for IPsec SA
 */
static u_int sa_hash(kernel_ipsec_sa_id_t *sa)
{
    return chunk_hash_inc(sa->src->get_address(sa->src),
                          chunk_hash_inc(sa->dst->get_address(sa->dst),
                          chunk_hash_inc(chunk_from_thing(sa->spi),
                          chunk_hash(chunk_from_thing(sa->proto)))));
}

/**
 * Equality function for IPsec SA
 */
static bool sa_equals(kernel_ipsec_sa_id_t *sa, kernel_ipsec_sa_id_t *other_sa)
{
    return sa->src->ip_equals(sa->src, other_sa->src) &&
            sa->dst->ip_equals(sa->dst, other_sa->dst) &&
            sa->spi == other_sa->spi && sa->proto == other_sa->proto;
}

/**
 * Hash function for interface
 */
static u_int interface_hash(char *interface)
{
    return chunk_hash(chunk_from_str(interface));
}

/**
 * Equality function for interface
 */
static bool interface_equals(char *interface1, char *interface2)
{
    return streq(interface1, interface2);
}

/**
 * Map an integer x with a one-to-one function using quadratic residues
 */
static u_int permute(u_int x, u_int p)
{
    u_int qr;

    x = x % p;
    qr = ((uint64_t)x * x) % p;
    if (x <= p / 2)
    {
        return qr;
    }
    return p - qr;
}

/**
 * Initialize seeds for SPI generation
 */
static bool init_spi(private_kernel_vpp_ipsec_t *this)
{
    bool ok = TRUE;
    rng_t *rng;

    rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
    if (!rng)
    {
        return FALSE;
    }
    ok = rng->get_bytes(rng, sizeof(this->nextspi), (uint8_t*)&this->nextspi);
    if (ok)
    {
        ok = rng->get_bytes(rng, sizeof(this->mixspi), (uint8_t*)&this->mixspi);
    }
    rng->destroy(rng);
    return ok;
}

/**
 * Calculate policy priority
 */
static uint32_t calculate_priority(policy_priority_t policy_priority,
                                   traffic_selector_t *src,
                                   traffic_selector_t *dst)
{
    uint32_t priority = PRIO_BASE;
    uint16_t port;
    uint8_t mask, proto;
    host_t *net;

    switch (policy_priority)
    {
        case POLICY_PRIORITY_FALLBACK:
            priority <<= 1;
            /* fall-through */
        case POLICY_PRIORITY_ROUTED:
            priority <<= 1;
            /* fall-through */
        case POLICY_PRIORITY_DEFAULT:
            priority <<= 1;
            /* fall-through */
        case POLICY_PRIORITY_PASS:
            break;
    }
    /* calculate priority based on selector size, small size = high prio */
    src->to_subnet(src, &net, &mask);
    priority -= mask;
    proto = src->get_protocol(src);
    port = net->get_port(net);
    net->destroy(net);

    dst->to_subnet(dst, &net, &mask);
    priority -= mask;
    proto = max(proto, dst->get_protocol(dst));
    port = max(port, net->get_port(net));
    net->destroy(net);

    priority <<= 2; /* make some room for the two flags */
    priority += port ? 0 : 2;
    priority += proto ? 0 : 1;
    return priority;
}

/**
 * Get sw_if_index from interface name
 */
static status_t get_sw_if_index(char *name, uint32_t **if_index)
{
    Interfaces__InterfacesState__Interface if_state;
    Rpc__DumpRequest rq = RPC__DUMP_REQUEST__INIT;
    Rpc__InterfaceResponse *rp;
    status_t rc;
    size_t n;

    rc = vac->dump_interfaces_state(vac, &rq, &rp);
    if (rc == SUCCESS)
    {
        n = rp->n_interfaces;
        while (n--)
        {
            if_state = rp->interfaces[n];
            if (strcmp(name, if_state->name) == 0)
            {
                if (if_state->has_if_index)
                {
                    *if_index = if_state->if_index;
                    return SUCCESS;
                }
                break;
            }
        }
    }
    return FAILED;
}

// TODO:
// split this for add / del, those are different rpc calls
// implement matching algo for 4 callsTO 1 mapping
// if mapping setup completed do the call (we should not care what
// call does the finishing rpc call)
// so add_sp or add_sa
// the call will be add_tunnel
// we need map of 4
// we need to do matching for add_sp (policy) we can match based on
//  interface but is this viable ?
// are sa and sp interface based ?
//  sps definitely are ! because they use IP address of the input interface
//  as src (if we are senders of IPSEC traffic)
/**
 * Add or remove a policy
 */
static status_t manage_policy(private_kernel_vpp_ipsec_t *this, bool add,
                              kernel_ipsec_policy_id_t *id,
                              kernel_ipsec_manage_policy_t *data)
{

  /* extracting keys !!
    // crypto key
    mp->crypto_algorithm = enc_alg;
    mp->crypto_key_length = data->enc_key.len;
    memcpy(mp->crypto_key, data->enc_key.ptr, data->enc_key.len);

    // integrity key
    mp->integrity_algorithm = ia;
    mp->integrity_key_length = data->int_key.len;
    memcpy(mp->integrity_key, data->int_key.ptr, data->int_key.len);
  */

    spd_t *spd;
    char *out = NULL, *interface;
    int out_len;
    uint32_t sw_if_index, spd_id, *sad_id;
    status_t rv = FAILED;
    uint32_t priority, auto_priority;
    chunk_t src_from, src_to, dst_from, dst_to;
    host_t *src, *dst, *addr;

    uint32_t if_index;
    status_t rc;

    this->mutex->lock(this->mutex);
    if (!id->interface)
    {
        addr = id->dir == POLICY_IN ? data->dst : data->src;
        if (!charon->kernel->get_interface(charon->kernel, addr, &interface))
        {
            DBG1(DBG_KNL, "policy no interface %H", addr);
            goto error;
        }
        id->interface = interface;
    }
    // we use this to get it out
    spd = this->spds->get(this->spds, id->interface);
    if (!spd)
    {
        if (!add)
        {
            DBG1(DBG_KNL, "SPD for %s not found", id->interface);
            goto error;
        }
        rc = get_sw_if_index(id->interface, &if_index);
        if (rc != SUCCESS)
        {
            DBG1(DBG_KNL, "sw_if_index for %s not found", id->interface);
            goto error;
        }
        // ditch it
        spd_id = ref_get(&this->next_spd_id);
        if (spd_add_del(TRUE, spd_id))
        {
            goto error;
        }
        if (manage_bypass(TRUE, spd_id))
        {
            goto error;
        }
        if (interface_add_del_spd(TRUE, spd_id, sw_if_index))
        {
            goto error;
        }
        INIT(spd,
                .spd_id = spd_id,
                .sw_if_index = sw_if_index,
                .policy_num = 0,
        );
        this->spds->put(this->spds, id->interface, spd);
    }

    auto_priority = calculate_priority(data->prio, id->src_ts, id->dst_ts);
    priority = data->manual_prio ? data->manual_prio : auto_priority;

    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SPD_ADD_DEL_ENTRY);
    mp->is_add = add;
    mp->spd_id = ntohl(spd->spd_id);
    mp->priority = ntohl(INT_MAX - priority);

    // we need this to know what we are configuring
    mp->is_outbound = id->dir == POLICY_OUT;


    // this will be interesting, those should be add as routes i guess
    if (id->dir == POLICY_OUT)
    {
        src_from = id->src_ts->get_from_address(id->src_ts);
        src_to = id->src_ts->get_to_address(id->src_ts);
        src = host_create_from_chunk(mp->is_ipv6 ? AF_INET6 : AF_INET, src_to, 0);
        dst_from = id->dst_ts->get_from_address(id->dst_ts);
        dst_to = id->dst_ts->get_to_address(id->dst_ts);
        dst = host_create_from_chunk(mp->is_ipv6 ? AF_INET6 : AF_INET, dst_to, 0);
    }
    else
    {
        dst_from = id->src_ts->get_from_address(id->src_ts);
        dst_to = id->src_ts->get_to_address(id->src_ts);
        dst = host_create_from_chunk(mp->is_ipv6 ? AF_INET6 : AF_INET, src_to, 0);
        src_from = id->dst_ts->get_from_address(id->dst_ts);
        src_to = id->dst_ts->get_to_address(id->dst_ts);
        src = host_create_from_chunk(mp->is_ipv6 ? AF_INET6 : AF_INET, dst_to, 0);
    }

    if (src->is_anyaddr(src) && dst->is_anyaddr(dst))
    {
        mp->is_ip_any = 1;
    }
    else
    {
        memcpy(mp->local_address_start, src_from.ptr, src_from.len);
        memcpy(mp->local_address_stop, src_to.ptr, src_to.len);
        memcpy(mp->remote_address_start, dst_from.ptr, dst_from.len);
        memcpy(mp->remote_address_stop, dst_to.ptr, dst_to.len);
    }
    mp->local_port_start = ntohs(id->src_ts->get_from_port(id->src_ts));
    mp->local_port_stop = ntohs(id->src_ts->get_to_port(id->src_ts));
    mp->remote_port_start = ntohs(id->dst_ts->get_from_port(id->dst_ts));
    mp->remote_port_stop = ntohs(id->dst_ts->get_to_port(id->dst_ts));

    if (this->install_routes && id->dir == POLICY_OUT && !mp->protocol)
    {
        // important !!! we need a route 
        // we may also need to enable promiscuous on input/output interface
        // what about arp ? 
        // set int state ipsec0 up !! also required
        if (data->type == POLICY_IPSEC && data->sa->mode != MODE_TRANSPORT)
        {
            manage_route(this, add, id->dst_ts, data->src, data->dst);
        }
    }
    rv = SUCCESS;
error:
    this->mutex->unlock(this->mutex);
    return rv;
}


/**
 * Add or remove a policy
 */
static status_t manage_policy(private_kernel_vpp_ipsec_t *this, bool add,
                              kernel_ipsec_policy_id_t *id,
                              kernel_ipsec_manage_policy_t *data)
{

  /* extracting keys !!
    // crypto key
    mp->crypto_algorithm = enc_alg;
    mp->crypto_key_length = data->enc_key.len;
    memcpy(mp->crypto_key, data->enc_key.ptr, data->enc_key.len);

    // integrity key
    mp->integrity_algorithm = ia;
    mp->integrity_key_length = data->int_key.len;
    memcpy(mp->integrity_key, data->int_key.ptr, data->int_key.len);
  */

    spd_t *spd;
    char *out = NULL, *interface;
    int out_len;
    uint32_t sw_if_index, spd_id, *sad_id;
    status_t rv = FAILED;
    uint32_t priority, auto_priority;
    chunk_t src_from, src_to, dst_from, dst_to;
    host_t *src, *dst, *addr;
    vl_api_ipsec_spd_add_del_entry_t *mp;
    vl_api_ipsec_spd_add_del_entry_reply_t *rmp;

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof(*mp));

    this->mutex->lock(this->mutex);
    if (!id->interface)
    {
        addr = id->dir == POLICY_IN ? data->dst : data->src;
        if (!charon->kernel->get_interface(charon->kernel, addr, &interface))
        {
            DBG1(DBG_KNL, "policy no interface %H", addr);
            goto error;
        }
        id->interface = interface;
    }
    // we use this to get it out
    spd = this->spds->get(this->spds, id->interface);
    if (!spd)
    {
        if (!add)
        {
            DBG1(DBG_KNL, "SPD for %s not found", id->interface);
            goto error;
        }
        sw_if_index = get_sw_if_index(id->interface);
        if (sw_if_index == ~0)
        {
            DBG1(DBG_KNL, "sw_if_index for %s not found", id->interface);
            goto error;
        }
        spd_id = ref_get(&this->next_spd_id);
        if (spd_add_del(TRUE, spd_id))
        {
            goto error;
        }
        if (manage_bypass(TRUE, spd_id))
        {
            goto error;
        }
        if (interface_add_del_spd(TRUE, spd_id, sw_if_index))
        {
            goto error;
        }
        INIT(spd,
                .spd_id = spd_id,
                .sw_if_index = sw_if_index,
                .policy_num = 0,
        );
        this->spds->put(this->spds, id->interface, spd);
    }

    auto_priority = calculate_priority(data->prio, id->src_ts, id->dst_ts);
    priority = data->manual_prio ? data->manual_prio : auto_priority;

    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SPD_ADD_DEL_ENTRY);
    mp->is_add = add;
    mp->spd_id = ntohl(spd->spd_id);
    mp->priority = ntohl(INT_MAX - priority);
    mp->is_outbound = id->dir == POLICY_OUT;
    // we don't care about these ! if we are doing tunneling interface
    switch (data->type)
    {
        case POLICY_IPSEC:
            mp->policy = 3;
            break;
        case POLICY_PASS:
            mp->policy = 0;
            break;
        case POLICY_DROP:
            mp->policy = 1;
            break;
    }
    // pozor data->sa je ipsec_sa_cfg_t uplne ako request a neobsahuje
    // vsetky data
    // data->sa
    // we have security association (keys .. integ)
    // security association is mapped to the SA in add_sa call
    // well if those data are in data->sa ?? we could ignore
    // add_sa call
    if ((data->type == POLICY_IPSEC) && data->sa)
    {
        kernel_ipsec_sa_id_t id = {
                .src = data->src,
                .dst = data->dst,
                .proto = data->sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
                .spi = data->sa->esp.use ? data->sa->esp.spi : data->sa->ah.spi,
        };
        sad_id = this->sas->get(this->sas, &id);
        if (!sad_id)
        {
            DBG1(DBG_KNL, "SA ID not found");
            goto error;
        }
        mp->sa_id = ntohl(*sad_id);
    }

    mp->is_ipv6 = id->src_ts->get_type(id->src_ts) == TS_IPV6_ADDR_RANGE;
    mp->protocol = id->src_ts->get_protocol(id->src_ts);

    if (id->dir == POLICY_OUT)
    {
        src_from = id->src_ts->get_from_address(id->src_ts);
        src_to = id->src_ts->get_to_address(id->src_ts);
        src = host_create_from_chunk(mp->is_ipv6 ? AF_INET6 : AF_INET, src_to, 0);
        dst_from = id->dst_ts->get_from_address(id->dst_ts);
        dst_to = id->dst_ts->get_to_address(id->dst_ts);
        dst = host_create_from_chunk(mp->is_ipv6 ? AF_INET6 : AF_INET, dst_to, 0);
    }
    else
    {
        dst_from = id->src_ts->get_from_address(id->src_ts);
        dst_to = id->src_ts->get_to_address(id->src_ts);
        dst = host_create_from_chunk(mp->is_ipv6 ? AF_INET6 : AF_INET, src_to, 0);
        src_from = id->dst_ts->get_from_address(id->dst_ts);
        src_to = id->dst_ts->get_to_address(id->dst_ts);
        src = host_create_from_chunk(mp->is_ipv6 ? AF_INET6 : AF_INET, dst_to, 0);
    }

    if (src->is_anyaddr(src) && dst->is_anyaddr(dst))
    {
        mp->is_ip_any = 1;
    }
    else
    {
        memcpy(mp->local_address_start, src_from.ptr, src_from.len);
        memcpy(mp->local_address_stop, src_to.ptr, src_to.len);
        memcpy(mp->remote_address_start, dst_from.ptr, dst_from.len);
        memcpy(mp->remote_address_stop, dst_to.ptr, dst_to.len);
    }
    mp->local_port_start = ntohs(id->src_ts->get_from_port(id->src_ts));
    mp->local_port_stop = ntohs(id->src_ts->get_to_port(id->src_ts));
    mp->remote_port_start = ntohs(id->dst_ts->get_from_port(id->dst_ts));
    mp->remote_port_stop = ntohs(id->dst_ts->get_to_port(id->dst_ts));

    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    if (add)
    {
        ref_get(&spd->policy_num);
    }
    else
    {
        if (ref_put(&spd->policy_num))
        {
            interface_add_del_spd(FALSE, spd->spd_id, spd->sw_if_index);
            manage_bypass(FALSE, spd->spd_id);
            spd_add_del(FALSE, spd->spd_id);
            this->spds->remove(this->spds, id->interface);
        }
    }
    if (this->install_routes && id->dir == POLICY_OUT && !mp->protocol)
    {
        // important !!! we need a route 
        // we may also need to enable promiscuous on input/output interface
        // what about arp ? 
        // set int state ipsec0 up !! also required
        if (data->type == POLICY_IPSEC && data->sa->mode != MODE_TRANSPORT)
        {
            manage_route(this, add, id->dst_ts, data->src, data->dst);
        }
    }
    rv = SUCCESS;
error:
    free(out);
    vl_msg_api_free(mp);
    this->mutex->unlock(this->mutex);
    return rv;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_add_sa_t *data)
{
    sa_t *sa;

    uint16_t vpp_enc_alg;
    uint16_t vpp_int_alg;

    if (data->mode != MODE_TUNNEL)
    {
        return NOT_SUPPORTED;
    }
    
    switch (data->enc_alg)
    {
        case ENCR_NULL:
            vpp_enc_alg = 0;
            break;
        case ENCR_AES_CBC:
            switch (data->enc_key.len * 8)
            {
                case 128:
                    vpp_enc_alg = 1;
                    break;
                case 192:
                    vpp_enc_alg = 2;
                    break;
                case 256:
                    vpp_enc_alg = 3;
                    break;
                default:
                    return FAILED;
            }
            break;
        case ENCR_3DES:
            vpp_enc_alg = 4;
            break;
        default:
            DBG1(DBG_KNL, "algorithm %N not supported by VPP!",
                 encryption_algorithm_names, data->enc_alg);
            return FAILED;
    }

    switch (data->int_alg)
    {
        case AUTH_UNDEFINED:
            vpp_int_alg = 0;
            break;
        case AUTH_HMAC_MD5_96:
            vpp_int_alg = 1;
            break;
        case AUTH_HMAC_SHA1_96:
            vpp_int_alg = 2;
            break;
        case AUTH_HMAC_SHA2_256_128:
            vpp_int_alg = 4;
            break;
        case AUTH_HMAC_SHA2_384_192:
            vpp_int_alg = 5;
            break;
        case AUTH_HMAC_SHA2_512_256:
            vpp_int_alg = 6;
            break;
        default:
            DBG1(DBG_KNL, "algorithm %N not supported by VPP!",
                 integrity_algorithm_names, data->int_alg);
            return FAILED;
    }

    this->mutex->lock(this->mutex);
    INIT(sa,
            // TODO: test if reqid is uniquely matched to policy
            .reqid = data->reqid,
            .spi = id->spi,
            .vpp_enc_alg = vpp_enc_alg,
            .vpp_int_alg = vpp_int_alg,
            .enc_key = enc_key,
            .int_key = int_key);
    this->sad->put(this->sad, data->reqid, sa);
    this->mutex->unlock(this->mutex);

    return SUCCESS;
}

// TODO: this has to be tested we don't know if the ipsec tunnel supports
// such vpp binary api message (if those counters are there)
// it looks like separate thing
METHOD(kernel_ipsec_t, query_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
    time_t *time)
{
    return NOT_SUPPORTED;
  /*
    char *out = NULL;
    int out_len;
    vl_api_ipsec_sa_dump_t *mp;
    vl_api_ipsec_sa_details_t *rmp;
    status_t rv = FAILED;
    sa_t *sa;

    this->mutex->lock(this->mutex);
    // ??
    sa = this->sas->get(this->sas, id);
    this->mutex->unlock(this->mutex);
    if (!sa)
    {
        DBG1(DBG_KNL, "SA not found");
        return NOT_FOUND;
    }
    mp = vl_msg_api_alloc(sizeof(*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SA_DUMP);
    mp->sa_id = ntohl(sa->sa_id);
    if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac SA dump failed");
        goto error;
    }
    if (!out_len)
    {
        DBG1(DBG_KNL, "SA ID %d no data", sa->sa_id);
        rv = NOT_FOUND;
        goto error;
    }
    rmp = (void*)out;

    if (bytes)
    {
        *bytes = htonll(rmp->total_data_size);
    }
    if (packets)
    {
        *packets = 0;
    }
    if (time)
    {
        *time = 0;
    }
    rv = SUCCESS;
error:
    free(out);
    vl_msg_api_free(mp);
    return rv; */
}

METHOD(kernel_ipsec_t, add_policy, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
    kernel_ipsec_manage_policy_t *data)
{
    return NOT_SUPPORTED;
    //return manage_policy(this, TRUE, id, data);
}

METHOD(kernel_ipsec_t, del_policy, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
    kernel_ipsec_manage_policy_t *data)
{
    return NOT_SUPPORTED;
    //return manage_policy(this, FALSE, id, data);
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
    private_kernel_vpp_ipsec_t *this)
{
    return KERNEL_ESP_V3_TFC;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
    private_kernel_vpp_ipsec_t *this, host_t *src, host_t *dst,
    uint8_t protocol, uint32_t *spi)
{
    static const u_int p = 268435399, offset = 0xc0000000;

    *spi = htonl(offset + permute(ref_get(&this->nextspi) ^ this->mixspi, p));
    return SUCCESS;
}

// TODO: design implementation
// we only accept atomic operation
// on all 4s so if you request to delete
// both associations and both policies
// we will send delete
METHOD(kernel_ipsec_t, del_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_del_sa_t *data)
{
    return FALSE;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
    private_kernel_vpp_ipsec_t *this, host_t *src, host_t *dst,
    uint16_t *cpi)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_update_sa_t *data)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
    private_kernel_vpp_ipsec_t *this)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
    kernel_ipsec_query_policy_t *data, time_t *use_time)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
    private_kernel_vpp_ipsec_t *this)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
    private_kernel_vpp_ipsec_t *this, int fd, int family)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
    private_kernel_vpp_ipsec_t *this, int fd, int family, u_int16_t port)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, destroy, void,
    private_kernel_vpp_ipsec_t *this)
{
    this->mutex->destroy(this->mutex);
    this->sas->destroy(this->sas);
    this->spds->destroy(this->spds);
    this->routes->destroy(this->routes);
    free(this);
}

kernel_vpp_ipsec_t *kernel_vpp_ipsec_create()
{
    private_kernel_vpp_ipsec_t *this;

    INIT(this,
        .public = {
            .interface = {
                .get_features = _get_features,
                .get_spi = _get_spi,
                .get_cpi = _get_cpi,
                .add_sa  = _add_sa,
                .update_sa = _update_sa,
                .query_sa = _query_sa,
                .del_sa = _del_sa,
                .flush_sas = _flush_sas,
                .add_policy = _add_policy,
                .query_policy = _query_policy,
                .del_policy = _del_policy,
                .flush_policies = _flush_policies,
                .bypass_socket = _bypass_socket,
                .enable_udp_decap = _enable_udp_decap,
                .destroy = _destroy,
            },
        },
        .mutex = mutex_create(MUTEX_TYPE_DEFAULT),

        .sad = hashtable_create((hashtable_hash_t)sa_hash,
                                (hashtable_equals_t)sa_equals, 32),

        .spd = hashtable_create((hashtable_hash_t)interface_hash,
                                 (hashtable_equals_t)interface_equals, 4),

        .routes = linked_list_create(),
        .install_routes = lib->settings->get_bool(lib->settings,
                            "%s.install_routes", TRUE, lib->ns),
    );

    if (!init_spi(this))
    {
        destroy(this);
        return NULL;
    }

    return &this->public;
}
