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

typedef enum {
  ADD_ROUTES,
  DEL_ROUTES
} routes_op_e;

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
     * Hash table containing cache of Security Association Entries
     */
    hashtable_t *sad;

    /**
     * Linked list of created ipsec tunnels
     */
    hashtable_t *tunnels;

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
    bool manage_routes;
};

/**
 * Security association entry
 */
typedef struct {

    /**
     * unique request ID (2xSA + SP)
     */
    uint32_t reqid;

    /**
     * SPI
     */
    uint32_t spi;

    /**
     * VPP Encryption algorithm
     */
    uint16_t vpp_enc_alg;

    /**
     * Encryption key
     */
    chunk_t enc_key;

    /**
     * VPP Integrity Protection algorithm
     */
    uint16_t vpp_int_alg;

    /**
     * Integrity protection key
     */
    chunk_t int_key;

} sa_t;

/**
 */
typedef struct {

    /**
     * Name of the ipsec tunnel interface
     */
    char *if_name;

    /**
     * Index of the ipsec tunnel interface
     */
    uint32_t sw_if_index;

    /**
     * SPI
     */
    uint32_t src_spi;

    /**
     * Source address
     */
    host_t *src_addr;

    /**
     * SPI
     */
    uint32_t dst_spi;

    /**
     * Destination address
     */
    host_t *dst_addr;

} tunnel_t;

/**
 * Hash function for IPsec Tunnel Interface
 */
static u_int tunnel_hash(ipsec_sa_id_t *sa)
{
    return chunk_hash_inc(sa->dst->get_address(sa->dst),
                          chunk_from_thing(sa->spi));
}

// we don't really need this !
/**
 * Equality function for IPsec Tunnel Interface
 */
static bool tunnel_equals(tunnel_t *one, tunnel_t *two)
{
    return one->src_addr->ip_equals(one->src_addr, two->src_addr) &&
           one->dst_addr->ip_equals(one->dst_addr, two->dst_addr) &&
           one->src_spi == two->src_spi && one->dst_spi == two->dst_spi;;
}

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

/**
 * Add or remove a routes
 */
static status_t manage_routes(private_kernel_vpp_ipsec_t *this,
                              kernel_ipsec_policy_id_t *id,
                              kernel_ipsec_manage_policy_t *data,
                              routes_op_e op)
{
    status_t rv = FAILED;
    uint8_t prefixlen;
    host_t *dst_net;
    host_t *gateway; // do we need this ?
    char *if_name; // do we need this ?

    // REVIEW: logic - add routes only if we support it

    if ((data-type != POLICY_IPSEC) || !data->sa)
    {
        return NOT_SUPPORTED;
    }

    if (data->sa->mode != MODE_TUNNEL)
    {
        return NOT_SUPPORTED;
    }

    // change this!
    this->mutex->lock(this->mutex);
    tunnel = this->tunnels->get(this->tunnels,
                                (void *)(uintptr_t)data->sa->reqid);
    if (!tunnel)
    {
        // tunnel is missing we won't add routes WHY would we ?
        DBG1(DBG_KNL, "tunnel missing");
        goto error;
    }

    // we only care about POLICY_OUT routes
    if (this->manage_routes && (id->dir == POLICY_OUT))
    {

      // WHY ? WHY ? (and non fatal also in the previous code)
      if (data->dst->is_anyaddr(dst))
      {
          goto error;
      }

      id->dst_ts->to_subnet(id->dst_ts, &dst_net, &prefixlen);

      gateway = charon->kernel->get_nexthop(charon->kernel, data->dst, -1, NULL, &if_name);

      // REVIEW:
      // cache routes so we don't do extra calls ??
      // we may not need to store any data locally
      // if we don't care about the extra calls

      // it was cached previously and it did not return
      // any kind of status so ..

      // as stated in the source code doc:
      // kernel_ipsec_manage_policy_t dst is 
      // Destination address of the SA(s) tied to this policy
      // so we know it is the same we don't need to store it

      // TODO: gateway IP address may not be physical interface IP !
      // it may be tunnel interface IP address
      // TODO: if_name is for sure not ipsec interface

      if (op == ADD_ROUTES)
      {
        
        DBG2(DBG_NKL, "add route %H/%d via %H on dev %s",
             dst_net, prefixlen, gateway, tunnel->if_name);

        // TODO: should we process response of this operation ?
        charon->kernel->add_route(charon->kernel,
            dst_net->get_address(dst_net), prefixlen, 
            data->dst, NULL, tunnel->if_name);
      }
      else
      {
        DBG2(DBG_NKL, "del route %H/%d via %H on dev %s",
             dst_net, prefixlen, gateway, tunnel->if_name);

        // TODO: should we process response of this operation ?
        charon->kernel->del_route(charon->kernel,
            dst_net->get_address(dst_net), prefixlen,
            data->dst, NULL, tunnel->if_name);
      }
    }
      
    rv = SUCCESS;
error:
    this->mutex->unlock(this->mutex);
    return rv;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_add_sa_t *data)
{
    tunnel_t *tun;
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

    // inbound comes first
    if (data->inbound)
    {
        INIT(sa,
              .reqid = data->reqid,
              .spi = id->spi,
              .vpp_enc_alg = vpp_enc_alg,
              .vpp_int_alg = vpp_int_alg,
              .enc_key = enc_key,
              .int_key = int_key);

        // reqid is unique for each entry (2xSA + SP)
        this->mutex->lock(this->mutex);
        this->sad->put(this->sad, (void *)(uintptr_t)data->reqid, sa); // typecast?
        this->mutex->unlock(this->mutex);
    }
    else
    {
        this->mutex->lock(this->mutex);
        sa = this->sad->remove(this->sad, (void *)(uintptr_t)data->reqid); // typecast?
        this->mutex->unlock(this->mutex);

        if (!sa)
        {
            DBG1(DBG_KNL, "adding outbound SA failed, missing inbound SA");
            return NOT_FOUND;
        }

        // TODO: get interface name + interface index (maybe needed)

        // TODO: hope these values are not twisted :)
        INIT(tun,
               .if_name = NULL; // we need this
               .sw_if_index = 0; // we may need this
               .src_spi = sa->spi,
               .src_addr = id->src,
               .dst_spi = id->spi,
               .dst_addr = id->dst);

        free(sa);

        // hash based on outbound

        kernel_ipsec_sa_id_t _id = {
                  .dst = data->dst,
                  .spi = data->sa->esp.spi
        };

        this->mutex->lock(this->mutex);
        this->tunnels->put(this->tunnels, &_id, tun);
        this->mutex->unlock(this->mutex);

        // TODO: convert values based on the requirements in the proto file
        /* extracting keys !!
         * this is just reference:

        // crypto key
        mp->crypto_algorithm = enc_alg;
        mp->crypto_key_length = data->enc_key.len;
        memcpy(mp->crypto_key, data->enc_key.ptr, data->enc_key.len);

        // integrity key
        mp->integrity_algorithm = ia;
        mp->integrity_key_length = data->int_key.len;
        memcpy(mp->integrity_key, data->int_key.ptr, data->int_key.len);
        */

        // promiscuous enable ?
        // what about arp ? 
        // set ipsec interface up ?
        // set interface to unnumbered (based on src IP adress)
        //  - get local interface based on src IP address then set unnumbered
        //    for the tunnel interface (to join with the "physical interface")
        // dump all tunnel interfaces, get ID of the tunnel interface !
 
        // TODO: send grpc call (create tunnel) if ok save tunnel in memory reg
    }

    return SUCCESS;
}

// TODO: the same logic as with the add_sa
// wait for outbound i guess (match it to the ipsec tunnel)
// - we won't be able to match based on the reqid
// - i am not sure about this but this is deffinitely new request
// - we could match based on OUTPUT/INPUT SPI somehow this may be
//  unique, most definitelly this is unique for specific destination
//  address so (destination SPI + destination IP) is a good unique
//  combo that could make it possible to lookup tunnel registration
//  in tunnel table
//
//  kluc je teda DST SPI + DST ADDRESS
METHOD(kernel_ipsec_t, del_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_del_sa_t *data)
{
    return FALSE;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
    kernel_ipsec_manage_policy_t *data)
{
    return manage_routes(this, id, data, ADD_ROUTES);
}

METHOD(kernel_ipsec_t, del_policy, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
    kernel_ipsec_manage_policy_t *data)
{
    return manage_routes(this, id, data, DEL_ROUTES);
}

// TODO: grpc vpp-agent return counters from tunnel interface
METHOD(kernel_ipsec_t, query_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
    time_t *time)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
    private_kernel_vpp_ipsec_t *this)
{
    return KERNEL_ESP_V3_TFC;
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

METHOD(kernel_ipsec_t, get_spi, status_t,
    private_kernel_vpp_ipsec_t *this, host_t *src, host_t *dst,
    uint8_t protocol, uint32_t *spi)
{
    static const u_int p = 268435399, offset = 0xc0000000;

    *spi = htonl(offset + permute(ref_get(&this->nextspi) ^ this->mixspi, p));
    return SUCCESS;
}

METHOD(kernel_ipsec_t, destroy, void,
    private_kernel_vpp_ipsec_t *this)
{
    this->mutex->destroy(this->mutex);
    this->routes->destroy(this->routes);
    this->sad->destroy(this->sad);
    free(this);
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
        // TODO: test if hashtable_has_ptr is suitable for us !!
        .sad = hashtable_create(hashtable_hash_ptr, hashtable_equals_ptr, 4),
        // we can reuse this hash for both in and out registration of (SPI + IP)
        .tunnels = hashtable_create((hashtable_hash_t)tunnel_hash,
                                      (hashtable_equals_t)tunnel_equals, 32),
        .routes = linked_list_create(),
        .manage_routes = lib->settings->get_bool(lib->settings,
                            "%s.install_routes", TRUE, lib->ns),
    );

    if (!init_spi(this))
    {
        destroy(this);
        return NULL;
    }

    return &this->public;
}
