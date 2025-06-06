/*
 * Copyright (c) 2009-2017 Nicira, Inc.
 * Copyright (c) 2016 Mellanox Technologies, Ltd.
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

#include <config.h>
#include "tc.h"

#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <linux/tc_act/tc_csum.h>
#include <linux/tc_act/tc_gact.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/tc_act/tc_mpls.h>
#include <linux/tc_act/tc_pedit.h>
#include <linux/tc_act/tc_skbedit.h>
#include <linux/tc_act/tc_tunnel_key.h>
#include <linux/tc_act/tc_vlan.h>
#include <linux/tc_act/tc_ct.h>
#include <linux/gen_stats.h>
#include <net/if.h>
#include <unistd.h>

#include "byte-order.h"
#include "coverage.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "odp-util.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "timeval.h"
#include "unaligned.h"

#define MAX_PEDIT_OFFSETS 32

#ifndef TCM_IFINDEX_MAGIC_BLOCK
#define TCM_IFINDEX_MAGIC_BLOCK (0xFFFFFFFFU)
#endif

#ifndef TCA_DUMP_FLAGS_TERSE
#define TCA_DUMP_FLAGS_TERSE (1 << 0)
#endif

#if TCA_MAX < 15
#define TCA_CHAIN 11
#define TCA_INGRESS_BLOCK 13
#define TCA_DUMP_FLAGS 15
#endif

#ifndef RTM_GETCHAIN
#define RTM_GETCHAIN 102
#endif

VLOG_DEFINE_THIS_MODULE(tc);

COVERAGE_DEFINE(tc_netlink_malformed_reply);

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5);

static enum tc_offload_policy tc_policy = TC_POLICY_NONE;

struct tc_pedit_key_ex {
    enum pedit_header_type htype;
    enum pedit_cmd cmd;
};

struct flower_key_to_pedit {
    enum pedit_header_type htype;
    int offset;
    int flower_offset;
    int size;
    int boundary_shift;
};

struct tc_flow_stats {
    uint64_t n_packets;
    uint64_t n_bytes;
};

static struct flower_key_to_pedit flower_pedit_map[] = {
    {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
        12,
        offsetof(struct tc_flower_key, ipv4.ipv4_src),
        MEMBER_SIZEOF(struct tc_flower_key, ipv4.ipv4_src),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
        16,
        offsetof(struct tc_flower_key, ipv4.ipv4_dst),
        MEMBER_SIZEOF(struct tc_flower_key, ipv4.ipv4_dst),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
        8,
        offsetof(struct tc_flower_key, ipv4.rewrite_ttl),
        MEMBER_SIZEOF(struct tc_flower_key, ipv4.rewrite_ttl),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
        1,
        offsetof(struct tc_flower_key, ipv4.rewrite_tos),
        MEMBER_SIZEOF(struct tc_flower_key, ipv4.rewrite_tos),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP6,
        7,
        offsetof(struct tc_flower_key, ipv6.rewrite_hlimit),
        MEMBER_SIZEOF(struct tc_flower_key, ipv6.rewrite_hlimit),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP6,
        8,
        offsetof(struct tc_flower_key, ipv6.ipv6_src),
        MEMBER_SIZEOF(struct tc_flower_key, ipv6.ipv6_src),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP6,
        24,
        offsetof(struct tc_flower_key, ipv6.ipv6_dst),
        MEMBER_SIZEOF(struct tc_flower_key, ipv6.ipv6_dst),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_IP6,
        0,
        offsetof(struct tc_flower_key, ipv6.rewrite_tclass),
        MEMBER_SIZEOF(struct tc_flower_key, ipv6.rewrite_tclass),
        4
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
        6,
        offsetof(struct tc_flower_key, src_mac),
        MEMBER_SIZEOF(struct tc_flower_key, src_mac),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
        0,
        offsetof(struct tc_flower_key, dst_mac),
        MEMBER_SIZEOF(struct tc_flower_key, dst_mac),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
        12,
        offsetof(struct tc_flower_key, eth_type),
        MEMBER_SIZEOF(struct tc_flower_key, eth_type),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_TCP,
        0,
        offsetof(struct tc_flower_key, tcp_src),
        MEMBER_SIZEOF(struct tc_flower_key, tcp_src),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_TCP,
        2,
        offsetof(struct tc_flower_key, tcp_dst),
        MEMBER_SIZEOF(struct tc_flower_key, tcp_dst),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_UDP,
        0,
        offsetof(struct tc_flower_key, udp_src),
        MEMBER_SIZEOF(struct tc_flower_key, udp_src),
        0
    }, {
        TCA_PEDIT_KEY_EX_HDR_TYPE_UDP,
        2,
        offsetof(struct tc_flower_key, udp_dst),
        MEMBER_SIZEOF(struct tc_flower_key, udp_dst),
        0
    },
};

static inline int
csum_update_flag(struct tc_flower *flower,
                 enum pedit_header_type htype);

struct tcmsg *
tc_make_request(int ifindex, int type, unsigned int flags,
                struct ofpbuf *request)
{
    struct tcmsg *tcmsg;

    ofpbuf_init(request, 512);
    nl_msg_put_nlmsghdr(request, sizeof *tcmsg, type, NLM_F_REQUEST | flags);
    tcmsg = ofpbuf_put_zeros(request, sizeof *tcmsg);
    tcmsg->tcm_family = AF_UNSPEC;
    tcmsg->tcm_ifindex = ifindex;
    /* Caller should fill in tcmsg->tcm_handle. */
    /* Caller should fill in tcmsg->tcm_parent. */

    return tcmsg;
}

struct tcamsg *
tc_make_action_request(int type, unsigned int flags,
                       struct ofpbuf *request)
{
    struct tcamsg *tcamsg;

    ofpbuf_init(request, 512);
    nl_msg_put_nlmsghdr(request, sizeof *tcamsg, type, NLM_F_REQUEST | flags);
    tcamsg = ofpbuf_put_zeros(request, sizeof *tcamsg);
    tcamsg->tca_family = AF_UNSPEC;

    return tcamsg;
}

static void request_from_tcf_id(struct tcf_id *id, uint16_t eth_type,
                                int type, unsigned int flags,
                                struct ofpbuf *request)
{
    int ifindex = id->block_id ? TCM_IFINDEX_MAGIC_BLOCK : id->ifindex;
    uint32_t ingress_parent = id->block_id ? : TC_INGRESS_PARENT;
    struct tcmsg *tcmsg;

    tcmsg = tc_make_request(ifindex, type, flags, request);
    tcmsg->tcm_parent = (id->hook == TC_EGRESS) ?
                        TC_EGRESS_PARENT : ingress_parent;
    tcmsg->tcm_info = tc_make_handle(id->prio, eth_type);
    tcmsg->tcm_handle = id->handle;

    if (id->chain) {
        nl_msg_put_u32(request, TCA_CHAIN, id->chain);
    }
}

int
tc_transact(struct ofpbuf *request, struct ofpbuf **replyp)
{
    int error = nl_transact(NETLINK_ROUTE, request, replyp);
    ofpbuf_uninit(request);
    return error;
}

/* Adds or deletes a root qdisc on device with specified ifindex.
 *
 * The tc_qdisc_hook parameter determines if the qdisc is added on device
 * ingress or egress.
 *
 * If tc_qdisc_hook is TC_INGRESS, this function is equivalent to running the
 * following when 'add' is true:
 *     /sbin/tc qdisc add dev <devname> handle ffff: ingress
 *
 * This function is equivalent to running the following when 'add' is false:
 *     /sbin/tc qdisc del dev <devname> handle ffff: ingress
 *
 * If tc_qdisc_hook is TC_EGRESS, this function is equivalent to:
 *     /sbin/tc qdisc (add|del) dev <devname> handle ffff: clsact
 *
 * Where dev <devname> is the device with specified ifindex name.
 *
 * The configuration and stats may be seen with the following command:
 *     /sbin/tc -s qdisc show dev <devname>
 *
 * If block_id is greater than 0, then the ingress qdisc is added to a block.
 * In this case, it is equivalent to running (when 'add' is true):
 *     /sbin/tc qdisc add dev <devname> ingress_block <block_id> ingress
 *
 * Returns 0 if successful, otherwise a positive errno value.
 */
int
tc_add_del_qdisc(int ifindex, bool add, uint32_t block_id,
                 enum tc_qdisc_hook hook)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;
    int error;
    int type = add ? RTM_NEWQDISC : RTM_DELQDISC;
    int flags = add ? NLM_F_EXCL | NLM_F_CREATE : 0;

    tcmsg = tc_make_request(ifindex, type, flags, &request);

    if (hook == TC_EGRESS) {
        tcmsg->tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
        tcmsg->tcm_parent = TC_H_CLSACT;
        nl_msg_put_string(&request, TCA_KIND, "clsact");
    } else {
        tcmsg->tcm_handle = TC_H_MAKE(TC_H_INGRESS, 0);
        tcmsg->tcm_parent = TC_H_INGRESS;
        nl_msg_put_string(&request, TCA_KIND, "ingress");
    }

    nl_msg_put_unspec(&request, TCA_OPTIONS, NULL, 0);
    if (hook == TC_INGRESS && block_id) {
        nl_msg_put_u32(&request, TCA_INGRESS_BLOCK, block_id);
    }

    error = tc_transact(&request, NULL);
    if (error) {
        /* If we're deleting the qdisc, don't worry about some of the
         * error conditions. */
        if (!add && (error == ENOENT || error == EINVAL)) {
            return 0;
        }
        return error;
    }

    return 0;
}

static const struct nl_policy tca_policy[] = {
    [TCA_KIND] = { .type = NL_A_STRING, .optional = false, },
    [TCA_OPTIONS] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_CHAIN] = { .type = NL_A_U32, .optional = true, },
    [TCA_STATS] = { .type = NL_A_UNSPEC,
                    .min_len = sizeof(struct tc_stats), .optional = true, },
    [TCA_STATS2] = { .type = NL_A_NESTED, .optional = true, },
};

static const struct nl_policy tca_chain_policy[] = {
    [TCA_CHAIN] = { .type = NL_A_U32, .optional = false, },
};

static const struct nl_policy tca_flower_policy[] = {
    [TCA_FLOWER_CLASSID] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_INDEV] = { .type = NL_A_STRING, .max_len = IFNAMSIZ,
                           .optional = true, },
    [TCA_FLOWER_KEY_ETH_SRC] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN, .optional = true, },
    [TCA_FLOWER_KEY_ETH_DST] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN, .optional = true, },
    [TCA_FLOWER_KEY_ETH_SRC_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ETH_DST_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ETH_TYPE] = { .type = NL_A_U16, .optional = false, },
    [TCA_FLOWER_KEY_ARP_SIP] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ARP_TIP] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ARP_SHA] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN,
                                 .optional = true, },
    [TCA_FLOWER_KEY_ARP_THA] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN,
                                 .optional = true, },
    [TCA_FLOWER_KEY_ARP_OP] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_ARP_SIP_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ARP_TIP_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ARP_SHA_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ARP_THA_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ARP_OP_MASK] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_FLAGS] = { .type = NL_A_U32, .optional = false, },
    [TCA_FLOWER_ACT] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_FLOWER_KEY_IP_PROTO] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_SRC] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_DST] = {.type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_SRC_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_DST_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV6_SRC] = { .type = NL_A_UNSPEC,
                                  .min_len = sizeof(struct in6_addr),
                                  .optional = true, },
    [TCA_FLOWER_KEY_IPV6_DST] = { .type = NL_A_UNSPEC,
                                  .min_len = sizeof(struct in6_addr),
                                  .optional = true, },
    [TCA_FLOWER_KEY_IPV6_SRC_MASK] = { .type = NL_A_UNSPEC,
                                       .min_len = sizeof(struct in6_addr),
                                       .optional = true, },
    [TCA_FLOWER_KEY_IPV6_DST_MASK] = { .type = NL_A_UNSPEC,
                                       .min_len = sizeof(struct in6_addr),
                                       .optional = true, },
    [TCA_FLOWER_KEY_TCP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_MPLS_TTL] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_MPLS_TC] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_MPLS_BOS] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_MPLS_LABEL] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_ID] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_PRIO] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_ETH_TYPE] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_ENC_KEY_ID] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_SRC] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_DST] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK] = { .type = NL_A_U32,
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_DST_MASK] = { .type = NL_A_U32,
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_SRC] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_DST] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK] = { .type = NL_A_UNSPEC,
                                           .min_len = sizeof(struct in6_addr),
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_DST_MASK] = { .type = NL_A_UNSPEC,
                                           .min_len = sizeof(struct in6_addr),
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_UDP_SRC_PORT] = { .type = NL_A_U16,
                                          .optional = true, },
    [TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK] = { .type = NL_A_U16,
                                               .optional = true, },
    [TCA_FLOWER_KEY_ENC_UDP_DST_PORT] = { .type = NL_A_U16,
                                          .optional = true, },
    [TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK] = { .type = NL_A_U16,
                                               .optional = true, },
    [TCA_FLOWER_KEY_FLAGS] = { .type = NL_A_BE32, .optional = true, },
    [TCA_FLOWER_KEY_FLAGS_MASK] = { .type = NL_A_BE32, .optional = true, },
    [TCA_FLOWER_KEY_IP_TTL] = { .type = NL_A_U8,
                                .optional = true, },
    [TCA_FLOWER_KEY_IP_TTL_MASK] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_IP_TOS] = { .type = NL_A_U8,
                                .optional = true, },
    [TCA_FLOWER_KEY_IP_TOS_MASK] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_TCP_FLAGS] = { .type = NL_A_U16,
                                   .optional = true, },
    [TCA_FLOWER_KEY_TCP_FLAGS_MASK] = { .type = NL_A_U16,
                                        .optional = true, },
    [TCA_FLOWER_KEY_CVLAN_ID] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_CVLAN_PRIO] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_CVLAN_ETH_TYPE] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IP_TOS] = { .type = NL_A_U8,
                                    .optional = true, },
    [TCA_FLOWER_KEY_ENC_IP_TOS_MASK] = { .type = NL_A_U8,
                                         .optional = true, },
    [TCA_FLOWER_KEY_ENC_IP_TTL] = { .type = NL_A_U8,
                                    .optional = true, },
    [TCA_FLOWER_KEY_ENC_IP_TTL_MASK] = { .type = NL_A_U8,
                                         .optional = true, },
    [TCA_FLOWER_KEY_ENC_OPTS] = { .type = NL_A_NESTED, .optional = true, },
    [TCA_FLOWER_KEY_ENC_OPTS_MASK] = { .type = NL_A_NESTED,
                                       .optional = true, },
    [TCA_FLOWER_KEY_CT_STATE] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_CT_STATE_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_CT_ZONE] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_CT_ZONE_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_CT_MARK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_CT_MARK_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_CT_LABELS] = { .type = NL_A_U128, .optional = true, },
    [TCA_FLOWER_KEY_CT_LABELS_MASK] = { .type = NL_A_U128,
                                        .optional = true, },
    [TCA_FLOWER_KEY_ICMPV4_CODE] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_ICMPV4_CODE_MASK] = { .type = NL_A_U8,
                                          .optional = true, },
    [TCA_FLOWER_KEY_ICMPV4_TYPE] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_ICMPV4_TYPE_MASK] = { .type = NL_A_U8,
                                          .optional = true, },
    [TCA_FLOWER_KEY_ICMPV6_CODE] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_ICMPV6_CODE_MASK] = { .type = NL_A_U8,
                                          .optional = true, },
    [TCA_FLOWER_KEY_ICMPV6_TYPE] = { .type = NL_A_U8,
                                     .optional = true, },
    [TCA_FLOWER_KEY_ICMPV6_TYPE_MASK] = { .type = NL_A_U8,
                                          .optional = true, },
};

static const struct nl_policy tca_flower_terse_policy[] = {
    [TCA_FLOWER_FLAGS] = { .type = NL_A_U32, .optional = false, },
    [TCA_FLOWER_ACT] = { .type = NL_A_NESTED, .optional = false, },
};

static void
nl_parse_flower_arp(struct nlattr **attrs, struct tc_flower *flower)
{
    const struct eth_addr *eth;

    if (attrs[TCA_FLOWER_KEY_ARP_SIP_MASK]) {
        flower->key.arp.spa =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ARP_SIP]);
        flower->mask.arp.spa =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ARP_SIP_MASK]);
    }
    if (attrs[TCA_FLOWER_KEY_ARP_TIP_MASK]) {
        flower->key.arp.tpa =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ARP_TIP]);
        flower->mask.arp.tpa =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ARP_TIP_MASK]);
    }
    if (attrs[TCA_FLOWER_KEY_ARP_SHA_MASK]) {
        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ARP_SHA], ETH_ALEN);
        memcpy(&flower->key.arp.sha, eth, sizeof flower->key.arp.sha);

        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ARP_SHA_MASK], ETH_ALEN);
        memcpy(&flower->mask.arp.sha, eth, sizeof flower->mask.arp.sha);
    }
    if (attrs[TCA_FLOWER_KEY_ARP_THA_MASK]) {
        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ARP_THA], ETH_ALEN);
        memcpy(&flower->key.arp.tha, eth, sizeof flower->key.arp.tha);

        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ARP_THA_MASK], ETH_ALEN);
        memcpy(&flower->mask.arp.tha, eth, sizeof flower->mask.arp.tha);
    }
    if (attrs[TCA_FLOWER_KEY_ARP_OP_MASK]) {
        flower->key.arp.opcode =
            nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ARP_OP]);
        flower->mask.arp.opcode =
            nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ARP_OP_MASK]);
    }
}

static void
nl_parse_flower_eth(struct nlattr **attrs, struct tc_flower *flower)
{
    const struct eth_addr *eth;

    if (attrs[TCA_FLOWER_KEY_ETH_SRC_MASK]) {
        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_SRC], ETH_ALEN);
        memcpy(&flower->key.src_mac, eth, sizeof flower->key.src_mac);

        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_SRC_MASK], ETH_ALEN);
        memcpy(&flower->mask.src_mac, eth, sizeof flower->mask.src_mac);
    }
    if (attrs[TCA_FLOWER_KEY_ETH_DST_MASK]) {
        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_DST], ETH_ALEN);
        memcpy(&flower->key.dst_mac, eth, sizeof flower->key.dst_mac);

        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_DST_MASK], ETH_ALEN);
        memcpy(&flower->mask.dst_mac, eth, sizeof flower->mask.dst_mac);
    }
}

static void
nl_parse_flower_mpls(struct nlattr **attrs, struct tc_flower *flower)
{
    uint8_t ttl, tc, bos;
    uint32_t label;

    if (!eth_type_mpls(flower->key.eth_type)) {
        return;
    }

    flower->key.encap_eth_type[0] =
        nl_attr_get_be16(attrs[TCA_FLOWER_KEY_ETH_TYPE]);
    flower->key.mpls_lse = 0;
    flower->mask.mpls_lse = 0;

    if (attrs[TCA_FLOWER_KEY_MPLS_TTL]) {
        ttl = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_MPLS_TTL]);
        set_mpls_lse_ttl(&flower->key.mpls_lse, ttl);
        set_mpls_lse_ttl(&flower->mask.mpls_lse, 0xff);
    }

    if (attrs[TCA_FLOWER_KEY_MPLS_BOS]) {
        bos = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_MPLS_BOS]);
        set_mpls_lse_bos(&flower->key.mpls_lse, bos);
        set_mpls_lse_bos(&flower->mask.mpls_lse, 0xff);
    }

    if (attrs[TCA_FLOWER_KEY_MPLS_TC]) {
        tc = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_MPLS_TC]);
        set_mpls_lse_tc(&flower->key.mpls_lse, tc);
        set_mpls_lse_tc(&flower->mask.mpls_lse, 0xff);
    }

    if (attrs[TCA_FLOWER_KEY_MPLS_LABEL]) {
        label = nl_attr_get_u32(attrs[TCA_FLOWER_KEY_MPLS_LABEL]);
        set_mpls_lse_label(&flower->key.mpls_lse, htonl(label));
        set_mpls_lse_label(&flower->mask.mpls_lse, OVS_BE32_MAX);
    }
}

static void
nl_parse_flower_vlan(struct nlattr **attrs, struct tc_flower *flower)
{
    ovs_be16 encap_ethtype;

    if (!eth_type_vlan(flower->key.eth_type)) {
        return;
    }

    flower->key.encap_eth_type[0] =
        nl_attr_get_be16(attrs[TCA_FLOWER_KEY_ETH_TYPE]);
    flower->mask.encap_eth_type[0] = CONSTANT_HTONS(0xffff);

    if (attrs[TCA_FLOWER_KEY_VLAN_ID]) {
        flower->key.vlan_id[0] =
            nl_attr_get_u16(attrs[TCA_FLOWER_KEY_VLAN_ID]);
        flower->mask.vlan_id[0] = VLAN_VID_MASK >> VLAN_VID_SHIFT;
    }
    if (attrs[TCA_FLOWER_KEY_VLAN_PRIO]) {
        flower->key.vlan_prio[0] =
            nl_attr_get_u8(attrs[TCA_FLOWER_KEY_VLAN_PRIO]);
        flower->mask.vlan_prio[0] = VLAN_PCP_MASK >> VLAN_PCP_SHIFT;
    }

    if (!attrs[TCA_FLOWER_KEY_VLAN_ETH_TYPE]) {
        return;
    }

    encap_ethtype = nl_attr_get_be16(attrs[TCA_FLOWER_KEY_VLAN_ETH_TYPE]);
    if (!eth_type_vlan(encap_ethtype)) {
        return;
    }

    flower->key.encap_eth_type[1] = flower->key.encap_eth_type[0];
    flower->mask.encap_eth_type[1] = CONSTANT_HTONS(0xffff);
    flower->key.encap_eth_type[0] = encap_ethtype;

    if (attrs[TCA_FLOWER_KEY_CVLAN_ID]) {
        flower->key.vlan_id[1] =
            nl_attr_get_u16(attrs[TCA_FLOWER_KEY_CVLAN_ID]);
        flower->mask.vlan_id[1] = VLAN_VID_MASK >> VLAN_VID_SHIFT;
    }
    if (attrs[TCA_FLOWER_KEY_CVLAN_PRIO]) {
        flower->key.vlan_prio[1] =
            nl_attr_get_u8(attrs[TCA_FLOWER_KEY_CVLAN_PRIO]);
        flower->mask.vlan_prio[1] = VLAN_PCP_MASK >> VLAN_PCP_SHIFT;
    }
}

static int
nl_parse_geneve_key(const struct nlattr *in_nlattr,
                    struct tun_metadata *metadata)
{
    struct geneve_opt *opt = NULL;
    const struct ofpbuf *msg;
    uint16_t last_opt_type;
    struct nlattr *nla;
    struct ofpbuf buf;
    size_t left;
    int cnt;

    nl_attr_get_nested(in_nlattr, &buf);
    msg = &buf;

    last_opt_type = TCA_FLOWER_KEY_ENC_OPT_GENEVE_UNSPEC;
    cnt = 0;
    NL_ATTR_FOR_EACH (nla, left, ofpbuf_at(msg, 0, 0), msg->size) {
        uint16_t type = nl_attr_type(nla);

        switch (type) {
        case TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS:
            if (cnt && last_opt_type != TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA) {
                VLOG_ERR_RL(&error_rl, "failed to parse tun options class");
                return EINVAL;
            }

            opt = &metadata->opts.gnv[cnt];
            opt->opt_class = nl_attr_get_be16(nla);
            cnt += sizeof(struct geneve_opt) / 4;
            metadata->present.len += sizeof(struct geneve_opt);
            last_opt_type = TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS;
            break;
        case TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE:
            if (last_opt_type != TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS) {
                VLOG_ERR_RL(&error_rl, "failed to parse tun options type");
                return EINVAL;
            }

            opt->type = nl_attr_get_u8(nla);
            last_opt_type = TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE;
            break;
        case TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA:
            if (last_opt_type != TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE) {
                VLOG_ERR_RL(&error_rl, "failed to parse tun options data");
                return EINVAL;
            }

            opt->length = nl_attr_get_size(nla) / 4;
            memcpy(opt + 1, nl_attr_get_unspec(nla, 1), opt->length * 4);
            cnt += opt->length;
            metadata->present.len += opt->length * 4;
            last_opt_type = TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA;
            break;
        }
    }

    if (last_opt_type != TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA) {
        VLOG_ERR_RL(&error_rl, "failed to parse tun options without data");
        return EINVAL;
    }

    return 0;
}

static int
nl_parse_vxlan_key(const struct nlattr *in_nlattr,
                   struct tc_flower_tunnel *tunnel)
{
    const struct ofpbuf *msg;
    struct nlattr *nla;
    struct ofpbuf buf;
    uint32_t gbp_raw;
    size_t left;

    nl_attr_get_nested(in_nlattr, &buf);
    msg = &buf;

    NL_ATTR_FOR_EACH (nla, left, ofpbuf_at(msg, 0, 0), msg->size) {
        uint16_t type = nl_attr_type(nla);

        switch (type) {
        case TCA_FLOWER_KEY_ENC_OPT_VXLAN_GBP:
            gbp_raw = nl_attr_get_u32(nla);
            odp_decode_gbp_raw(gbp_raw, &tunnel->gbp.id,
                               &tunnel->gbp.flags);
            tunnel->gbp.id_present = true;
            break;
        default:
            VLOG_WARN_RL(&error_rl, "failed to parse vxlan tun options");
            return EINVAL;
        }
    }

    return 0;
}

static int
nl_parse_flower_tunnel_opts(struct nlattr *options,
                            struct tc_flower_tunnel *tunnel)
{
    const struct ofpbuf *msg;
    struct nlattr *nla;
    struct ofpbuf buf;
    size_t left;
    int err;

    nl_attr_get_nested(options, &buf);
    msg = &buf;

    NL_ATTR_FOR_EACH (nla, left, ofpbuf_at(msg, 0, 0), msg->size) {
        uint16_t type = nl_attr_type(nla);
        switch (type) {
        case TCA_FLOWER_KEY_ENC_OPTS_GENEVE:
            err = nl_parse_geneve_key(nla, &tunnel->metadata);
            if (err) {
                return err;
            }

            break;
        case TCA_FLOWER_KEY_ENC_OPTS_VXLAN:
            err = nl_parse_vxlan_key(nla, tunnel);
            if (err) {
                return err;
            }

            break;
        }
    }

    return 0;
}

static int
flower_tun_geneve_opt_check_len(struct tun_metadata *key,
                                struct tun_metadata *mask)
{
    const struct geneve_opt *opt, *opt_mask;
    int len, cnt = 0;

    if (key->present.len != mask->present.len) {
        goto bad_length;
    }

    len = key->present.len;
    while (len) {
        opt = &key->opts.gnv[cnt];
        opt_mask = &mask->opts.gnv[cnt];

        if (opt->length != opt_mask->length) {
            goto bad_length;
        }

        cnt += sizeof(struct geneve_opt) / 4 + opt->length;
        len -= sizeof(struct geneve_opt) + opt->length * 4;
    }

    return 0;

bad_length:
    VLOG_ERR_RL(&error_rl,
                "failed to parse tun options; key/mask length differ");
    return EINVAL;
}

static int
nl_parse_flower_tunnel(struct nlattr **attrs, struct tc_flower *flower)
{
    int err;

    if (attrs[TCA_FLOWER_KEY_ENC_KEY_ID]) {
        ovs_be32 id = nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ENC_KEY_ID]);

        flower->key.tunnel.id = be32_to_be64(id);
        flower->mask.tunnel.id = OVS_BE64_MAX;
    }
    if (attrs[TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK]) {
        flower->mask.tunnel.ipv4.ipv4_src =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK]);
        flower->key.tunnel.ipv4.ipv4_src =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ENC_IPV4_SRC]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_IPV4_DST_MASK]) {
        flower->mask.tunnel.ipv4.ipv4_dst =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ENC_IPV4_DST_MASK]);
        flower->key.tunnel.ipv4.ipv4_dst =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ENC_IPV4_DST]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK]) {
        flower->mask.tunnel.ipv6.ipv6_src =
            nl_attr_get_in6_addr(attrs[TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK]);
        flower->key.tunnel.ipv6.ipv6_src =
            nl_attr_get_in6_addr(attrs[TCA_FLOWER_KEY_ENC_IPV6_SRC]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_IPV6_DST_MASK]) {
        flower->mask.tunnel.ipv6.ipv6_dst =
            nl_attr_get_in6_addr(attrs[TCA_FLOWER_KEY_ENC_IPV6_DST_MASK]);
        flower->key.tunnel.ipv6.ipv6_dst =
            nl_attr_get_in6_addr(attrs[TCA_FLOWER_KEY_ENC_IPV6_DST]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK]) {
        flower->mask.tunnel.tp_src =
            nl_attr_get_be16(attrs[TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK]);
        flower->key.tunnel.tp_src =
            nl_attr_get_be16(attrs[TCA_FLOWER_KEY_ENC_UDP_SRC_PORT]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK]) {
        flower->mask.tunnel.tp_dst =
            nl_attr_get_be16(attrs[TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK]);
        flower->key.tunnel.tp_dst =
            nl_attr_get_be16(attrs[TCA_FLOWER_KEY_ENC_UDP_DST_PORT]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_IP_TOS_MASK]) {
        flower->key.tunnel.tos =
            nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ENC_IP_TOS]);
        flower->mask.tunnel.tos =
            nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ENC_IP_TOS_MASK]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_IP_TTL_MASK]) {
        flower->key.tunnel.ttl =
            nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ENC_IP_TTL]);
        flower->mask.tunnel.ttl =
            nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ENC_IP_TTL_MASK]);
    }

    if (!is_all_zeros(&flower->mask.tunnel, sizeof flower->mask.tunnel) ||
        !is_all_zeros(&flower->key.tunnel, sizeof flower->key.tunnel)) {
        flower->tunnel = true;
    }

    if (attrs[TCA_FLOWER_KEY_ENC_OPTS] &&
        attrs[TCA_FLOWER_KEY_ENC_OPTS_MASK]) {
         err = nl_parse_flower_tunnel_opts(attrs[TCA_FLOWER_KEY_ENC_OPTS],
                                           &flower->key.tunnel);
         if (err) {
             return err;
         }

         err = nl_parse_flower_tunnel_opts(attrs[TCA_FLOWER_KEY_ENC_OPTS_MASK],
                                           &flower->mask.tunnel);
         if (err) {
             return err;
         }

         err = flower_tun_geneve_opt_check_len(&flower->key.tunnel.metadata,
                                               &flower->mask.tunnel.metadata);
         if (err) {
             return err;
         }
    } else if (attrs[TCA_FLOWER_KEY_ENC_OPTS]) {
        VLOG_ERR_RL(&error_rl,
                    "failed to parse tun options; no mask supplied");
        return EINVAL;
    } else if (attrs[TCA_FLOWER_KEY_ENC_OPTS_MASK]) {
        VLOG_ERR_RL(&error_rl, "failed to parse tun options; no key supplied");
        return EINVAL;
    }

    return 0;
}

static void
nl_parse_flower_ct_match(struct nlattr **attrs, struct tc_flower *flower) {
    struct tc_flower_key *key = &flower->key;
    struct tc_flower_key *mask = &flower->mask;
    struct nlattr *attr_key, *attr_mask;

    attr_key = attrs[TCA_FLOWER_KEY_CT_STATE];
    attr_mask = attrs[TCA_FLOWER_KEY_CT_STATE_MASK];
    if (attr_mask) {
        key->ct_state = nl_attr_get_u16(attr_key);
        mask->ct_state = nl_attr_get_u16(attr_mask);
    }

    attr_key = attrs[TCA_FLOWER_KEY_CT_ZONE];
    attr_mask = attrs[TCA_FLOWER_KEY_CT_ZONE_MASK];
    if (attrs[TCA_FLOWER_KEY_CT_ZONE_MASK]) {
        key->ct_zone = nl_attr_get_u16(attr_key);
        mask->ct_zone = nl_attr_get_u16(attr_mask);
    }

    attr_key = attrs[TCA_FLOWER_KEY_CT_MARK];
    attr_mask = attrs[TCA_FLOWER_KEY_CT_MARK_MASK];
    if (attrs[TCA_FLOWER_KEY_CT_MARK_MASK]) {
        key->ct_mark = nl_attr_get_u32(attr_key);
        mask->ct_mark = nl_attr_get_u32(attr_mask);
    }

    attr_key = attrs[TCA_FLOWER_KEY_CT_LABELS];
    attr_mask = attrs[TCA_FLOWER_KEY_CT_LABELS_MASK];
    if (attrs[TCA_FLOWER_KEY_CT_LABELS_MASK]) {
        key->ct_label = nl_attr_get_u128(attr_key);
        mask->ct_label = nl_attr_get_u128(attr_mask);
    }
}

static void
nl_parse_flower_ip(struct nlattr **attrs, struct tc_flower *flower) {
    uint8_t ip_proto = 0;
    struct tc_flower_key *key = &flower->key;
    struct tc_flower_key *mask = &flower->mask;

    if (attrs[TCA_FLOWER_KEY_IP_PROTO]) {
        ip_proto = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_IP_PROTO]);
        key->ip_proto = ip_proto;
        mask->ip_proto = UINT8_MAX;
    }

    if (attrs[TCA_FLOWER_KEY_FLAGS_MASK]) {
        key->flags = ntohl(nl_attr_get_be32(attrs[TCA_FLOWER_KEY_FLAGS]));
        mask->flags =
                ntohl(nl_attr_get_be32(attrs[TCA_FLOWER_KEY_FLAGS_MASK]));
    }

    if (attrs[TCA_FLOWER_KEY_IPV4_SRC_MASK]) {
        key->ipv4.ipv4_src =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_SRC]);
        mask->ipv4.ipv4_src =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_SRC_MASK]);
    }
    if (attrs[TCA_FLOWER_KEY_IPV4_DST_MASK]) {
        key->ipv4.ipv4_dst =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_DST]);
        mask->ipv4.ipv4_dst =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_DST_MASK]);
    }
    if (attrs[TCA_FLOWER_KEY_IPV6_SRC_MASK]) {
        struct nlattr *attr = attrs[TCA_FLOWER_KEY_IPV6_SRC];
        struct nlattr *attr_mask = attrs[TCA_FLOWER_KEY_IPV6_SRC_MASK];

        key->ipv6.ipv6_src = nl_attr_get_in6_addr(attr);
        mask->ipv6.ipv6_src = nl_attr_get_in6_addr(attr_mask);
    }
    if (attrs[TCA_FLOWER_KEY_IPV6_DST_MASK]) {
        struct nlattr *attr = attrs[TCA_FLOWER_KEY_IPV6_DST];
        struct nlattr *attr_mask = attrs[TCA_FLOWER_KEY_IPV6_DST_MASK];

        key->ipv6.ipv6_dst = nl_attr_get_in6_addr(attr);
        mask->ipv6.ipv6_dst = nl_attr_get_in6_addr(attr_mask);
    }

    if (ip_proto == IPPROTO_TCP) {
        if (attrs[TCA_FLOWER_KEY_TCP_SRC_MASK]) {
            key->tcp_src =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_SRC]);
            mask->tcp_src =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_SRC_MASK]);
        }
        if (attrs[TCA_FLOWER_KEY_TCP_DST_MASK]) {
            key->tcp_dst =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_DST]);
            mask->tcp_dst =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_DST_MASK]);
        }
        if (attrs[TCA_FLOWER_KEY_TCP_FLAGS_MASK]) {
            key->tcp_flags =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_FLAGS]);
            mask->tcp_flags =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_FLAGS_MASK]);
        }
    } else if (ip_proto == IPPROTO_UDP) {
        if (attrs[TCA_FLOWER_KEY_UDP_SRC_MASK]) {
            key->udp_src = nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_SRC]);
            mask->udp_src =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_SRC_MASK]);
        }
        if (attrs[TCA_FLOWER_KEY_UDP_DST_MASK]) {
            key->udp_dst = nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_DST]);
            mask->udp_dst =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_DST_MASK]);
        }
    } else if (ip_proto == IPPROTO_SCTP) {
        if (attrs[TCA_FLOWER_KEY_SCTP_SRC_MASK]) {
            key->sctp_src = nl_attr_get_be16(attrs[TCA_FLOWER_KEY_SCTP_SRC]);
            mask->sctp_src =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_SCTP_SRC_MASK]);
        }
        if (attrs[TCA_FLOWER_KEY_SCTP_DST_MASK]) {
            key->sctp_dst = nl_attr_get_be16(attrs[TCA_FLOWER_KEY_SCTP_DST]);
            mask->sctp_dst =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_SCTP_DST_MASK]);
        }
    } else if (ip_proto == IPPROTO_ICMP) {
        if (attrs[TCA_FLOWER_KEY_ICMPV4_CODE_MASK]) {
            key->icmp_code =
               nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ICMPV4_CODE]);
            mask->icmp_code =
                nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ICMPV4_CODE_MASK]);
        }
        if (attrs[TCA_FLOWER_KEY_ICMPV4_TYPE_MASK]) {
            key->icmp_type = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ICMPV4_TYPE]);
            mask->icmp_type =
                nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ICMPV4_TYPE_MASK]);
        }
    } else if (ip_proto == IPPROTO_ICMPV6) {
        if (attrs[TCA_FLOWER_KEY_ICMPV6_CODE_MASK]) {
            key->icmp_code = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ICMPV6_CODE]);
            mask->icmp_code =
                 nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ICMPV6_CODE_MASK]);
        }
        if (attrs[TCA_FLOWER_KEY_ICMPV6_TYPE_MASK]) {
            key->icmp_type = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ICMPV6_TYPE]);
            mask->icmp_type =
                nl_attr_get_u8(attrs[TCA_FLOWER_KEY_ICMPV6_TYPE_MASK]);
        }
    }

    if (attrs[TCA_FLOWER_KEY_IP_TTL_MASK]) {
        key->ip_ttl = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_IP_TTL]);
        mask->ip_ttl = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_IP_TTL_MASK]);
    }

    if (attrs[TCA_FLOWER_KEY_IP_TOS_MASK]) {
        key->ip_tos = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_IP_TOS]);
        mask->ip_tos = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_IP_TOS_MASK]);
    }

    nl_parse_flower_ct_match(attrs, flower);
}

static enum tc_offloaded_state
nl_get_flower_offloaded_state(struct nlattr **attrs)
{
    uint32_t flower_flags = 0;

    if (attrs[TCA_FLOWER_FLAGS]) {
        flower_flags = nl_attr_get_u32(attrs[TCA_FLOWER_FLAGS]);
        if (flower_flags & TCA_CLS_FLAGS_NOT_IN_HW) {
            return TC_OFFLOADED_STATE_NOT_IN_HW;
        } else if (flower_flags & TCA_CLS_FLAGS_IN_HW) {
            return TC_OFFLOADED_STATE_IN_HW;
        }
    }
    return TC_OFFLOADED_STATE_UNDEFINED;
}

static void
nl_parse_flower_flags(struct nlattr **attrs, struct tc_flower *flower)
{
    flower->offloaded_state = nl_get_flower_offloaded_state(attrs);
}

static void
nl_parse_action_pc(uint32_t action_pc, struct tc_action *action)
{
    if (action_pc == TC_ACT_STOLEN) {
        action->jump_action = JUMP_ACTION_STOP;
    } else if (action_pc & TC_ACT_JUMP) {
        action->jump_action = action_pc & TC_ACT_EXT_VAL_MASK;
    } else {
        action->jump_action = 0;
    }
}

static const struct nl_policy pedit_policy[] = {
            [TCA_PEDIT_PARMS_EX] = { .type = NL_A_UNSPEC,
                                     .min_len = sizeof(struct tc_pedit),
                                     .optional = false, },
            [TCA_PEDIT_KEYS_EX]   = { .type = NL_A_NESTED,
                                      .optional = false, },
};

static int
nl_parse_act_pedit(struct nlattr *options, struct tc_flower *flower)
{
    struct tc_action *action = &flower->actions[flower->action_count++];
    struct nlattr *pe_attrs[ARRAY_SIZE(pedit_policy)];
    const struct tc_pedit *pe;
    const struct tc_pedit_key *keys;
    const struct nlattr *nla, *keys_ex, *ex_type;
    const void *keys_attr;
    char *rewrite_key = (void *) &action->rewrite.key;
    char *rewrite_mask = (void *) &action->rewrite.mask;
    size_t keys_ex_size, left;
    int type, i = 0, err;

    if (!nl_parse_nested(options, pedit_policy, pe_attrs,
                         ARRAY_SIZE(pedit_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse pedit action options");
        return EPROTO;
    }

    pe = nl_attr_get_unspec(pe_attrs[TCA_PEDIT_PARMS_EX], sizeof *pe);
    keys = pe->keys;
    keys_attr = pe_attrs[TCA_PEDIT_KEYS_EX];
    keys_ex = nl_attr_get(keys_attr);
    keys_ex_size = nl_attr_get_size(keys_attr);

    NL_ATTR_FOR_EACH (nla, left, keys_ex, keys_ex_size) {
        if (i >= pe->nkeys) {
            break;
        }

        if (nl_attr_type(nla) != TCA_PEDIT_KEY_EX) {
            VLOG_ERR_RL(&error_rl, "unable to parse legacy pedit type: %d",
                        nl_attr_type(nla));
            return EOPNOTSUPP;
        }

        ex_type = nl_attr_find_nested(nla, TCA_PEDIT_KEY_EX_HTYPE);
        if (!ex_type) {
            return EOPNOTSUPP;
        }

        type = nl_attr_get_u16(ex_type);

        err = csum_update_flag(flower, type);
        if (err) {
            return err;
        }

        for (int j = 0; j < ARRAY_SIZE(flower_pedit_map); j++) {
            struct flower_key_to_pedit *m = &flower_pedit_map[j];
            int flower_off = m->flower_offset;
            int sz = m->size;
            int mf = m->offset;
            int ef = ROUND_UP(mf, 4);

            if (m->htype != type) {
               continue;
            }

            /* check overlap between current pedit key, which is always
             * 4 bytes (range [off, off + 3]), and a map entry in
             * flower_pedit_map sf = ROUND_DOWN(mf, 4)
             * (range [sf|mf, (mf + sz - 1)|ef]) */
            if ((keys->off >= mf && keys->off < mf + sz)
                || (keys->off + 3 >= mf && keys->off + 3 < ef)) {
                int diff = flower_off + (keys->off - mf);
                ovs_be32 *dst = (void *) (rewrite_key + diff);
                ovs_be32 *dst_m = (void *) (rewrite_mask + diff);
                ovs_be32 mask, mask_word, data_word, val;
                uint32_t zero_bits;

                mask_word = htonl(ntohl(keys->mask) << m->boundary_shift);
                data_word = htonl(ntohl(keys->val) << m->boundary_shift);
                mask = ~(mask_word);

                if (keys->off < mf) {
                    zero_bits = 8 * (mf - keys->off);
                    mask &= htonl(UINT32_MAX >> zero_bits);
                } else if (keys->off + 4 > mf + m->size) {
                    zero_bits = 8 * (keys->off + 4 - mf - m->size);
                    mask &= htonl(UINT32_MAX << zero_bits);
                }

                val = get_unaligned_be32(dst_m);
                val |= mask;
                put_unaligned_be32(dst_m, val);

                val = get_unaligned_be32(dst);
                val |= data_word & mask;
                put_unaligned_be32(dst, val);
            }
        }

        keys++;
        i++;
    }

    action->type = TC_ACT_PEDIT;

    nl_parse_action_pc(pe->action, action);
    return 0;
}

static const struct nl_policy tunnel_key_policy[] = {
    [TCA_TUNNEL_KEY_PARMS] = { .type = NL_A_UNSPEC,
                               .min_len = sizeof(struct tc_tunnel_key),
                               .optional = false, },
    [TCA_TUNNEL_KEY_ENC_IPV4_SRC] = { .type = NL_A_U32, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_IPV4_DST] = { .type = NL_A_U32, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_IPV6_SRC] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_TUNNEL_KEY_ENC_IPV6_DST] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_TUNNEL_KEY_ENC_KEY_ID] = { .type = NL_A_U32, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_DST_PORT] = { .type = NL_A_U16, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_TOS] = { .type = NL_A_U8, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_TTL] = { .type = NL_A_U8, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_OPTS] = { .type = NL_A_NESTED, .optional = true, },
    [TCA_TUNNEL_KEY_NO_CSUM] = { .type = NL_A_U8, .optional = true, },
};

static int
nl_parse_act_geneve_opts(const struct nlattr *in_nlattr,
                         struct tc_action *action)
{
    struct geneve_opt *opt = NULL;
    const struct ofpbuf *msg;
    uint16_t last_opt_type;
    struct nlattr *nla;
    struct ofpbuf buf;
    size_t left;
    int cnt;

    nl_attr_get_nested(in_nlattr, &buf);
    msg = &buf;

    last_opt_type = TCA_TUNNEL_KEY_ENC_OPT_GENEVE_UNSPEC;
    cnt = 0;
    NL_ATTR_FOR_EACH (nla, left, ofpbuf_at(msg, 0, 0), msg->size) {
        uint16_t type = nl_attr_type(nla);

        switch (type) {
        case TCA_TUNNEL_KEY_ENC_OPT_GENEVE_CLASS:
            if (cnt && last_opt_type != TCA_TUNNEL_KEY_ENC_OPT_GENEVE_DATA) {
                VLOG_ERR_RL(&error_rl,
                            "failed to parse action geneve options class");
                return EINVAL;
            }

            opt = &action->encap.data.opts.gnv[cnt];
            opt->opt_class = nl_attr_get_be16(nla);
            cnt += sizeof(struct geneve_opt) / 4;
            action->encap.data.present.len += sizeof(struct geneve_opt);
            last_opt_type = TCA_TUNNEL_KEY_ENC_OPT_GENEVE_CLASS;
            break;
        case TCA_TUNNEL_KEY_ENC_OPT_GENEVE_TYPE:
            if (last_opt_type != TCA_TUNNEL_KEY_ENC_OPT_GENEVE_CLASS) {
                VLOG_ERR_RL(&error_rl,
                            "failed to parse action geneve options type");
                return EINVAL;
            }

            opt->type = nl_attr_get_u8(nla);
            last_opt_type = TCA_TUNNEL_KEY_ENC_OPT_GENEVE_TYPE;
            break;
        case TCA_TUNNEL_KEY_ENC_OPT_GENEVE_DATA:
            if (last_opt_type != TCA_TUNNEL_KEY_ENC_OPT_GENEVE_TYPE) {
                VLOG_ERR_RL(&error_rl,
                            "failed to parse action geneve options data");
                return EINVAL;
            }

            opt->length = nl_attr_get_size(nla) / 4;
            memcpy(opt + 1, nl_attr_get_unspec(nla, 1), opt->length * 4);
            cnt += opt->length;
            action->encap.data.present.len += opt->length * 4;
            last_opt_type = TCA_TUNNEL_KEY_ENC_OPT_GENEVE_DATA;
            break;
        }
    }

    if (last_opt_type != TCA_TUNNEL_KEY_ENC_OPT_GENEVE_DATA) {
        VLOG_ERR_RL(&error_rl,
                   "failed to parse action geneve options without data");
        return EINVAL;
    }

    return 0;
}

static int
nl_parse_act_vxlan_opts(struct nlattr *in_nlattr, struct tc_action *action)
{
    const struct ofpbuf *msg;
    struct nlattr *nla;
    struct ofpbuf buf;
    size_t left;

    nl_attr_get_nested(in_nlattr, &buf);
    msg = &buf;

    NL_ATTR_FOR_EACH (nla, left, ofpbuf_at(msg, 0, 0), msg->size) {
        uint16_t type = nl_attr_type(nla);
        int32_t gbp_raw;

        switch (type) {
        case TCA_FLOWER_KEY_ENC_OPT_VXLAN_GBP:
            gbp_raw = nl_attr_get_u32(nla);
            odp_decode_gbp_raw(gbp_raw, &action->encap.gbp.id,
                               &action->encap.gbp.flags);
            action->encap.gbp.id_present = true;

            break;
        }
    }

    return 0;
}

static int
nl_parse_act_tunnel_opts(struct nlattr *options, struct tc_action *action)
{
    const struct ofpbuf *msg;
    struct nlattr *nla;
    struct ofpbuf buf;
    size_t left;
    int err;

    if (!options) {
        return 0;
    }

    nl_attr_get_nested(options, &buf);
    msg = &buf;

    NL_ATTR_FOR_EACH (nla, left, ofpbuf_at(msg, 0, 0), msg->size) {
        uint16_t type = nl_attr_type(nla);
        switch (type) {
        case TCA_TUNNEL_KEY_ENC_OPTS_GENEVE:
            err = nl_parse_act_geneve_opts(nla, action);
            if (err) {
                return err;
            }
            break;
        case TCA_TUNNEL_KEY_ENC_OPTS_VXLAN:
            err = nl_parse_act_vxlan_opts(nla, action);
            if (err) {
                return err;
            }
            break;
        }
    }

    return 0;
}

static int
nl_parse_act_tunnel_key(struct nlattr *options, struct tc_flower *flower)
{
    struct nlattr *tun_attrs[ARRAY_SIZE(tunnel_key_policy)];
    const struct nlattr *tun_parms;
    const struct tc_tunnel_key *tun;
    struct tc_action *action;
    int err;

    if (!nl_parse_nested(options, tunnel_key_policy, tun_attrs,
                ARRAY_SIZE(tunnel_key_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse tunnel_key action options");
        return EPROTO;
    }

    tun_parms = tun_attrs[TCA_TUNNEL_KEY_PARMS];
    tun = nl_attr_get_unspec(tun_parms, sizeof *tun);
    if (tun->t_action == TCA_TUNNEL_KEY_ACT_SET) {
        struct nlattr *id = tun_attrs[TCA_TUNNEL_KEY_ENC_KEY_ID];
        struct nlattr *dst_port = tun_attrs[TCA_TUNNEL_KEY_ENC_DST_PORT];
        struct nlattr *ipv4_src = tun_attrs[TCA_TUNNEL_KEY_ENC_IPV4_SRC];
        struct nlattr *ipv4_dst = tun_attrs[TCA_TUNNEL_KEY_ENC_IPV4_DST];
        struct nlattr *ipv6_src = tun_attrs[TCA_TUNNEL_KEY_ENC_IPV6_SRC];
        struct nlattr *ipv6_dst = tun_attrs[TCA_TUNNEL_KEY_ENC_IPV6_DST];
        struct nlattr *tos = tun_attrs[TCA_TUNNEL_KEY_ENC_TOS];
        struct nlattr *ttl = tun_attrs[TCA_TUNNEL_KEY_ENC_TTL];
        struct nlattr *tun_opt = tun_attrs[TCA_TUNNEL_KEY_ENC_OPTS];
        struct nlattr *no_csum = tun_attrs[TCA_TUNNEL_KEY_NO_CSUM];

        action = &flower->actions[flower->action_count++];
        action->type = TC_ACT_ENCAP;
        action->encap.ipv4.ipv4_src = ipv4_src ? nl_attr_get_be32(ipv4_src) : 0;
        action->encap.ipv4.ipv4_dst = ipv4_dst ? nl_attr_get_be32(ipv4_dst) : 0;
        if (ipv6_src) {
            action->encap.ipv6.ipv6_src = nl_attr_get_in6_addr(ipv6_src);
        }
        if (ipv6_dst) {
            action->encap.ipv6.ipv6_dst = nl_attr_get_in6_addr(ipv6_dst);
        }
        action->encap.id = id ? be32_to_be64(nl_attr_get_be32(id)) : 0;
        action->encap.id_present = id ? true : false;
        action->encap.tp_dst = dst_port ? nl_attr_get_be16(dst_port) : 0;
        action->encap.tos = tos ? nl_attr_get_u8(tos) : 0;
        action->encap.ttl = ttl ? nl_attr_get_u8(ttl) : 0;
        action->encap.no_csum = no_csum ? nl_attr_get_u8(no_csum) : 0;

        err = nl_parse_act_tunnel_opts(tun_opt, action);
        if (err) {
            return err;
        }
        nl_parse_action_pc(tun->action, action);
    } else if (tun->t_action == TCA_TUNNEL_KEY_ACT_RELEASE) {
        flower->tunnel = true;
    } else {
        VLOG_ERR_RL(&error_rl, "unknown tunnel actions: %d, %d",
                    tun->action, tun->t_action);
        return EINVAL;
    }
    return 0;
}

static const struct nl_policy gact_policy[] = {
    [TCA_GACT_PARMS] = { .type = NL_A_UNSPEC,
                         .min_len = sizeof(struct tc_gact),
                         .optional = false, },
    [TCA_GACT_TM] = { .type = NL_A_UNSPEC,
                      .min_len = sizeof(struct tcf_t),
                      .optional = false, },
};

static int
get_user_hz(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static int user_hz = 100;

    if (ovsthread_once_start(&once)) {
        user_hz = sysconf(_SC_CLK_TCK);
        ovsthread_once_done(&once);
    }

    return user_hz;
}

static void
nl_parse_tcf(const struct tcf_t *tm, struct tc_flower *flower)
{
    uint64_t lastused;

    /* On creation both tm->install and tm->lastuse are set to jiffies
     * by the kernel. So if both values are the same, the flow has not been
     * used yet.
     *
     * Note that tm->firstuse can not be used due to some kernel bug, i.e.,
     * hardware offloaded flows do not update tm->firstuse. */
    if (tm->lastuse == tm->install) {
        lastused = 0;
    } else {
        lastused = time_msec() - (tm->lastuse * 1000 / get_user_hz());
    }

    if (flower->lastused < lastused) {
        flower->lastused = lastused;
    }
}

static int
nl_parse_act_gact(struct nlattr *options, struct tc_flower *flower)
{
    struct nlattr *gact_attrs[ARRAY_SIZE(gact_policy)];
    const struct tc_gact *p;
    struct nlattr *gact_parms;
    struct tc_action *action;
    struct tcf_t tm;

    if (!nl_parse_nested(options, gact_policy, gact_attrs,
                         ARRAY_SIZE(gact_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse gact action options");
        return EPROTO;
    }

    gact_parms = gact_attrs[TCA_GACT_PARMS];
    p = nl_attr_get_unspec(gact_parms, sizeof *p);

    if (TC_ACT_EXT_CMP(p->action, TC_ACT_GOTO_CHAIN)) {
        action = &flower->actions[flower->action_count++];
        action->chain = p->action & TC_ACT_EXT_VAL_MASK;
        action->type = TC_ACT_GOTO;
        nl_parse_action_pc(p->action, action);
    } else if (p->action != TC_ACT_SHOT) {
        VLOG_ERR_RL(&error_rl, "unknown gact action: %d", p->action);
        return EINVAL;
    }

    memcpy(&tm, nl_attr_get_unspec(gact_attrs[TCA_GACT_TM], sizeof tm),
           sizeof tm);
    nl_parse_tcf(&tm, flower);

    return 0;
}

static const struct nl_policy police_policy[] = {
    [TCA_POLICE_TBF] = { .type = NL_A_UNSPEC,
                         .min_len = sizeof(struct tc_police),
                         .optional = false, },
    [TCA_POLICE_RATE] = { .type = NL_A_UNSPEC,
                          .min_len = 1024,
                          .optional = true, },
    [TCA_POLICE_RATE64] = { .type = NL_A_U32,
                            .optional = true, },
    [TCA_POLICE_PEAKRATE] = { .type = NL_A_UNSPEC,
                              .min_len = 1024,
                              .optional = true, },
    [TCA_POLICE_AVRATE] = { .type = NL_A_U32,
                            .optional = true, },
    [TCA_POLICE_RESULT] = { .type = NL_A_U32,
                            .optional = true, },
    [TCA_POLICE_TM] = { .type = NL_A_UNSPEC,
                        .min_len = sizeof(struct tcf_t),
                        .optional = true, },
};

static int
nl_parse_act_police(const struct nlattr *options, struct tc_flower *flower)
{
    struct nlattr *police_attrs[ARRAY_SIZE(police_policy)] = {};
    const struct tc_police *police;
    struct nlattr *police_result;
    struct tc_action *action;
    struct nlattr *police_tm;
    struct tcf_t tm;

    if (!nl_parse_nested(options, police_policy, police_attrs,
                         ARRAY_SIZE(police_policy))) {
        VLOG_ERR_RL(&error_rl, "Failed to parse police action options");
        return EPROTO;
    }

    police = nl_attr_get_unspec(police_attrs[TCA_POLICE_TBF], sizeof *police);
    action = &flower->actions[flower->action_count++];

    police_result = police_attrs[TCA_POLICE_RESULT];
    if (police_result && !tc_is_meter_index(police->index)) {
        action->type = TC_ACT_POLICE_MTU;
        action->police.mtu = police->mtu;

        uint32_t action_pc = nl_attr_get_u32(police_result);
        if (action_pc & TC_ACT_JUMP) {
            action->police.result_jump = action_pc & TC_ACT_EXT_VAL_MASK;
        } else {
            action->police.result_jump = JUMP_ACTION_STOP;
        }
    } else {
        action->type = TC_ACT_POLICE;
        action->police.index = police->index;
    }

    police_tm = police_attrs[TCA_POLICE_TM];
    if (police_tm) {
        memcpy(&tm, nl_attr_get_unspec(police_tm, sizeof tm), sizeof tm);
        nl_parse_tcf(&tm, flower);
    }

    nl_parse_action_pc(police->action, action);
    return 0;
}

static const struct nl_policy mirred_policy[] = {
    [TCA_MIRRED_PARMS] = { .type = NL_A_UNSPEC,
                           .min_len = sizeof(struct tc_mirred),
                           .optional = false, },
    [TCA_MIRRED_TM] = { .type = NL_A_UNSPEC,
                        .min_len = sizeof(struct tcf_t),
                        .optional = false, },
};

static int
nl_parse_act_mirred(struct nlattr *options, struct tc_flower *flower)
{

    struct nlattr *mirred_attrs[ARRAY_SIZE(mirred_policy)];
    const struct tc_mirred *m;
    const struct nlattr *mirred_parms;
    struct nlattr *mirred_tm;
    struct tc_action *action;
    struct tcf_t tm;

    if (!nl_parse_nested(options, mirred_policy, mirred_attrs,
                         ARRAY_SIZE(mirred_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse mirred action options");
        return EPROTO;
    }

    mirred_parms = mirred_attrs[TCA_MIRRED_PARMS];
    m = nl_attr_get_unspec(mirred_parms, sizeof *m);

    if (m->eaction != TCA_EGRESS_REDIR && m->eaction != TCA_EGRESS_MIRROR &&
        m->eaction != TCA_INGRESS_REDIR && m->eaction != TCA_INGRESS_MIRROR) {
        VLOG_ERR_RL(&error_rl, "unknown mirred action: %d, %d, %d",
                    m->action, m->eaction, m->ifindex);
        return EINVAL;
    }

    action = &flower->actions[flower->action_count++];
    action->out.ifindex_out = m->ifindex;
    if (m->eaction == TCA_INGRESS_REDIR || m->eaction == TCA_INGRESS_MIRROR) {
        action->out.ingress = true;
    } else {
        action->out.ingress = false;
    }
    action->type = TC_ACT_OUTPUT;

    mirred_tm = mirred_attrs[TCA_MIRRED_TM];
    memcpy(&tm, nl_attr_get_unspec(mirred_tm, sizeof tm), sizeof tm);

    nl_parse_tcf(&tm, flower);
    nl_parse_action_pc(m->action, action);
    return 0;
}

static const struct nl_policy ct_policy[] = {
    [TCA_CT_PARMS] = { .type = NL_A_UNSPEC,
                              .min_len = sizeof(struct tc_ct),
                              .optional = false, },
    [TCA_CT_ACTION] = { .type = NL_A_U16,
                         .optional = true, },
    [TCA_CT_ZONE] = { .type = NL_A_U16,
                      .optional = true, },
    [TCA_CT_MARK] = { .type = NL_A_U32,
                       .optional = true, },
    [TCA_CT_MARK_MASK] = { .type = NL_A_U32,
                            .optional = true, },
    [TCA_CT_LABELS] = { .type = NL_A_UNSPEC,
                         .optional = true, },
    [TCA_CT_LABELS_MASK] = { .type = NL_A_UNSPEC,
                              .optional = true, },
    [TCA_CT_NAT_IPV4_MIN] = { .type = NL_A_U32,
                              .optional = true, },
    [TCA_CT_NAT_IPV4_MAX] = { .type = NL_A_U32,
                              .optional = true, },
    [TCA_CT_NAT_IPV6_MIN] = { .min_len = sizeof(struct in6_addr),
                              .type = NL_A_UNSPEC,
                              .optional = true },
    [TCA_CT_NAT_IPV6_MAX] = { .min_len = sizeof(struct in6_addr),
                              .type = NL_A_UNSPEC,
                               .optional = true },
    [TCA_CT_NAT_PORT_MIN] = { .type = NL_A_U16,
                              .optional = true, },
    [TCA_CT_NAT_PORT_MAX] = { .type = NL_A_U16,
                              .optional = true, },
    [TCA_CT_TM] = { .type = NL_A_UNSPEC,
                    .min_len = sizeof(struct tcf_t),
                    .optional = true, },
};

static int
nl_parse_act_ct(struct nlattr *options, struct tc_flower *flower)
{
    struct nlattr *ct_attrs[ARRAY_SIZE(ct_policy)];
    const struct nlattr *ct_parms;
    struct tc_action *action;
    const struct tc_ct *ct;
    uint16_t ct_action = 0;
    struct tcf_t tm;

    if (!nl_parse_nested(options, ct_policy, ct_attrs,
                         ARRAY_SIZE(ct_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse ct action options");
        return EPROTO;
    }

    ct_parms = ct_attrs[TCA_CT_PARMS];
    ct = nl_attr_get_unspec(ct_parms, sizeof *ct);

    if (ct_attrs[TCA_CT_ACTION]) {
        ct_action = nl_attr_get_u16(ct_attrs[TCA_CT_ACTION]);
    }

    action = &flower->actions[flower->action_count++];
    action->ct.clear = ct_action & TCA_CT_ACT_CLEAR;
    if (!action->ct.clear) {
        struct nlattr *zone = ct_attrs[TCA_CT_ZONE];
        struct nlattr *mark = ct_attrs[TCA_CT_MARK];
        struct nlattr *mark_mask = ct_attrs[TCA_CT_MARK_MASK];
        struct nlattr *label = ct_attrs[TCA_CT_LABELS];
        struct nlattr *label_mask = ct_attrs[TCA_CT_LABELS_MASK];

        action->ct.commit = ct_action & TCA_CT_ACT_COMMIT;
        action->ct.force = ct_action & TCA_CT_ACT_FORCE;

        action->ct.zone = zone ? nl_attr_get_u16(zone) : 0;
        action->ct.mark = mark ? nl_attr_get_u32(mark) : 0;
        action->ct.mark_mask = mark_mask ? nl_attr_get_u32(mark_mask) : 0;
        action->ct.label = label? nl_attr_get_u128(label) : OVS_U128_ZERO;
        action->ct.label_mask = label_mask ?
                                nl_attr_get_u128(label_mask) : OVS_U128_ZERO;

        if (ct_action & TCA_CT_ACT_NAT) {
            struct nlattr *ipv4_min = ct_attrs[TCA_CT_NAT_IPV4_MIN];
            struct nlattr *ipv4_max = ct_attrs[TCA_CT_NAT_IPV4_MAX];
            struct nlattr *ipv6_min = ct_attrs[TCA_CT_NAT_IPV6_MIN];
            struct nlattr *ipv6_max = ct_attrs[TCA_CT_NAT_IPV6_MAX];
            struct nlattr *port_min = ct_attrs[TCA_CT_NAT_PORT_MIN];
            struct nlattr *port_max = ct_attrs[TCA_CT_NAT_PORT_MAX];

            action->ct.nat_type = TC_NAT_RESTORE;
            if (ct_action & TCA_CT_ACT_NAT_SRC) {
                action->ct.nat_type = TC_NAT_SRC;
            } else if (ct_action & TCA_CT_ACT_NAT_DST) {
                action->ct.nat_type = TC_NAT_DST;
            }

            if (ipv4_min) {
                action->ct.range.ip_family = AF_INET;
                action->ct.range.ipv4.min = nl_attr_get_be32(ipv4_min);
                if (ipv4_max) {
                    ovs_be32 addr = nl_attr_get_be32(ipv4_max);

                    if (action->ct.range.ipv4.min != addr) {
                        action->ct.range.ipv4.max = addr;
                    }
                }
            } else if (ipv6_min) {
                action->ct.range.ip_family = AF_INET6;
                action->ct.range.ipv6.min
                    = nl_attr_get_in6_addr(ipv6_min);
                if (ipv6_max) {
                    struct in6_addr addr = nl_attr_get_in6_addr(ipv6_max);

                    if (!ipv6_addr_equals(&action->ct.range.ipv6.min, &addr)) {
                        action->ct.range.ipv6.max = addr;
                    }
                }
            }

            if (port_min) {
                action->ct.range.port.min = nl_attr_get_be16(port_min);
                if (port_max) {
                    action->ct.range.port.max = nl_attr_get_be16(port_max);
                    if (action->ct.range.port.min ==
                        action->ct.range.port.max) {
                        action->ct.range.port.max = 0;
                    }
                }
            }
        }
    }
    action->type = TC_ACT_CT;

    if (ct_attrs[TCA_CT_TM]) {
        memcpy(&tm, nl_attr_get_unspec(ct_attrs[TCA_CT_TM], sizeof tm),
               sizeof tm);
        nl_parse_tcf(&tm, flower);
    }
    nl_parse_action_pc(ct->action, action);
    return 0;
}

static const struct nl_policy vlan_policy[] = {
    [TCA_VLAN_PARMS] = { .type = NL_A_UNSPEC,
                         .min_len = sizeof(struct tc_vlan),
                         .optional = false, },
    [TCA_VLAN_PUSH_VLAN_ID] = { .type = NL_A_U16, .optional = true, },
    [TCA_VLAN_PUSH_VLAN_PROTOCOL] = { .type = NL_A_U16, .optional = true, },
    [TCA_VLAN_PUSH_VLAN_PRIORITY] = { .type = NL_A_U8, .optional = true, },
};

static int
nl_parse_act_vlan(struct nlattr *options, struct tc_flower *flower)
{
    struct nlattr *vlan_attrs[ARRAY_SIZE(vlan_policy)];
    const struct tc_vlan *v;
    const struct nlattr *vlan_parms;
    struct tc_action *action;

    if (!nl_parse_nested(options, vlan_policy, vlan_attrs,
                         ARRAY_SIZE(vlan_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse vlan action options");
        return EPROTO;
    }

    action = &flower->actions[flower->action_count++];
    vlan_parms = vlan_attrs[TCA_VLAN_PARMS];
    v = nl_attr_get_unspec(vlan_parms, sizeof *v);
    if (v->v_action == TCA_VLAN_ACT_PUSH) {
        struct nlattr *vlan_tpid = vlan_attrs[TCA_VLAN_PUSH_VLAN_PROTOCOL];
        struct nlattr *vlan_id = vlan_attrs[TCA_VLAN_PUSH_VLAN_ID];
        struct nlattr *vlan_prio = vlan_attrs[TCA_VLAN_PUSH_VLAN_PRIORITY];

        action->vlan.vlan_push_tpid = nl_attr_get_be16(vlan_tpid);
        action->vlan.vlan_push_id = nl_attr_get_u16(vlan_id);
        action->vlan.vlan_push_prio = vlan_prio ? nl_attr_get_u8(vlan_prio) : 0;
        action->type = TC_ACT_VLAN_PUSH;
    } else if (v->v_action == TCA_VLAN_ACT_POP) {
        action->type = TC_ACT_VLAN_POP;
    } else {
        VLOG_ERR_RL(&error_rl, "unknown vlan action: %d, %d",
                    v->action, v->v_action);
        return EINVAL;
    }

    nl_parse_action_pc(v->action, action);
    return 0;
}

static const struct nl_policy mpls_policy[] = {
    [TCA_MPLS_PARMS] = { .type = NL_A_UNSPEC,
                         .min_len = sizeof(struct tc_mpls),
                         .optional = false, },
    [TCA_MPLS_PROTO] = { .type = NL_A_U16, .optional = true, },
    [TCA_MPLS_LABEL] = { .type = NL_A_U32, .optional = true, },
    [TCA_MPLS_TC] = { .type = NL_A_U8, .optional = true, },
    [TCA_MPLS_TTL] = { .type = NL_A_U8, .optional = true, },
    [TCA_MPLS_BOS] = { .type = NL_A_U8, .optional = true, },
};

static int
nl_parse_act_mpls(struct nlattr *options, struct tc_flower *flower)
{
    struct nlattr *mpls_attrs[ARRAY_SIZE(mpls_policy)];
    const struct nlattr *mpls_parms;
    struct nlattr *mpls_proto;
    struct nlattr *mpls_label;
    struct tc_action *action;
    const struct tc_mpls *m;
    struct nlattr *mpls_ttl;
    struct nlattr *mpls_bos;
    struct nlattr *mpls_tc;

    if (!nl_parse_nested(options, mpls_policy, mpls_attrs,
                         ARRAY_SIZE(mpls_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse mpls action options");
        return EPROTO;
    }

    action = &flower->actions[flower->action_count++];
    mpls_parms = mpls_attrs[TCA_MPLS_PARMS];
    m = nl_attr_get_unspec(mpls_parms, sizeof *m);

    switch (m->m_action) {
    case TCA_MPLS_ACT_POP:
        mpls_proto = mpls_attrs[TCA_MPLS_PROTO];
        if (mpls_proto) {
            action->mpls.proto = nl_attr_get_be16(mpls_proto);
        }
        action->type = TC_ACT_MPLS_POP;
        break;
    case TCA_MPLS_ACT_PUSH:
        mpls_proto = mpls_attrs[TCA_MPLS_PROTO];
        if (mpls_proto) {
            action->mpls.proto = nl_attr_get_be16(mpls_proto);
        }
        mpls_label = mpls_attrs[TCA_MPLS_LABEL];
        if (mpls_label) {
            action->mpls.label = nl_attr_get_u32(mpls_label);
        }
        mpls_tc = mpls_attrs[TCA_MPLS_TC];
        if (mpls_tc) {
            action->mpls.tc = nl_attr_get_u8(mpls_tc);
        }
        mpls_ttl = mpls_attrs[TCA_MPLS_TTL];
        if (mpls_ttl) {
            action->mpls.ttl = nl_attr_get_u8(mpls_ttl);
        }
        mpls_bos = mpls_attrs[TCA_MPLS_BOS];
        if (mpls_bos) {
            action->mpls.bos = nl_attr_get_u8(mpls_bos);
        }
        action->type = TC_ACT_MPLS_PUSH;
        break;
    case TCA_MPLS_ACT_MODIFY:
        mpls_label = mpls_attrs[TCA_MPLS_LABEL];
        if (mpls_label) {
            action->mpls.label = nl_attr_get_u32(mpls_label);
        }
        mpls_tc = mpls_attrs[TCA_MPLS_TC];
        if (mpls_tc) {
            action->mpls.tc = nl_attr_get_u8(mpls_tc);
        }
        mpls_ttl = mpls_attrs[TCA_MPLS_TTL];
        if (mpls_ttl) {
            action->mpls.ttl = nl_attr_get_u8(mpls_ttl);
        }
        mpls_bos = mpls_attrs[TCA_MPLS_BOS];
        if (mpls_bos) {
            action->mpls.bos = nl_attr_get_u8(mpls_bos);
        }
        action->type = TC_ACT_MPLS_SET;
        break;
    default:
        VLOG_ERR_RL(&error_rl, "unknown mpls action: %d, %d",
                    m->action, m->m_action);
        return EINVAL;
    }

    nl_parse_action_pc(m->action, action);
    return 0;
}

static const struct nl_policy csum_policy[] = {
    [TCA_CSUM_PARMS] = { .type = NL_A_UNSPEC,
                         .min_len = sizeof(struct tc_csum),
                         .optional = false, },
};

static int
nl_parse_act_csum(struct nlattr *options, struct tc_flower *flower)
{
    struct nlattr *csum_attrs[ARRAY_SIZE(csum_policy)];
    const struct tc_csum *c;
    const struct nlattr *csum_parms;

    if (!nl_parse_nested(options, csum_policy, csum_attrs,
                         ARRAY_SIZE(csum_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse csum action options");
        return EPROTO;
    }

    csum_parms = csum_attrs[TCA_CSUM_PARMS];
    c = nl_attr_get_unspec(csum_parms, sizeof *c);

    /* sanity checks */
    if (c->update_flags != flower->csum_update_flags) {
        VLOG_WARN_RL(&error_rl,
                     "expected different act csum flags: 0x%x != 0x%x",
                     flower->csum_update_flags, c->update_flags);
        return EINVAL;
    }
    flower->csum_update_flags = 0; /* so we know csum was handled */

    if (flower->needs_full_ip_proto_mask
        && flower->mask.ip_proto != UINT8_MAX) {
        VLOG_WARN_RL(&error_rl, "expected full matching on flower ip_proto");
        return EINVAL;
    }

    /* The action_pc should be set on the previous action. */
    if (flower->action_count < TCA_ACT_MAX_NUM) {
        struct tc_action *action = &flower->actions[flower->action_count];

        nl_parse_action_pc(c->action, action);
    }
    return 0;
}

static const struct nl_policy act_policy[] = {
    [TCA_ACT_KIND] = { .type = NL_A_STRING, .optional = false, },
    [TCA_ACT_COOKIE] = { .type = NL_A_UNSPEC, .optional = true, },
    [TCA_ACT_OPTIONS] = { .type = NL_A_NESTED, .optional = true, },
    [TCA_ACT_STATS] = { .type = NL_A_NESTED, .optional = false, },
};

static int
nl_parse_action_stats(struct nlattr *act_stats,
                      struct ovs_flow_stats *stats_sw,
                      struct ovs_flow_stats *stats_hw,
                      struct ovs_flow_stats *stats_dropped)
{
    struct tc_flow_stats s_sw = {0}, s_hw = {0};
    const struct gnet_stats_queue *qs = NULL;
    uint16_t prev_type = __TCA_STATS_MAX;
    const struct nlattr *nla;
    unsigned int seen = 0;
    size_t left;

    /* Cannot use nl_parse_nested due to duplicate attributes. */
    NL_NESTED_FOR_EACH (nla, left, act_stats) {
        struct gnet_stats_basic stats_basic;
        uint16_t type = nl_attr_type(nla);

        seen |= 1 << type;

        switch (type) {
        case TCA_STATS_BASIC:
            memcpy(&stats_basic, nl_attr_get_unspec(nla, sizeof stats_basic),
                   sizeof stats_basic);
            s_sw.n_packets = stats_basic.packets;
            s_sw.n_bytes = stats_basic.bytes;
            break;

        case TCA_STATS_BASIC_HW:
            memcpy(&stats_basic, nl_attr_get_unspec(nla, sizeof stats_basic),
                   sizeof stats_basic);
            s_hw.n_packets = stats_basic.packets;
            s_hw.n_bytes = stats_basic.bytes;
            break;

        case TCA_STATS_QUEUE:
            qs = nl_attr_get_unspec(nla, sizeof *qs);
            break;

        case TCA_STATS_PKT64:
            if (prev_type == TCA_STATS_BASIC) {
                s_sw.n_packets = nl_attr_get_u64(nla);
            } else if (prev_type == TCA_STATS_BASIC_HW) {
                s_hw.n_packets = nl_attr_get_u64(nla);
            } else {
                goto err;
            }
            break;

        default:
            break;
        }
        prev_type = type;
    }

    if (!(seen & (1 << TCA_STATS_BASIC))) {
        goto err;
    }

    if (seen & (1 << TCA_STATS_BASIC_HW)) {
        s_sw.n_packets = s_sw.n_packets - s_hw.n_packets;
        s_sw.n_bytes = s_sw.n_bytes - s_hw.n_bytes;

        if (s_hw.n_packets > get_32aligned_u64(&stats_hw->n_packets)) {
            put_32aligned_u64(&stats_hw->n_packets, s_hw.n_packets);
            put_32aligned_u64(&stats_hw->n_bytes, s_hw.n_bytes);
        }
    }

    if (s_sw.n_packets > get_32aligned_u64(&stats_sw->n_packets)) {
        put_32aligned_u64(&stats_sw->n_packets, s_sw.n_packets);
        put_32aligned_u64(&stats_sw->n_bytes, s_sw.n_bytes);
    }

    if (stats_dropped && qs) {
        put_32aligned_u64(&stats_dropped->n_packets, qs->drops);
    }

    return 0;

err:
    VLOG_ERR_RL(&error_rl, "Failed to parse action stats policy");
    return EPROTO;
}

static int
nl_parse_single_action(struct nlattr *action, struct tc_flower *flower,
                       bool terse, bool *csum)
{
    struct nlattr *act_options;
    struct nlattr *act_cookie;
    const char *act_kind;
    struct nlattr *action_attrs[ARRAY_SIZE(act_policy)];
    int err = 0;

    if (!nl_parse_nested(action, act_policy, action_attrs,
                         ARRAY_SIZE(act_policy)) ||
        (!terse && !action_attrs[TCA_ACT_OPTIONS])) {
        VLOG_ERR_RL(&error_rl, "failed to parse single action options");
        return EPROTO;
    }

    *csum = false;
    act_kind = nl_attr_get_string(action_attrs[TCA_ACT_KIND]);
    act_options = action_attrs[TCA_ACT_OPTIONS];
    act_cookie = action_attrs[TCA_ACT_COOKIE];

    if (terse) {
        /* Terse dump doesn't provide act options attribute. */
    } else if (!strcmp(act_kind, "gact")) {
        err = nl_parse_act_gact(act_options, flower);
    } else if (!strcmp(act_kind, "mirred")) {
        err = nl_parse_act_mirred(act_options, flower);
    } else if (!strcmp(act_kind, "vlan")) {
        err = nl_parse_act_vlan(act_options, flower);
    } else if (!strcmp(act_kind, "mpls")) {
        err = nl_parse_act_mpls(act_options, flower);
    } else if (!strcmp(act_kind, "tunnel_key")) {
        err = nl_parse_act_tunnel_key(act_options, flower);
    } else if (!strcmp(act_kind, "pedit")) {
        err = nl_parse_act_pedit(act_options, flower);
    } else if (!strcmp(act_kind, "csum")) {
        nl_parse_act_csum(act_options, flower);
        *csum = true;
    } else if (!strcmp(act_kind, "skbedit")) {
        /* Added for TC rule only (not in OvS rule) so ignore. */
    } else if (!strcmp(act_kind, "ct")) {
        nl_parse_act_ct(act_options, flower);
    } else if (!strcmp(act_kind, "police")) {
        nl_parse_act_police(act_options, flower);
    } else {
        VLOG_ERR_RL(&error_rl, "unknown tc action kind: %s", act_kind);
        err = EINVAL;
    }

    if (err) {
        return err;
    }

    if (act_cookie) {
        flower->act_cookie.data = nl_attr_get(act_cookie);
        flower->act_cookie.len = nl_attr_get_size(act_cookie);
    }

    return nl_parse_action_stats(action_attrs[TCA_ACT_STATS],
                                 &flower->stats_sw, &flower->stats_hw, NULL);
}

int
tc_parse_action_stats(struct nlattr *action, struct ovs_flow_stats *stats_sw,
                      struct ovs_flow_stats *stats_hw,
                      struct ovs_flow_stats *stats_dropped)
{
    struct nlattr *action_attrs[ARRAY_SIZE(act_policy)];

    if (!nl_parse_nested(action, act_policy, action_attrs,
                         ARRAY_SIZE(act_policy))) {
        VLOG_ERR_RL(&error_rl, "Failed to parse single action options");
        return EPROTO;
    }

    return nl_parse_action_stats(action_attrs[TCA_ACT_STATS], stats_sw,
                                 stats_hw, stats_dropped);
}

#define TCA_ACT_MIN_PRIO 1

static int
nl_parse_flower_actions(struct nlattr **attrs, struct tc_flower *flower,
                        bool terse)
{
    const struct nlattr *actions = attrs[TCA_FLOWER_ACT];
    static struct nl_policy actions_orders_policy[TCA_ACT_MAX_NUM + 1] = {};
    struct nlattr *actions_orders[ARRAY_SIZE(actions_orders_policy)];
    const int max_size = ARRAY_SIZE(actions_orders_policy);
    int previous_action_count = 0;
    bool need_jump_adjust = false;
    int jump_adjust = 0;
    bool csum = false;

    for (int i = TCA_ACT_MIN_PRIO; i < max_size; i++) {
        actions_orders_policy[i].type = NL_A_NESTED;
        actions_orders_policy[i].optional = true;
    }

    if (!nl_parse_nested(actions, actions_orders_policy, actions_orders,
                         ARRAY_SIZE(actions_orders_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse flower order of actions");
        return EPROTO;
    }

    for (int i = TCA_ACT_MIN_PRIO; i < max_size; i++) {
        if (actions_orders[i]) {
            int err;

            if (flower->action_count >= TCA_ACT_MAX_NUM) {
                VLOG_DBG_RL(&error_rl, "Can only support %d actions", TCA_ACT_MAX_NUM);
                return EOPNOTSUPP;
            }
            err = nl_parse_single_action(actions_orders[i], flower, terse,
                                         &csum);

            if (flower->action_count == previous_action_count) {

                struct tc_action *action;

                /* We had no update on the TC action count, which means
                 * we had a none TC type action. So need to adjust existing
                 * jump offsets. */
                jump_adjust++;

                if (need_jump_adjust || (csum && flower->action_count > 0)) {

                    if (csum && flower->action_count > 0) {
                        /* The csum action is special as it might carry
                         * a jump count for the previous TC_ACT and therefore
                         * should be adjusted with jump_adjust as it got
                         * copied. */
                        action = &flower->actions[flower->action_count - 1];
                        if (action->jump_action
                            && action->jump_action != JUMP_ACTION_STOP) {
                            action->jump_action -= (jump_adjust - 1);
                        }
                    }

                    for (int j = 0; j < flower->action_count; j++) {
                        action = &flower->actions[j];

                        if (action->type == TC_ACT_POLICE_MTU
                            && action->police.result_jump != JUMP_ACTION_STOP
                            && (action->police.result_jump - 1) >
                            flower->action_count) {

                            action->police.result_jump--;
                        }

                        if (action->jump_action
                            && action->jump_action != JUMP_ACTION_STOP
                            && (action->jump_action - 1) >
                            flower->action_count) {

                            action->jump_action--;
                        }
                    }
                }
            } else {
                struct tc_action *action;

                action = &flower->actions[previous_action_count];
                if (action->type == TC_ACT_POLICE_MTU &&
                    action->police.result_jump != JUMP_ACTION_STOP) {
                    action->police.result_jump -= jump_adjust;
                    need_jump_adjust = true;
                }

                if (action->jump_action
                    && action->jump_action != JUMP_ACTION_STOP) {
                    action->jump_action -= jump_adjust;
                    need_jump_adjust = true;
                }

                previous_action_count = flower->action_count;
            }

            if (err) {
                return err;
            }
        }
    }

    if (flower->csum_update_flags) {
        VLOG_WARN_RL(&error_rl,
                     "expected act csum with flags: 0x%x",
                     flower->csum_update_flags);
        return EINVAL;
    }

    return 0;
}

static int
nl_parse_flower_options(struct nlattr *nl_options, struct tc_flower *flower,
                        bool terse)
{
    struct nlattr *attrs[ARRAY_SIZE(tca_flower_policy)];
    int err;

    if (terse) {
        if (!nl_parse_nested(nl_options, tca_flower_terse_policy,
                             attrs, ARRAY_SIZE(tca_flower_terse_policy))) {
            VLOG_ERR_RL(&error_rl, "failed to parse flower classifier terse options");
            return EPROTO;
        }
        goto skip_flower_opts;
    }

    if (!nl_parse_nested(nl_options, tca_flower_policy,
                         attrs, ARRAY_SIZE(tca_flower_policy))) {
        VLOG_ERR_RL(&error_rl, "failed to parse flower classifier options");
        return EPROTO;
    }

    nl_parse_flower_eth(attrs, flower);
    nl_parse_flower_arp(attrs, flower);
    nl_parse_flower_mpls(attrs, flower);
    nl_parse_flower_vlan(attrs, flower);
    nl_parse_flower_ip(attrs, flower);
    err = nl_parse_flower_tunnel(attrs, flower);
    if (err) {
        return err;
    }

skip_flower_opts:
    nl_parse_flower_flags(attrs, flower);
    return nl_parse_flower_actions(attrs, flower, terse);
}

int
parse_netlink_to_tc_flower(struct ofpbuf *reply, struct tcf_id *id,
                           struct tc_flower *flower, bool terse)
{
    struct ofpbuf b = ofpbuf_const_initializer(reply->data, reply->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct tcmsg *tc = ofpbuf_try_pull(&b, sizeof *tc);
    struct nlattr *ta[ARRAY_SIZE(tca_policy)];
    const char *kind;

    if (!nlmsg || !tc) {
        COVERAGE_INC(tc_netlink_malformed_reply);
        return EPROTO;
    }

    memset(flower, 0, sizeof *flower);

    flower->key.eth_type = (OVS_FORCE ovs_be16) tc_get_minor(tc->tcm_info);
    flower->mask.eth_type = OVS_BE16_MAX;
    id->prio = tc_get_major(tc->tcm_info);
    id->handle = tc->tcm_handle;

    if (id->prio == TC_RESERVED_PRIORITY_POLICE) {
        return 0;
    }

    if (!id->handle) {
        return EAGAIN;
    }

    if (!nl_policy_parse(&b, 0, tca_policy, ta, ARRAY_SIZE(ta))) {
        VLOG_ERR_RL(&error_rl, "failed to parse tca policy");
        return EPROTO;
    }

    if (ta[TCA_CHAIN]) {
        id->chain = nl_attr_get_u32(ta[TCA_CHAIN]);
    }

    kind = nl_attr_get_string(ta[TCA_KIND]);
    if (strcmp(kind, "flower")) {
        VLOG_DBG_ONCE("Unsupported filter: %s", kind);
        return EPROTO;
    }

    return nl_parse_flower_options(ta[TCA_OPTIONS], flower, terse);
}

int
parse_netlink_to_tc_chain(struct ofpbuf *reply, uint32_t *chain)
{
    struct ofpbuf b = ofpbuf_const_initializer(reply->data, reply->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct tcmsg *tc = ofpbuf_try_pull(&b, sizeof *tc);
    struct nlattr *ta[ARRAY_SIZE(tca_chain_policy)];

    if (!nlmsg || !tc) {
        COVERAGE_INC(tc_netlink_malformed_reply);
        return EPROTO;
    }

    if (!nl_policy_parse(&b, 0, tca_chain_policy, ta, ARRAY_SIZE(ta))) {
        VLOG_ERR_RL(&error_rl, "failed to parse tca chain policy");
        return EINVAL;
    }

   *chain = nl_attr_get_u32(ta[TCA_CHAIN]);

    return 0;
}

int
tc_dump_flower_start(struct tcf_id *id, struct nl_dump *dump, bool terse)
{
    struct ofpbuf request;

    request_from_tcf_id(id, 0, RTM_GETTFILTER, NLM_F_DUMP, &request);
    if (terse) {
        struct nla_bitfield32 dump_flags = { TCA_DUMP_FLAGS_TERSE,
                                             TCA_DUMP_FLAGS_TERSE };

        nl_msg_put_unspec(&request, TCA_DUMP_FLAGS, &dump_flags,
                          sizeof dump_flags);
    }
    nl_dump_start(dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    return 0;
}

int
tc_dump_tc_chain_start(struct tcf_id *id, struct nl_dump *dump)
{
    struct ofpbuf request;

    request_from_tcf_id(id, 0, RTM_GETCHAIN, NLM_F_DUMP, &request);
    nl_dump_start(dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    return 0;
}

int
tc_dump_tc_action_start(char *name, struct nl_dump *dump)
{
    size_t offset, root_offset;
    struct ofpbuf request;

    tc_make_action_request(RTM_GETACTION, NLM_F_DUMP, &request);
    root_offset = nl_msg_start_nested(&request, TCA_ACT_TAB);
    offset = nl_msg_start_nested(&request, 1);
    nl_msg_put_string(&request, TCA_ACT_KIND, name);
    nl_msg_end_nested(&request, offset);
    nl_msg_end_nested(&request, root_offset);

    nl_dump_start(dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    return 0;
}

int
parse_netlink_to_tc_policer(struct ofpbuf *reply, uint32_t police_idx[])
{
    static struct nl_policy actions_orders_policy[TCA_ACT_MAX_PRIO] = {};
    struct ofpbuf b = ofpbuf_const_initializer(reply->data, reply->size);
    struct nlattr *actions_orders[ARRAY_SIZE(actions_orders_policy)];
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    const int max_size = ARRAY_SIZE(actions_orders_policy);
    struct tcamsg *tca = ofpbuf_try_pull(&b, sizeof *tca);
    const struct nlattr *actions;
    struct tc_flower flower;
    int i, cnt = 0;
    int err;

    if (!nlmsg || !tca) {
        COVERAGE_INC(tc_netlink_malformed_reply);
        return EPROTO;
    }

    for (i = 0; i < max_size; i++) {
        actions_orders_policy[i].type = NL_A_NESTED;
        actions_orders_policy[i].optional = true;
    }

    actions = nl_attr_find(&b, 0, TCA_ACT_TAB);
    if (!actions || !nl_parse_nested(actions, actions_orders_policy,
                                     actions_orders, max_size)) {
        VLOG_ERR_RL(&error_rl,
                    "Failed to parse actions in netlink to policer");
        return EPROTO;
    }

    for (i = 0; i < TCA_ACT_MAX_PRIO; i++) {
        if (actions_orders[i]) {
            bool csum;

            memset(&flower, 0, sizeof(struct tc_flower));
            err = nl_parse_single_action(actions_orders[i], &flower, false,
                                         &csum);
            if (err || flower.actions[0].type != TC_ACT_POLICE) {
                continue;
            }
            if (flower.actions[0].police.index) {
                police_idx[cnt++] = flower.actions[0].police.index;
            }
        }
    }

    return 0;
}

int
tc_del_filter(struct tcf_id *id, const char *kind)
{
    struct ofpbuf request;

    request_from_tcf_id(id, 0, RTM_DELTFILTER, NLM_F_ACK, &request);
    if (kind) {
        nl_msg_put_string(&request, TCA_KIND, kind);
    }
    return tc_transact(&request, NULL);
}

int
tc_del_flower_filter(struct tcf_id *id)
{
    return tc_del_filter(id, "flower");
}

int
tc_get_flower(struct tcf_id *id, struct tc_flower *flower)
{
    struct ofpbuf request;
    struct ofpbuf *reply;
    int error;

    request_from_tcf_id(id, 0, RTM_GETTFILTER, NLM_F_ECHO, &request);
    nl_msg_put_string(&request, TCA_KIND, "flower");
    error = tc_transact(&request, &reply);
    if (error) {
        return error;
    }

    error = parse_netlink_to_tc_flower(reply, id, flower, false);
    ofpbuf_delete(reply);
    return error;
}

static int
tc_get_tc_cls_policy(enum tc_offload_policy policy)
{
    if (policy == TC_POLICY_SKIP_HW) {
        return TCA_CLS_FLAGS_SKIP_HW;
    } else if (policy == TC_POLICY_SKIP_SW) {
        return TCA_CLS_FLAGS_SKIP_SW;
    }

    return 0;
}

static void
nl_msg_put_act_csum(struct ofpbuf *request, uint32_t flags, uint32_t action_pc)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "csum");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_csum parm = { .action = action_pc,
                                .update_flags = flags };

        nl_msg_put_unspec(request, TCA_CSUM_PARMS, &parm, sizeof parm);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_pedit(struct ofpbuf *request, struct tc_pedit *parm,
                     struct tc_pedit_key_ex *ex, uint32_t action_pc)
{
    size_t ksize = sizeof *parm + parm->nkeys * sizeof(struct tc_pedit_key);
    size_t offset, offset_keys_ex, offset_key;
    int i;

    nl_msg_put_string(request, TCA_ACT_KIND, "pedit");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        parm->action = action_pc;

        nl_msg_put_unspec(request, TCA_PEDIT_PARMS_EX, parm, ksize);
        offset_keys_ex = nl_msg_start_nested(request, TCA_PEDIT_KEYS_EX);
        for (i = 0; i < parm->nkeys; i++, ex++) {
            offset_key = nl_msg_start_nested(request, TCA_PEDIT_KEY_EX);
            nl_msg_put_u16(request, TCA_PEDIT_KEY_EX_HTYPE, ex->htype);
            nl_msg_put_u16(request, TCA_PEDIT_KEY_EX_CMD, ex->cmd);
            nl_msg_end_nested(request, offset_key);
        }
        nl_msg_end_nested(request, offset_keys_ex);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_push_vlan(struct ofpbuf *request, ovs_be16 tpid,
                         uint16_t vid, uint8_t prio, uint32_t action_pc)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "vlan");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_vlan parm = { .action = action_pc,
                                .v_action = TCA_VLAN_ACT_PUSH };

        nl_msg_put_unspec(request, TCA_VLAN_PARMS, &parm, sizeof parm);
        nl_msg_put_be16(request, TCA_VLAN_PUSH_VLAN_PROTOCOL, tpid);
        nl_msg_put_u16(request, TCA_VLAN_PUSH_VLAN_ID, vid);
        nl_msg_put_u8(request, TCA_VLAN_PUSH_VLAN_PRIORITY, prio);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_pop_vlan(struct ofpbuf *request, uint32_t action_pc)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "vlan");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_vlan parm = { .action = action_pc,
                                .v_action = TCA_VLAN_ACT_POP };

        nl_msg_put_unspec(request, TCA_VLAN_PARMS, &parm, sizeof parm);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_pop_mpls(struct ofpbuf *request, ovs_be16 proto,
                        uint32_t action_pc)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "mpls");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS | NLA_F_NESTED);
    {
        struct tc_mpls parm = { .action = action_pc,
                                .m_action = TCA_MPLS_ACT_POP };

        nl_msg_put_unspec(request, TCA_MPLS_PARMS, &parm, sizeof parm);
        nl_msg_put_be16(request, TCA_MPLS_PROTO, proto);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_push_mpls(struct ofpbuf *request, ovs_be16 proto,
                         uint32_t label, uint8_t tc, uint8_t ttl, uint8_t bos,
                         uint32_t action_pc)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "mpls");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS | NLA_F_NESTED);
    {
        struct tc_mpls parm = { .action = action_pc,
                                .m_action = TCA_MPLS_ACT_PUSH };

        nl_msg_put_unspec(request, TCA_MPLS_PARMS, &parm, sizeof parm);
        nl_msg_put_be16(request, TCA_MPLS_PROTO, proto);
        nl_msg_put_u32(request, TCA_MPLS_LABEL, label);
        nl_msg_put_u8(request, TCA_MPLS_TC, tc);
        nl_msg_put_u8(request, TCA_MPLS_TTL, ttl);
        nl_msg_put_u8(request, TCA_MPLS_BOS, bos);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_set_mpls(struct ofpbuf *request, uint32_t label, uint8_t tc,
                        uint8_t ttl, uint8_t bos, uint32_t action_pc)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "mpls");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS | NLA_F_NESTED);
    {
        struct tc_mpls parm = { .action = action_pc,
                                .m_action = TCA_MPLS_ACT_MODIFY };

        nl_msg_put_unspec(request, TCA_MPLS_PARMS, &parm, sizeof parm);
        nl_msg_put_u32(request, TCA_MPLS_LABEL, label);
        nl_msg_put_u8(request, TCA_MPLS_TC, tc);
        nl_msg_put_u8(request, TCA_MPLS_TTL, ttl);
        nl_msg_put_u8(request, TCA_MPLS_BOS, bos);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_tunnel_key_release(struct ofpbuf *request)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "tunnel_key");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_tunnel_key tun = { .action = TC_ACT_PIPE,
                                     .t_action = TCA_TUNNEL_KEY_ACT_RELEASE };

        nl_msg_put_unspec(request, TCA_TUNNEL_KEY_PARMS, &tun, sizeof tun);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_tunnel_geneve_option(struct ofpbuf *request,
                                    struct tun_metadata *tun_metadata)
{
    const struct geneve_opt *opt;
    size_t outer, inner;
    int len, cnt = 0;

    len = tun_metadata->present.len;
    if (!len) {
        return;
    }

    outer = nl_msg_start_nested(request, TCA_TUNNEL_KEY_ENC_OPTS);

    while (len) {
        opt = &tun_metadata->opts.gnv[cnt];
        inner = nl_msg_start_nested(request, TCA_TUNNEL_KEY_ENC_OPTS_GENEVE);

        nl_msg_put_be16(request, TCA_TUNNEL_KEY_ENC_OPT_GENEVE_CLASS,
                        opt->opt_class);
        nl_msg_put_u8(request, TCA_TUNNEL_KEY_ENC_OPT_GENEVE_TYPE, opt->type);
        nl_msg_put_unspec(request, TCA_TUNNEL_KEY_ENC_OPT_GENEVE_DATA, opt + 1,
                          opt->length * 4);

        cnt += sizeof(struct geneve_opt) / 4 + opt->length;
        len -= sizeof(struct geneve_opt) + opt->length * 4;

        nl_msg_end_nested(request, inner);
    }

    nl_msg_end_nested(request, outer);
}

static void
nl_msg_put_act_tunnel_vxlan_opts(struct ofpbuf *request,
                                 struct tc_action_encap *encap)
{
    size_t outer, inner;
    uint32_t gbp_raw;

    if (!encap->gbp.id_present) {
        return;
    }

    gbp_raw = odp_encode_gbp_raw(encap->gbp.flags,
                                 encap->gbp.id);
    outer = nl_msg_start_nested_with_flag(request, TCA_TUNNEL_KEY_ENC_OPTS);
    inner = nl_msg_start_nested_with_flag(request,
                                          TCA_TUNNEL_KEY_ENC_OPTS_VXLAN);
    nl_msg_put_u32(request, TCA_TUNNEL_KEY_ENC_OPT_VXLAN_GBP, gbp_raw);
    nl_msg_end_nested(request, inner);
    nl_msg_end_nested(request, outer);
}

static void
nl_msg_put_act_tunnel_key_set(struct ofpbuf *request,
                              struct tc_action_encap *encap,
                              uint32_t action_pc)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "tunnel_key");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_tunnel_key tun = { .action = action_pc,
                                     .t_action = TCA_TUNNEL_KEY_ACT_SET };

        nl_msg_put_unspec(request, TCA_TUNNEL_KEY_PARMS, &tun, sizeof tun);

        ovs_be32 id32 = be64_to_be32(encap->id);
        if (encap->id_present) {
            nl_msg_put_be32(request, TCA_TUNNEL_KEY_ENC_KEY_ID, id32);
        }
        if (encap->ipv4.ipv4_dst) {
            nl_msg_put_be32(request, TCA_TUNNEL_KEY_ENC_IPV4_SRC,
                            encap->ipv4.ipv4_src);
            nl_msg_put_be32(request, TCA_TUNNEL_KEY_ENC_IPV4_DST,
                            encap->ipv4.ipv4_dst);
        } else if (ipv6_addr_is_set(&encap->ipv6.ipv6_dst)) {
            nl_msg_put_in6_addr(request, TCA_TUNNEL_KEY_ENC_IPV6_DST,
                                &encap->ipv6.ipv6_dst);
            nl_msg_put_in6_addr(request, TCA_TUNNEL_KEY_ENC_IPV6_SRC,
                                &encap->ipv6.ipv6_src);
        }
        if (encap->tos) {
            nl_msg_put_u8(request, TCA_TUNNEL_KEY_ENC_TOS, encap->tos);
        }
        if (encap->ttl) {
            nl_msg_put_u8(request, TCA_TUNNEL_KEY_ENC_TTL, encap->ttl);
        }
        if (encap->tp_dst) {
            nl_msg_put_be16(request, TCA_TUNNEL_KEY_ENC_DST_PORT,
                            encap->tp_dst);
        }
        nl_msg_put_act_tunnel_vxlan_opts(request, encap);
        nl_msg_put_act_tunnel_geneve_option(request, &encap->data);
        nl_msg_put_u8(request, TCA_TUNNEL_KEY_NO_CSUM, encap->no_csum);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_gact(struct ofpbuf *request, uint32_t chain)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "gact");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_gact p = { .action = TC_ACT_SHOT };

        if (chain) {
            p.action = TC_ACT_GOTO_CHAIN | chain;
        }

        nl_msg_put_unspec(request, TCA_GACT_PARMS, &p, sizeof p);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_police_index(struct ofpbuf *request, uint32_t police_idx,
                            uint32_t action_pc)
{
    struct tc_police police;
    size_t offset;

    memset(&police, 0, sizeof police);
    police.index = police_idx;
    police.action = action_pc;

    nl_msg_put_string(request, TCA_ACT_KIND, "police");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    nl_msg_put_unspec(request, TCA_POLICE_TBF, &police, sizeof police);
    nl_msg_put_u32(request, TCA_POLICE_RESULT, action_pc);
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_ct(struct ofpbuf *request, struct tc_action *action,
                  uint32_t action_pc)
{
    uint16_t ct_action = 0;
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "ct");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS | NLA_F_NESTED);
    {
        struct tc_ct ct = {
            .action = action_pc,
        };

        if (!action->ct.clear) {
            if (action->ct.zone) {
                nl_msg_put_u16(request, TCA_CT_ZONE, action->ct.zone);
            }

            if (!is_all_zeros(&action->ct.label_mask,
                              sizeof action->ct.label_mask)) {
                nl_msg_put_u128(request, TCA_CT_LABELS,
                                action->ct.label);
                nl_msg_put_u128(request, TCA_CT_LABELS_MASK,
                                action->ct.label_mask);
            }

            if (action->ct.mark_mask) {
                nl_msg_put_u32(request, TCA_CT_MARK,
                               action->ct.mark);
                nl_msg_put_u32(request, TCA_CT_MARK_MASK,
                               action->ct.mark_mask);
            }

            if (action->ct.commit) {
                ct_action = TCA_CT_ACT_COMMIT;
                if (action->ct.force) {
                    ct_action |= TCA_CT_ACT_FORCE;
                }
            }

            if (action->ct.nat_type) {
                ct_action |= TCA_CT_ACT_NAT;

                if (action->ct.nat_type == TC_NAT_SRC) {
                    ct_action |= TCA_CT_ACT_NAT_SRC;
                } else if (action->ct.nat_type == TC_NAT_DST) {
                    ct_action |= TCA_CT_ACT_NAT_DST;
                }

                if (action->ct.range.ip_family == AF_INET) {
                    nl_msg_put_be32(request, TCA_CT_NAT_IPV4_MIN,
                                    action->ct.range.ipv4.min);
                    if (action->ct.range.ipv4.max) {
                        nl_msg_put_be32(request, TCA_CT_NAT_IPV4_MAX,
                                    action->ct.range.ipv4.max);
                    }
                } else if (action->ct.range.ip_family == AF_INET6) {

                    nl_msg_put_in6_addr(request, TCA_CT_NAT_IPV6_MIN,
                                        &action->ct.range.ipv6.min);
                    if (ipv6_addr_is_set(&action->ct.range.ipv6.max)) {
                        nl_msg_put_in6_addr(request, TCA_CT_NAT_IPV6_MAX,
                                            &action->ct.range.ipv6.max);
                    }
                }

                if (action->ct.range.port.min) {
                    nl_msg_put_be16(request, TCA_CT_NAT_PORT_MIN,
                                    action->ct.range.port.min);
                    if (action->ct.range.port.max) {
                        nl_msg_put_be16(request, TCA_CT_NAT_PORT_MAX,
                                        action->ct.range.port.max);
                    }
                }
            }
        } else {
            ct_action = TCA_CT_ACT_CLEAR;
        }

        nl_msg_put_u16(request, TCA_CT_ACTION, ct_action);
        nl_msg_put_unspec(request, TCA_CT_PARMS, &ct, sizeof ct);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_skbedit_to_host(struct ofpbuf *request)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "skbedit");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_skbedit s = { .action = TC_ACT_PIPE };

        nl_msg_put_unspec(request, TCA_SKBEDIT_PARMS, &s, sizeof s);
        nl_msg_put_be16(request, TCA_SKBEDIT_PTYPE, PACKET_HOST);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_mirred(struct ofpbuf *request, int ifindex, int action,
                      int eaction)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "mirred");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_mirred m = { .action = action,
                               .eaction = eaction,
                               .ifindex = ifindex };

        nl_msg_put_unspec(request, TCA_MIRRED_PARMS, &m, sizeof m);
    }
    nl_msg_end_nested(request, offset);
}

static inline void
nl_msg_put_act_cookie(struct ofpbuf *request, struct tc_cookie *ck) {
    if (ck->len) {
        nl_msg_put_unspec(request, TCA_ACT_COOKIE, ck->data, ck->len);
    }
}

static inline void
nl_msg_put_act_flags(struct ofpbuf *request) {
    struct nla_bitfield32 act_flags = { TCA_ACT_FLAGS_NO_PERCPU_STATS,
                                        TCA_ACT_FLAGS_NO_PERCPU_STATS };

    nl_msg_put_unspec(request, TCA_ACT_FLAGS, &act_flags, sizeof act_flags);
}

/* Given flower, a key_to_pedit map entry, calculates the rest,
 * where:
 *
 * mask, data - pointers of where read the first word of flower->key/mask.
 * current_offset - which offset to use for the first pedit action.
 * cnt - max pedits actions to use.
 * first_word_mask/last_word_mask - the mask to use for the first/last read
 * (as we read entire words). */
static void
calc_offsets(struct tc_action *action, struct flower_key_to_pedit *m,
             int *cur_offset, int *cnt, ovs_be32 *last_word_mask,
             ovs_be32 *first_word_mask, ovs_be32 **mask, ovs_be32 **data)
{
    int start_offset, max_offset, total_size;
    int diff, right_zero_bits, left_zero_bits;
    char *rewrite_key = (void *) &action->rewrite.key;
    char *rewrite_mask = (void *) &action->rewrite.mask;

    max_offset = m->offset + m->size;
    start_offset = ROUND_DOWN(m->offset, 4);
    diff = m->offset - start_offset;
    total_size = max_offset - start_offset;
    right_zero_bits = 8 * (4 - ((max_offset % 4) ? : 4));
    left_zero_bits = 8 * (m->offset - start_offset);

    *cur_offset = start_offset;
    *cnt = (total_size / 4) + (total_size % 4 ? 1 : 0);
    *last_word_mask = htonl(UINT32_MAX << right_zero_bits);
    *first_word_mask = htonl(UINT32_MAX >> left_zero_bits);
    *data = (void *) (rewrite_key + m->flower_offset - diff);
    *mask = (void *) (rewrite_mask + m->flower_offset - diff);
}

static inline int
csum_update_flag(struct tc_flower *flower,
                 enum pedit_header_type htype) {
    /* Explictily specifiy the csum flags so HW can return EOPNOTSUPP
     * if it doesn't support a checksum recalculation of some headers.
     * And since OVS allows a flow such as
     * eth(dst=<mac>),eth_type(0x0800) actions=set(ipv4(src=<new_ip>))
     * we need to force a more specific flow as this can, for example,
     * need a recalculation of icmp checksum if the packet that passes
     * is ICMPv6 and tcp checksum if its tcp.
     *
     * This section of the code must be kept in sync with the pre-check
     * function in netdev-offload-tc.c, tc_will_add_l4_checksum(). */

    switch (htype) {
    case TCA_PEDIT_KEY_EX_HDR_TYPE_IP4:
        flower->csum_update_flags |= TCA_CSUM_UPDATE_FLAG_IPV4HDR;
        /* Fall through. */
    case TCA_PEDIT_KEY_EX_HDR_TYPE_IP6:
    case TCA_PEDIT_KEY_EX_HDR_TYPE_TCP:
    case TCA_PEDIT_KEY_EX_HDR_TYPE_UDP:
        if (flower->key.ip_proto == IPPROTO_TCP) {
            flower->needs_full_ip_proto_mask = true;
            flower->csum_update_flags |= TCA_CSUM_UPDATE_FLAG_TCP;
        } else if (flower->key.ip_proto == IPPROTO_UDP) {
            flower->needs_full_ip_proto_mask = true;
            flower->csum_update_flags |= TCA_CSUM_UPDATE_FLAG_UDP;
        } else if (flower->key.ip_proto == IPPROTO_ICMP ||
                   flower->key.ip_proto == IPPROTO_IGMP ||
                   flower->key.ip_proto == IPPROTO_SCTP ||
                   flower->key.ip_proto == IPPROTO_IPIP ||
                   flower->key.ip_proto == IPPROTO_GRE) {
            flower->needs_full_ip_proto_mask = true;
        } else if (flower->key.ip_proto == IPPROTO_ICMPV6) {
            flower->needs_full_ip_proto_mask = true;
            flower->csum_update_flags |= TCA_CSUM_UPDATE_FLAG_ICMP;
        } else if (flower->key.ip_proto == IPPROTO_UDPLITE) {
            flower->needs_full_ip_proto_mask = true;
            flower->csum_update_flags |= TCA_CSUM_UPDATE_FLAG_UDPLITE;
        } else {
            VLOG_WARN_RL(&error_rl,
                         "can't offload rewrite of IP/IPV6 with ip_proto: %d",
                         flower->key.ip_proto);
            break;
        }
        /* Fall through. */
    case TCA_PEDIT_KEY_EX_HDR_TYPE_ETH:
        return 0; /* success */

    case TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK:
    case __PEDIT_HDR_TYPE_MAX:
    default:
        break;
    }

    return EOPNOTSUPP;
}

static bool
rewrite_pedits_need_csum_update(struct tc_action *action)
{
    int i, j;

    for (i = 0; i < ARRAY_SIZE(flower_pedit_map); i++) {
        struct flower_key_to_pedit *m = &flower_pedit_map[i];
        ovs_be32 *mask, *data, first_word_mask, last_word_mask;
        int cnt = 0, cur_offset = 0;

        if (!m->size) {
            continue;
        }

        calc_offsets(action, m, &cur_offset, &cnt, &last_word_mask,
                     &first_word_mask, &mask, &data);

        for (j = 0; j < cnt; j++,  mask++) {
            ovs_be32 mask_word = get_unaligned_be32(mask);

            if (j == 0) {
                mask_word &= first_word_mask;
            }
            if (j == cnt - 1) {
                mask_word &= last_word_mask;
            }
            if (!mask_word) {
                continue;
            }

            switch (m->htype) {
            case TCA_PEDIT_KEY_EX_HDR_TYPE_IP4:
            case TCA_PEDIT_KEY_EX_HDR_TYPE_IP6:
            case TCA_PEDIT_KEY_EX_HDR_TYPE_TCP:
            case TCA_PEDIT_KEY_EX_HDR_TYPE_UDP:
                return true;
            case TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK:
            case TCA_PEDIT_KEY_EX_HDR_TYPE_ETH:
            case __PEDIT_HDR_TYPE_MAX:
                break;
            }
        }
    }
    return false;
}

static int
nl_msg_put_flower_rewrite_pedits(struct ofpbuf *request,
                                 struct tc_flower *flower,
                                 struct tc_action *action,
                                 uint32_t action_pc)
{
    union {
        struct tc_pedit sel;
        uint8_t buffer[sizeof(struct tc_pedit)
                       + MAX_PEDIT_OFFSETS * sizeof(struct tc_pedit_key)];
    } sel;
    struct tc_pedit_key_ex keys_ex[MAX_PEDIT_OFFSETS];
    int i, j, err;

    memset(&sel, 0, sizeof sel);
    memset(keys_ex, 0, sizeof keys_ex);

    for (i = 0; i < ARRAY_SIZE(flower_pedit_map); i++) {
        struct flower_key_to_pedit *m = &flower_pedit_map[i];
        struct tc_pedit_key *pedit_key = NULL;
        struct tc_pedit_key_ex *pedit_key_ex = NULL;
        ovs_be32 *mask, *data, first_word_mask, last_word_mask;
        int cnt = 0, cur_offset = 0;

        if (!m->size) {
            continue;
        }

        calc_offsets(action, m, &cur_offset, &cnt, &last_word_mask,
                     &first_word_mask, &mask, &data);

        for (j = 0; j < cnt; j++,  mask++, data++, cur_offset += 4) {
            ovs_be32 mask_word = get_unaligned_be32(mask);
            ovs_be32 data_word = get_unaligned_be32(data);

            if (j == 0) {
                mask_word &= first_word_mask;
            }
            if (j == cnt - 1) {
                mask_word &= last_word_mask;
            }
            if (!mask_word) {
                continue;
            }
            if (sel.sel.nkeys == MAX_PEDIT_OFFSETS) {
                VLOG_WARN_RL(&error_rl, "reached too many pedit offsets: %d",
                             MAX_PEDIT_OFFSETS);
                return EOPNOTSUPP;
            }

            pedit_key = &sel.sel.keys[sel.sel.nkeys];
            pedit_key_ex = &keys_ex[sel.sel.nkeys];
            pedit_key_ex->cmd = TCA_PEDIT_KEY_EX_CMD_SET;
            pedit_key_ex->htype = m->htype;
            pedit_key->off = cur_offset;
            mask_word = htonl(ntohl(mask_word) >> m->boundary_shift);
            data_word = htonl(ntohl(data_word) >> m->boundary_shift);
            pedit_key->mask = ~mask_word;
            pedit_key->val = data_word & mask_word;
            sel.sel.nkeys++;

            err = csum_update_flag(flower, m->htype);
            if (err) {
                return err;
            }

            if (flower->needs_full_ip_proto_mask) {
                flower->mask.ip_proto = UINT8_MAX;
            }
        }
    }
    nl_msg_put_act_pedit(request, &sel.sel, keys_ex,
                         flower->csum_update_flags ? TC_ACT_PIPE : action_pc);

    return 0;
}

static void
nl_msg_put_flower_acts_release(struct ofpbuf *request, uint16_t act_index)
{
    size_t act_offset;

    act_offset = nl_msg_start_nested(request, act_index);
    nl_msg_put_act_tunnel_key_release(request);
    nl_msg_put_act_flags(request);
    nl_msg_end_nested(request, act_offset);
}

/* Aggregates all previous successive pedit actions csum_update_flags
 * to flower->csum_update_flags. Only append one csum action to the
 * last pedit action. */
static void
nl_msg_put_csum_act(struct ofpbuf *request, struct tc_flower *flower,
                    uint32_t action_pc, uint16_t *act_index)
{
    size_t act_offset;

    /* No pedit actions or processed already. */
    if (!flower->csum_update_flags) {
        return;
    }

    act_offset = nl_msg_start_nested(request, (*act_index)++);
    nl_msg_put_act_csum(request, flower->csum_update_flags, action_pc);
    nl_msg_put_act_flags(request);
    nl_msg_end_nested(request, act_offset);

    /* Clear it. So we can have another series of pedit actions. */
    flower->csum_update_flags = 0;
}

static int
get_action_index_for_tc_actions(struct tc_flower *flower, uint16_t act_index,
                                struct tc_action *action, int action_count,
                                bool tunnel_key_released)
{
    bool need_csum = false;

    if (action_count < 0) {
        /* Only forward jumps are supported */
        return -EINVAL;
    }

    for (int i = 0; i < action_count; i++, action++) {
        if (action->type != TC_ACT_PEDIT && need_csum) {
            need_csum = false;
            act_index++;
        }

        switch (action->type) {

        case TC_ACT_OUTPUT:
            if (!tunnel_key_released && flower->tunnel) {
                act_index++;
                tunnel_key_released = true;
            }
            if (action->out.ingress) {
                act_index++;
            }
            act_index++;
            break;

        case TC_ACT_ENCAP:
            if (!tunnel_key_released && flower->tunnel) {
                act_index++;
                tunnel_key_released = true;
            }
            act_index++;
            break;

        case TC_ACT_PEDIT:
            if (!need_csum) {
                need_csum = rewrite_pedits_need_csum_update(action);
            }
            if (i == (action_count - 1) && need_csum) {
                need_csum = false;
                act_index++;
            }
            act_index++;
            break;

        case TC_ACT_POLICE:
        case TC_ACT_POLICE_MTU:
        case TC_ACT_VLAN_POP:
        case TC_ACT_VLAN_PUSH:
        case TC_ACT_MPLS_POP:
        case TC_ACT_MPLS_PUSH:
        case TC_ACT_MPLS_SET:
        case TC_ACT_GOTO:
        case TC_ACT_CT:
            /* Increase act_index by one if we are sure this type of action
             * will only add one tc action in the kernel. */
            act_index++;
            break;

            /* If we can't determine how many tc actions will be added by the
             * kernel return -EOPNOTSUPP.
             *
             * Please do NOT add a default case. */
        }
    }

    return act_index;
}

static int
nl_msg_put_act_police_mtu(struct ofpbuf *request, struct tc_flower *flower,
                          struct tc_action *action, uint32_t action_pc,
                          int action_index, uint16_t act_index, bool released)
{
    uint32_t tc_action;
    size_t offset;

    if (action->police.result_jump != JUMP_ACTION_STOP) {
        int jump_index;
        int action_count = action->police.result_jump - action_index - 1;

        jump_index = get_action_index_for_tc_actions(flower,
                                                     act_index - 1,
                                                     action + 1,
                                                     action_count,
                                                     released);
        if (jump_index < 0) {
            return -jump_index;
        }
        tc_action = TC_ACT_JUMP | (jump_index & TC_ACT_EXT_VAL_MASK);
    } else {
        tc_action = TC_ACT_STOLEN;
    }

    nl_msg_put_string(request, TCA_ACT_KIND, "police");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_police p = { .action = action_pc,
            .mtu = action->police.mtu };

        nl_msg_put_unspec(request, TCA_POLICE_TBF, &p, sizeof p);

        /* The value in jump_action is the total number of TC_ACT_*
         * we need to jump, not the actual number of TCA_ACT_KIND
         * (act_index) actions. As certain TC_ACT_* actions can be
         * translated into multiple TCA_ACT_KIND ones.
         *
         * See nl_msg_put_flower_acts() below for more details. */
        nl_msg_put_u32(request, TCA_POLICE_RESULT, tc_action);
    }
    nl_msg_end_nested(request, offset);
    return 0;
}

static int
nl_msg_put_flower_acts(struct ofpbuf *request, struct tc_flower *flower)
{
    bool ingress, released = false;
    size_t offset;
    size_t act_offset;
    uint16_t act_index = 1;
    struct tc_action *action;
    int i, ifindex = 0;

    offset = nl_msg_start_nested(request, TCA_FLOWER_ACT);
    {
        int error;
        uint32_t prev_action_pc = TC_ACT_PIPE;

        action = flower->actions;
        for (i = 0; i < flower->action_count; i++, action++) {
            uint32_t action_pc; /* Programmatic Control */

            if (!action->jump_action) {
                if (i == flower->action_count - 1) {
                    action_pc = TC_ACT_SHOT;
                } else {
                    action_pc = TC_ACT_PIPE;
                }
            } else if (action->jump_action == JUMP_ACTION_STOP) {
                action_pc = TC_ACT_STOLEN;
            } else {
                /* The value in jump_action is the total number of TC_ACT_*
                 * we need to jump, not the actual number of TCA_ACT_KIND
                 * (act_index) actions. As certain TC_ACT_* actions can be
                 * translated into multiple TCA_ACT_KIND ones.
                 *
                 * If we can determine the number of actual actions being
                 * inserted we will update the count, if not we will return
                 * -EOPNOTSUPP.
                 */
                int jump_index;
                int act_index_start = act_index - 1;
                int action_count = (action->jump_action &
                                    TC_ACT_EXT_VAL_MASK) - i;

                if (flower->csum_update_flags &&
                    (action->type != TC_ACT_PEDIT
                     || prev_action_pc & TC_ACT_JUMP)) {
                    act_index_start++;
                }

                jump_index = get_action_index_for_tc_actions(flower,
                                                             act_index_start,
                                                             action,
                                                             action_count,
                                                             released);
                if (jump_index < 0) {
                    return -jump_index;
                }

                action_pc = TC_ACT_JUMP | jump_index;
            }

            if (action->type != TC_ACT_PEDIT || prev_action_pc & TC_ACT_JUMP) {
                nl_msg_put_csum_act(request, flower, prev_action_pc,
                                    &act_index);
            }

            switch (action->type) {
            case TC_ACT_PEDIT: {
                act_offset = nl_msg_start_nested(request, act_index++);
                error = nl_msg_put_flower_rewrite_pedits(request, flower,
                                                         action, action_pc);
                if (error) {
                    return error;
                }
                nl_msg_end_nested(request, act_offset);

                if (i == flower->action_count - 1) {
                    /* If this is the last action check csum calc again. */
                    nl_msg_put_csum_act(request, flower, action_pc,
                                        &act_index);
                }
            }
            break;
            case TC_ACT_ENCAP: {
                if (!released && flower->tunnel) {
                    nl_msg_put_flower_acts_release(request, act_index++);
                    released = true;
                }

                act_offset = nl_msg_start_nested(request, act_index++);
                nl_msg_put_act_tunnel_key_set(request, &action->encap,
                                              action_pc);
                nl_msg_put_act_flags(request);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_VLAN_POP: {
                act_offset = nl_msg_start_nested(request, act_index++);
                nl_msg_put_act_pop_vlan(request, action_pc);
                nl_msg_put_act_flags(request);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_VLAN_PUSH: {
                act_offset = nl_msg_start_nested(request, act_index++);
                nl_msg_put_act_push_vlan(request,
                                         action->vlan.vlan_push_tpid,
                                         action->vlan.vlan_push_id,
                                         action->vlan.vlan_push_prio,
                                         action_pc);
                nl_msg_put_act_flags(request);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_MPLS_POP: {
                act_offset = nl_msg_start_nested(request, act_index++);
                nl_msg_put_act_pop_mpls(request, action->mpls.proto,
                                        action_pc);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_MPLS_PUSH: {
                act_offset = nl_msg_start_nested(request, act_index++);
                nl_msg_put_act_push_mpls(request, action->mpls.proto,
                                         action->mpls.label, action->mpls.tc,
                                         action->mpls.ttl, action->mpls.bos,
                                         action_pc);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_MPLS_SET: {
                act_offset = nl_msg_start_nested(request, act_index++);
                nl_msg_put_act_set_mpls(request, action->mpls.label,
                                        action->mpls.tc, action->mpls.ttl,
                                        action->mpls.bos, action_pc);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_OUTPUT: {
                if (!released && flower->tunnel) {
                    nl_msg_put_flower_acts_release(request, act_index++);
                    released = true;
                }

                ingress = action->out.ingress;
                ifindex = action->out.ifindex_out;
                if (ifindex < 1) {
                    VLOG_ERR_RL(&error_rl, "%s: invalid ifindex: %d, type: %d",
                                __func__, ifindex, action->type);
                    return EINVAL;
                }

                if (ingress) {
                    /* If redirecting to ingress (internal port) ensure
                     * pkt_type on skb is set to PACKET_HOST. */
                    act_offset = nl_msg_start_nested(request, act_index++);
                    nl_msg_put_act_skbedit_to_host(request);
                    nl_msg_end_nested(request, act_offset);
                }

                act_offset = nl_msg_start_nested(request, act_index++);
                if (i == flower->action_count - 1) {
                    if (ingress) {
                        nl_msg_put_act_mirred(request, ifindex, TC_ACT_STOLEN,
                                              TCA_INGRESS_REDIR);
                    } else {
                        nl_msg_put_act_mirred(request, ifindex, TC_ACT_STOLEN,
                                              TCA_EGRESS_REDIR);
                    }
                    action->jump_action = JUMP_ACTION_STOP;
                } else {
                    if (ingress) {
                        nl_msg_put_act_mirred(request, ifindex, action_pc,
                                              TCA_INGRESS_MIRROR);
                    } else {
                        nl_msg_put_act_mirred(request, ifindex, action_pc,
                                              TCA_EGRESS_MIRROR);
                    }
                }
                nl_msg_put_act_cookie(request, &flower->act_cookie);
                nl_msg_put_act_flags(request);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_GOTO: {
                if (released) {
                    /* We don't support tunnel release + output + goto
                     * for now, as next chain by default will try and match
                     * the tunnel metadata that was released/unset.
                     *
                     * This will happen with tunnel + mirror ports.
                     */
                    return -EOPNOTSUPP;
                }

                act_offset = nl_msg_start_nested(request, act_index++);
                nl_msg_put_act_gact(request, action->chain);
                nl_msg_put_act_cookie(request, &flower->act_cookie);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_CT: {
                act_offset = nl_msg_start_nested(request, act_index++);
                nl_msg_put_act_ct(request, action, action_pc);
                nl_msg_put_act_cookie(request, &flower->act_cookie);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_POLICE: {
                act_offset = nl_msg_start_nested(request, act_index++);
                nl_msg_put_act_police_index(request, action->police.index,
                                            action_pc);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            case TC_ACT_POLICE_MTU: {
                act_offset = nl_msg_start_nested(request, act_index++);
                if (nl_msg_put_act_police_mtu(request, flower, action,
                                              action_pc, i, act_index,
                                              released)) {
                    return -EOPNOTSUPP;
                }
                nl_msg_put_act_cookie(request, &flower->act_cookie);
                nl_msg_put_act_flags(request);
                nl_msg_end_nested(request, act_offset);
            }
            break;
            }

            prev_action_pc = action_pc;
        }
    }

    if (!flower->action_count) {
        act_offset = nl_msg_start_nested(request, act_index++);
        nl_msg_put_act_gact(request, 0);
        nl_msg_put_act_cookie(request, &flower->act_cookie);
        nl_msg_put_act_flags(request);
        nl_msg_end_nested(request, act_offset);
    }
    nl_msg_end_nested(request, offset);

    return 0;
}

static void
nl_msg_put_masked_value(struct ofpbuf *request, uint16_t type,
                        uint16_t mask_type, const void *data,
                        const void *mask_data, size_t len)
{
    if (mask_type != TCA_FLOWER_UNSPEC) {
        if (is_all_zeros(mask_data, len)) {
            return;
        }
        nl_msg_put_unspec(request, mask_type, mask_data, len);
    }
    nl_msg_put_unspec(request, type, data, len);
}

static void
nl_msg_put_flower_geneve(struct ofpbuf *request,
                         const struct tc_flower_tunnel *tunnel)
{
    const struct tun_metadata *metadata = &tunnel->metadata;
    const struct geneve_opt *opt;
    int len, cnt = 0;
    size_t offset;

    len = metadata->present.len;
    while (len) {
        opt = &metadata->opts.gnv[cnt];
        offset = nl_msg_start_nested(request, TCA_FLOWER_KEY_ENC_OPTS_GENEVE);

        nl_msg_put_be16(request, TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS,
                        opt->opt_class);
        nl_msg_put_u8(request, TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE, opt->type);
        nl_msg_put_unspec(request, TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA, opt + 1,
                          opt->length * 4);

        cnt += sizeof(struct geneve_opt) / 4 + opt->length;
        len -= sizeof(struct geneve_opt) + opt->length * 4;

        nl_msg_end_nested(request, offset);
    }
}

static void
nl_msg_put_flower_vxlan_tun_opts(struct ofpbuf *request,
                                 const struct tc_flower_tunnel *tunnel)
{
    uint32_t gbp_raw;
    size_t offset;

    if (!tunnel->gbp.id_present) {
        return;
    }

    gbp_raw = odp_encode_gbp_raw(tunnel->gbp.flags, tunnel->gbp.id);
    offset = nl_msg_start_nested_with_flag(request,
                                           TCA_FLOWER_KEY_ENC_OPTS_VXLAN);
    nl_msg_put_u32(request, TCA_FLOWER_KEY_ENC_OPT_VXLAN_GBP, gbp_raw);
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_flower_tunnel_opts(struct ofpbuf *request, uint16_t type,
                              struct tc_flower_tunnel *tunnel)
{
    size_t outer;

    if (!tunnel->metadata.present.len && !tunnel->gbp.id_present) {
        return;
    }

    outer = nl_msg_start_nested(request, type);
    nl_msg_put_flower_geneve(request, tunnel);
    nl_msg_put_flower_vxlan_tun_opts(request, tunnel);
    nl_msg_end_nested(request, outer);
}

static void
nl_msg_put_flower_tunnel(struct ofpbuf *request, struct tc_flower *flower)
{
    ovs_be32 ipv4_src_mask = flower->mask.tunnel.ipv4.ipv4_src;
    ovs_be32 ipv4_dst_mask = flower->mask.tunnel.ipv4.ipv4_dst;
    ovs_be32 ipv4_src = flower->key.tunnel.ipv4.ipv4_src;
    ovs_be32 ipv4_dst = flower->key.tunnel.ipv4.ipv4_dst;
    struct in6_addr *ipv6_src_mask = &flower->mask.tunnel.ipv6.ipv6_src;
    struct in6_addr *ipv6_dst_mask = &flower->mask.tunnel.ipv6.ipv6_dst;
    struct in6_addr *ipv6_src = &flower->key.tunnel.ipv6.ipv6_src;
    struct in6_addr *ipv6_dst = &flower->key.tunnel.ipv6.ipv6_dst;
    ovs_be32 id = be64_to_be32(flower->key.tunnel.id);
    ovs_be16 tp_src = flower->key.tunnel.tp_src;
    ovs_be16 tp_dst = flower->key.tunnel.tp_dst;
    uint8_t tos = flower->key.tunnel.tos;
    uint8_t ttl = flower->key.tunnel.ttl;
    uint8_t tos_mask = flower->mask.tunnel.tos;
    uint8_t ttl_mask = flower->mask.tunnel.ttl;
    ovs_be64 id_mask = flower->mask.tunnel.id;
    ovs_be16 tp_src_mask = flower->mask.tunnel.tp_src;
    ovs_be16 tp_dst_mask = flower->mask.tunnel.tp_dst;

    if (ipv4_dst_mask || ipv4_src_mask) {
        nl_msg_put_be32(request, TCA_FLOWER_KEY_ENC_IPV4_DST_MASK,
                        ipv4_dst_mask);
        nl_msg_put_be32(request, TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK,
                        ipv4_src_mask);
        nl_msg_put_be32(request, TCA_FLOWER_KEY_ENC_IPV4_DST, ipv4_dst);
        nl_msg_put_be32(request, TCA_FLOWER_KEY_ENC_IPV4_SRC, ipv4_src);
    } else if (ipv6_addr_is_set(ipv6_dst_mask) ||
               ipv6_addr_is_set(ipv6_src_mask)) {
        nl_msg_put_in6_addr(request, TCA_FLOWER_KEY_ENC_IPV6_DST_MASK,
                            ipv6_dst_mask);
        nl_msg_put_in6_addr(request, TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK,
                            ipv6_src_mask);
        nl_msg_put_in6_addr(request, TCA_FLOWER_KEY_ENC_IPV6_DST, ipv6_dst);
        nl_msg_put_in6_addr(request, TCA_FLOWER_KEY_ENC_IPV6_SRC, ipv6_src);
    }
    if (tos_mask) {
        nl_msg_put_u8(request, TCA_FLOWER_KEY_ENC_IP_TOS, tos);
        nl_msg_put_u8(request, TCA_FLOWER_KEY_ENC_IP_TOS_MASK, tos_mask);
    }
    if (ttl_mask) {
        nl_msg_put_u8(request, TCA_FLOWER_KEY_ENC_IP_TTL, ttl);
        nl_msg_put_u8(request, TCA_FLOWER_KEY_ENC_IP_TTL_MASK, ttl_mask);
    }
    if (tp_src_mask) {
        nl_msg_put_be16(request, TCA_FLOWER_KEY_ENC_UDP_SRC_PORT, tp_src);
        nl_msg_put_be16(request, TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK,
                        tp_src_mask);
    }
    if (tp_dst_mask) {
        nl_msg_put_be16(request, TCA_FLOWER_KEY_ENC_UDP_DST_PORT, tp_dst);
        nl_msg_put_be16(request, TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK,
                        tp_dst_mask);
    }
    if (id_mask) {
        nl_msg_put_be32(request, TCA_FLOWER_KEY_ENC_KEY_ID, id);
    }
    nl_msg_put_flower_tunnel_opts(request, TCA_FLOWER_KEY_ENC_OPTS,
                                  &flower->key.tunnel);
    nl_msg_put_flower_tunnel_opts(request, TCA_FLOWER_KEY_ENC_OPTS_MASK,
                                  &flower->mask.tunnel);
}

#define FLOWER_PUT_MASKED_VALUE(member, type) \
    nl_msg_put_masked_value(request, type, type##_MASK, &flower->key.member, \
                            &flower->mask.member, sizeof flower->key.member)

static int
nl_msg_put_flower_options(struct ofpbuf *request, struct tc_flower *flower)
{

    uint16_t host_eth_type = ntohs(flower->key.eth_type);
    bool is_vlan = eth_type_vlan(flower->key.eth_type);
    bool is_qinq = is_vlan && eth_type_vlan(flower->key.encap_eth_type[0]);
    bool is_mpls = eth_type_mpls(flower->key.eth_type);
    enum tc_offload_policy policy = flower->tc_policy;
    int err;

    /* need to parse acts first as some acts require changing the matching
     * see csum_update_flag()  */
    err  = nl_msg_put_flower_acts(request, flower);
    if (err) {
        return err;
    }

    if (is_vlan) {
        if (is_qinq) {
            host_eth_type = ntohs(flower->key.encap_eth_type[1]);
        } else {
            host_eth_type = ntohs(flower->key.encap_eth_type[0]);
        }
    }

    if (is_mpls) {
        host_eth_type = ntohs(flower->key.encap_eth_type[0]);
    }

    FLOWER_PUT_MASKED_VALUE(dst_mac, TCA_FLOWER_KEY_ETH_DST);
    FLOWER_PUT_MASKED_VALUE(src_mac, TCA_FLOWER_KEY_ETH_SRC);

    if (host_eth_type == ETH_P_ARP) {
        FLOWER_PUT_MASKED_VALUE(arp.spa, TCA_FLOWER_KEY_ARP_SIP);
        FLOWER_PUT_MASKED_VALUE(arp.tpa, TCA_FLOWER_KEY_ARP_TIP);
        FLOWER_PUT_MASKED_VALUE(arp.sha, TCA_FLOWER_KEY_ARP_SHA);
        FLOWER_PUT_MASKED_VALUE(arp.tha, TCA_FLOWER_KEY_ARP_THA);
        FLOWER_PUT_MASKED_VALUE(arp.opcode, TCA_FLOWER_KEY_ARP_OP);
    }

    if (host_eth_type == ETH_P_IP || host_eth_type == ETH_P_IPV6) {
        FLOWER_PUT_MASKED_VALUE(ip_ttl, TCA_FLOWER_KEY_IP_TTL);
        FLOWER_PUT_MASKED_VALUE(ip_tos, TCA_FLOWER_KEY_IP_TOS);

        if (flower->mask.ip_proto && flower->key.ip_proto) {
            nl_msg_put_u8(request, TCA_FLOWER_KEY_IP_PROTO,
                          flower->key.ip_proto);
        }

        if (flower->mask.flags) {
            nl_msg_put_be32(request, TCA_FLOWER_KEY_FLAGS,
                           htonl(flower->key.flags));
            nl_msg_put_be32(request, TCA_FLOWER_KEY_FLAGS_MASK,
                           htonl(flower->mask.flags));
        }

        if (flower->key.ip_proto == IPPROTO_UDP) {
            FLOWER_PUT_MASKED_VALUE(udp_src, TCA_FLOWER_KEY_UDP_SRC);
            FLOWER_PUT_MASKED_VALUE(udp_dst, TCA_FLOWER_KEY_UDP_DST);
        } else if (flower->key.ip_proto == IPPROTO_TCP) {
            FLOWER_PUT_MASKED_VALUE(tcp_src, TCA_FLOWER_KEY_TCP_SRC);
            FLOWER_PUT_MASKED_VALUE(tcp_dst, TCA_FLOWER_KEY_TCP_DST);
            FLOWER_PUT_MASKED_VALUE(tcp_flags, TCA_FLOWER_KEY_TCP_FLAGS);
        } else if (flower->key.ip_proto == IPPROTO_SCTP) {
            FLOWER_PUT_MASKED_VALUE(sctp_src, TCA_FLOWER_KEY_SCTP_SRC);
            FLOWER_PUT_MASKED_VALUE(sctp_dst, TCA_FLOWER_KEY_SCTP_DST);
        } else if (flower->key.ip_proto == IPPROTO_ICMP) {
            FLOWER_PUT_MASKED_VALUE(icmp_code, TCA_FLOWER_KEY_ICMPV4_CODE);
            FLOWER_PUT_MASKED_VALUE(icmp_type, TCA_FLOWER_KEY_ICMPV4_TYPE);
        } else if (flower->key.ip_proto == IPPROTO_ICMPV6) {
            FLOWER_PUT_MASKED_VALUE(icmp_code, TCA_FLOWER_KEY_ICMPV6_CODE);
            FLOWER_PUT_MASKED_VALUE(icmp_type, TCA_FLOWER_KEY_ICMPV6_TYPE);
        }
    }

    FLOWER_PUT_MASKED_VALUE(ct_state, TCA_FLOWER_KEY_CT_STATE);
    FLOWER_PUT_MASKED_VALUE(ct_zone, TCA_FLOWER_KEY_CT_ZONE);
    FLOWER_PUT_MASKED_VALUE(ct_mark, TCA_FLOWER_KEY_CT_MARK);
    FLOWER_PUT_MASKED_VALUE(ct_label, TCA_FLOWER_KEY_CT_LABELS);

    if (host_eth_type == ETH_P_IP) {
            FLOWER_PUT_MASKED_VALUE(ipv4.ipv4_src, TCA_FLOWER_KEY_IPV4_SRC);
            FLOWER_PUT_MASKED_VALUE(ipv4.ipv4_dst, TCA_FLOWER_KEY_IPV4_DST);
    } else if (host_eth_type == ETH_P_IPV6) {
            FLOWER_PUT_MASKED_VALUE(ipv6.ipv6_src, TCA_FLOWER_KEY_IPV6_SRC);
            FLOWER_PUT_MASKED_VALUE(ipv6.ipv6_dst, TCA_FLOWER_KEY_IPV6_DST);
    }

    nl_msg_put_be16(request, TCA_FLOWER_KEY_ETH_TYPE, flower->key.eth_type);

    if (is_mpls) {
        if (mpls_lse_to_ttl(flower->mask.mpls_lse)) {
            nl_msg_put_u8(request, TCA_FLOWER_KEY_MPLS_TTL,
                          mpls_lse_to_ttl(flower->key.mpls_lse));
        }
        if (mpls_lse_to_tc(flower->mask.mpls_lse)) {
            nl_msg_put_u8(request, TCA_FLOWER_KEY_MPLS_TC,
                          mpls_lse_to_tc(flower->key.mpls_lse));
        }
        if (mpls_lse_to_bos(flower->mask.mpls_lse)) {
            nl_msg_put_u8(request, TCA_FLOWER_KEY_MPLS_BOS,
                          mpls_lse_to_bos(flower->key.mpls_lse));
        }
        if (mpls_lse_to_label(flower->mask.mpls_lse)) {
            nl_msg_put_u32(request, TCA_FLOWER_KEY_MPLS_LABEL,
                           mpls_lse_to_label(flower->key.mpls_lse));
        }
    }

    if (is_vlan) {
        if (flower->mask.vlan_id[0]) {
            nl_msg_put_u16(request, TCA_FLOWER_KEY_VLAN_ID,
                           flower->key.vlan_id[0]);
        }
        if (flower->mask.vlan_prio[0]) {
            nl_msg_put_u8(request, TCA_FLOWER_KEY_VLAN_PRIO,
                          flower->key.vlan_prio[0]);
        }
        if (flower->key.encap_eth_type[0]) {
            nl_msg_put_be16(request, TCA_FLOWER_KEY_VLAN_ETH_TYPE,
                            flower->key.encap_eth_type[0]);
        }

        if (is_qinq) {
            if (flower->mask.vlan_id[1]) {
                nl_msg_put_u16(request, TCA_FLOWER_KEY_CVLAN_ID,
                               flower->key.vlan_id[1]);
            }
            if (flower->mask.vlan_prio[1]) {
                nl_msg_put_u8(request, TCA_FLOWER_KEY_CVLAN_PRIO,
                              flower->key.vlan_prio[1]);
            }
            if (flower->key.encap_eth_type[1]) {
                nl_msg_put_be16(request, TCA_FLOWER_KEY_CVLAN_ETH_TYPE,
                                flower->key.encap_eth_type[1]);
            }
        }
    }

    if (policy == TC_POLICY_NONE) {
        policy = tc_policy;
    }

    nl_msg_put_u32(request, TCA_FLOWER_FLAGS, tc_get_tc_cls_policy(policy));

    if (flower->tunnel) {
        nl_msg_put_flower_tunnel(request, flower);
    }

    return 0;
}

static void
log_tc_flower_match(const char *msg,
                    const struct tc_flower *a,
                    const struct tc_flower *b)
{
    uint8_t key_a[sizeof(struct tc_flower_key)];
    uint8_t key_b[sizeof(struct tc_flower_key)];
    struct ds s = DS_EMPTY_INITIALIZER;

    for (int i = 0; i < sizeof a->key; i++) {
        uint8_t mask_a = ((uint8_t *) &a->mask)[i];
        uint8_t mask_b = ((uint8_t *) &b->mask)[i];

        key_a[i] = ((uint8_t *) &a->key)[i] & mask_a;
        key_b[i] = ((uint8_t *) &b->key)[i] & mask_b;
    }
    ds_put_cstr(&s, "\nExpected Mask:\n");
    ds_put_sparse_hex_dump(&s, &a->mask, sizeof a->mask, 0, false);
    ds_put_cstr(&s, "\nReceived Mask:\n");
    ds_put_sparse_hex_dump(&s, &b->mask, sizeof b->mask, 0, false);
    ds_put_cstr(&s, "\nExpected Key:\n");
    ds_put_sparse_hex_dump(&s, &a->key, sizeof a->key, 0, false);
    ds_put_cstr(&s, "\nReceived Key:\n");
    ds_put_sparse_hex_dump(&s, &b->key, sizeof b->key, 0, false);
    ds_put_cstr(&s, "\nExpected Masked Key:\n");
    ds_put_sparse_hex_dump(&s, key_a, sizeof key_a, 0, false);
    ds_put_cstr(&s, "\nReceived Masked Key:\n");
    ds_put_sparse_hex_dump(&s, key_b, sizeof key_b, 0, false);

    if (a->action_count != b->action_count) {
        /* If action count is not equal, we print all actions to see which
         * ones are missing. */
        const struct tc_action *action;
        int i;

        ds_put_cstr(&s, "\nExpected Actions:\n");
        for (i = 0, action = a->actions; i < a->action_count; i++, action++) {
            ds_put_format(&s, " - %d -\n", i);
            ds_put_sparse_hex_dump(&s, action, sizeof *action, 0, false);
        }
        ds_put_cstr(&s, "\nReceived Actions:\n");
        for (i = 0, action = b->actions; i < b->action_count; i++, action++) {
            ds_put_format(&s, " - %d -\n", i);
            ds_put_sparse_hex_dump(&s, action, sizeof *action, 0, false);
        }
    } else {
        /* Only dump the delta in actions. */
        const struct tc_action *action_a = a->actions;
        const struct tc_action *action_b = b->actions;

        for (int i = 0; i < a->action_count; i++, action_a++, action_b++) {
            if (memcmp(action_a, action_b, sizeof *action_a)) {
                ds_put_format(&s, "\nAction %d mismatch:\n"
                                  " - Expected Action:\n", i);
                ds_put_sparse_hex_dump(&s, action_a, sizeof *action_a,
                                       0, false);
                ds_put_cstr(&s, " - Received Action:\n");
                ds_put_sparse_hex_dump(&s, action_b, sizeof *action_b,
                                       0, false);
            }
        }
    }
    VLOG_DBG_RL(&error_rl, "%s%s", msg, ds_cstr(&s));
    ds_destroy(&s);
}

static bool
cmp_tc_flower_match_action(const struct tc_flower *a,
                           const struct tc_flower *b)
{
    if (memcmp(&a->mask, &b->mask, sizeof a->mask)) {
        log_tc_flower_match("tc flower compare failed mask compare:", a, b);
        return false;
    }

    /* We can not memcmp() the key as some keys might be set while the mask
     * is not.*/

    for (int i = 0; i < sizeof a->key; i++) {
        uint8_t mask = ((uint8_t *)&a->mask)[i];
        uint8_t key_a = ((uint8_t *)&a->key)[i] & mask;
        uint8_t key_b = ((uint8_t *)&b->key)[i] & mask;

        if (key_a != key_b) {
            log_tc_flower_match("tc flower compare failed masked key compare:",
                                a, b);
            return false;
        }
    }

    /* Compare the actions. */
    const struct tc_action *action_a = a->actions;
    const struct tc_action *action_b = b->actions;

    if (a->action_count != b->action_count) {
        log_tc_flower_match("tc flower compare failed action length check",
                            a, b);
        return false;
    }

    for (int i = 0; i < a->action_count; i++, action_a++, action_b++) {
        if (memcmp(action_a, action_b, sizeof *action_a)) {
            log_tc_flower_match("tc flower compare failed action compare",
                                a, b);
            return false;
        }
    }

    return true;
}

int
tc_replace_flower(struct tcf_id *id, struct tc_flower *flower)
{
    struct ofpbuf request;
    struct ofpbuf *reply;
    int error = 0;
    size_t basic_offset;
    uint16_t eth_type = (OVS_FORCE uint16_t) flower->key.eth_type;

    request_from_tcf_id(id, eth_type, RTM_NEWTFILTER,
                        NLM_F_CREATE | NLM_F_ECHO, &request);

    nl_msg_put_string(&request, TCA_KIND, "flower");
    basic_offset = nl_msg_start_nested(&request, TCA_OPTIONS);
    {
        error = nl_msg_put_flower_options(&request, flower);

        if (error) {
            ofpbuf_uninit(&request);
            return error;
        }
    }
    nl_msg_end_nested(&request, basic_offset);

    error = tc_transact(&request, &reply);
    if (!error) {
        struct ofpbuf b = ofpbuf_const_initializer(reply->data, reply->size);
        struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
        struct tcmsg *tc = ofpbuf_try_pull(&b, sizeof *tc);

        if (!nlmsg || !tc) {
            COVERAGE_INC(tc_netlink_malformed_reply);
            ofpbuf_delete(reply);
            return EPROTO;
        }

        id->prio = tc_get_major(tc->tcm_info);
        id->handle = tc->tcm_handle;

        if (id->prio != TC_RESERVED_PRIORITY_POLICE) {
            struct tc_flower flower_out;
            struct tcf_id id_out;
            int ret;

            ret = parse_netlink_to_tc_flower(reply, &id_out, &flower_out,
                                             false);

            if (ret || !cmp_tc_flower_match_action(flower, &flower_out)) {
                VLOG_WARN_RL(&error_rl, "Kernel flower acknowledgment does "
                             "not match request!  Set dpif_netlink to dbg to "
                             "see which rule caused this error.");
            }
        }
        ofpbuf_delete(reply);
    }

    return error;
}

void
tc_set_policy(const char *policy)
{
    if (!policy) {
        return;
    }

    if (!strcmp(policy, "skip_sw")) {
        tc_policy = TC_POLICY_SKIP_SW;
    } else if (!strcmp(policy, "skip_hw")) {
        tc_policy = TC_POLICY_SKIP_HW;
    } else if (!strcmp(policy, "none")) {
        tc_policy = TC_POLICY_NONE;
    } else {
        VLOG_WARN("tc: Invalid policy '%s'", policy);
        return;
    }

    VLOG_INFO("tc: Using policy '%s'", policy);
}

void
nl_msg_put_act_tc_policy_flag(struct ofpbuf *request)
{
    int flag = 0;

    if (!request) {
        return;
    }

    if (tc_policy == TC_POLICY_SKIP_HW) {
        flag = TCA_ACT_FLAGS_SKIP_HW;
    } else if (tc_policy == TC_POLICY_SKIP_SW) {
        flag = TCA_ACT_FLAGS_SKIP_SW;
    }

    if (flag) {
        struct nla_bitfield32 flags = { flag, flag };
        nl_msg_put_unspec(request, TCA_ACT_FLAGS, &flags, sizeof flags);
    }
}
