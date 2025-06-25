/*
 * Copyright (c) 2015 Nicira, Inc.
 * Copyright (c) 2014 WindRiver, Inc.
 * Copyright (c) 2015 Avaya, Inc.
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

/* Implementation of Auto Attach.
 * Based on sample implementation in 802.1ab.  Above copyright and license
 * applies to all modifications.
 * Limitations:
 * - No support for multiple bridge.
 * - Auto Attach state machine not implemented.
 * - Auto Attach and LLDP code are bundled together.  The plan is to decoupled
 *   them.
 */

#include <config.h>
#include "ovs-lldp.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "flow.h"
#include "openvswitch/list.h"
#include "lldp/lldp-const.h"
#include "lldp/lldp-tlv.h"
#include "lldp/lldpd.h"
#include "lldp/lldpd-structs.h"
#include "netdev.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "smap.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovs_lldp);

#define LLDP_PROTOCOL_ID        0x0000
#define LLDP_PROTOCOL_VERSION   0x00
#define LLDP_TYPE_CONFIG        0x00
#define LLDP_CHASSIS_TTL        120
#define ETH_TYPE_LLDP           0x88cc
#define MINIMUM_ETH_PACKET_SIZE 68

#define AA_STATUS_MULTIPLE \
    AA_STATUS(ACTIVE,2,Active) \
    AA_STATUS(REJECT_GENERIC,3,Reject (Generic)) \
    AA_STATUS(REJECT_AA_RES_NOTAVAIL,4,Reject (AA resources unavailable)) \
    AA_STATUS(REJECT_INVALID,6,Reject (Invalid)) \
    AA_STATUS(REJECT_VLAN_RES_UNAVAIL,8,Reject (VLAN resources unavailable)) \
    AA_STATUS(REJECT_VLAN_APP_ISSUE,9,Reject (Application interaction issue)) \
    AA_STATUS(PENDING,255,Pending)

enum aa_status {
#define AA_STATUS(NAME, VALUE, STR) AA_STATUS_##NAME = VALUE,
    AA_STATUS_MULTIPLE
#undef AA_STATUS
    AA_STATUS_N_MULTIPLE
};

/* Internal structure for an Auto Attach mapping.
 */
struct aa_mapping_internal {
    struct hmap_node hmap_node_isid;
    struct hmap_node hmap_node_aux;
    uint32_t         isid;
    uint16_t         vlan;
    void             *aux;
    enum aa_status   status;
};

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;

/* Hash map of all LLDP instances keyed by name (port at the moment).
 */
static struct hmap all_lldps__ = HMAP_INITIALIZER(&all_lldps__);
static struct hmap *const all_lldps OVS_GUARDED_BY(mutex) = &all_lldps__;

/* Hash map of all the Auto Attach mappings.  Global at the moment (but will
 * be per bridge).  Used when adding a new port to a bridge so that we can
 * properly install all the configured mapping on the port and export them
 * To the Auto Attach server via LLDP.
 */
static struct hmap all_mappings__ = HMAP_INITIALIZER(&all_mappings__);
static struct hmap *const all_mappings OVS_GUARDED_BY(mutex) = &all_mappings__;

static struct lldp_aa_element_system_id system_id_null;

/* Find an Auto Attach mapping keyed by I-SID.
 */
static struct aa_mapping_internal *
mapping_find_by_isid(struct lldp *lldp, uint32_t isid)
    OVS_REQUIRES(mutex)
{
    struct aa_mapping_internal *m;

    HMAP_FOR_EACH_IN_BUCKET (m, hmap_node_isid, hash_int(isid, 0),
                             &lldp->mappings_by_isid) {
        if (isid == m->isid) {
            return m;
        }
    }

    return NULL;
}

/* Find an Auto Attach mapping keyed by aux.  aux is an opaque pointer created
 * by the bridge that refers to an OVSDB mapping record.
 */
static struct aa_mapping_internal *
mapping_find_by_aux(struct lldp *lldp, const void *aux) OVS_REQUIRES(mutex)
{
    struct aa_mapping_internal *m;

    HMAP_FOR_EACH_IN_BUCKET (m, hmap_node_aux, hash_pointer(aux, 0),
                             &lldp->mappings_by_aux) {
        if (aux == m->aux) {
            return m;
        }
    }

    return NULL;
}

/* Convert an Auto Attach request status to a string.
 */
static char *
aa_status_to_str(uint8_t status)
{
    switch (status) {
#define AA_STATUS(NAME, VALUE, STR) case AA_STATUS_##NAME: return #STR;
        AA_STATUS_MULTIPLE
#undef AA_STATUS
        default: return "Undefined";
    }
}

/* Display LLDP and Auto Attach statistics.
 */
static void
aa_print_lldp_and_aa_stats(struct ds *ds, struct lldp *lldp)
    OVS_REQUIRES(mutex)
{
    struct lldpd_hardware *hw;

    ds_put_format(ds, "Statistics: %s\n", lldp->name);

    if (!lldp->lldpd) {
        return;
    }

    LIST_FOR_EACH (hw, h_entries, &lldp->lldpd->g_hardware) {
        ds_put_format(ds, "  tx cnt: %"PRIu64"\n", hw->h_tx_cnt);
        ds_put_format(ds, "  rx cnt: %"PRIu64"\n", hw->h_rx_cnt);
        ds_put_format(ds, "  rx discarded cnt: %"PRIu64"\n",
                      hw->h_rx_discarded_cnt);
        ds_put_format(ds, "  rx unrecognized cnt: %"PRIu64"\n",
                      hw->h_rx_unrecognized_cnt);
        ds_put_format(ds, "  ageout cnt: %"PRIu64"\n", hw->h_ageout_cnt);
        ds_put_format(ds, "  insert cnt: %"PRIu64"\n", hw->h_insert_cnt);
        ds_put_format(ds, "  delete cnt: %"PRIu64"\n", hw->h_delete_cnt);
        ds_put_format(ds, "  drop cnt: %"PRIu64"\n", hw->h_drop_cnt);
    }
}

static void
aa_print_element_status_port(struct ds *ds, struct lldpd_hardware *hw)
{
    struct lldpd_port *port;

    LIST_FOR_EACH (port, p_entries, &hw->h_rports) {
        if (memcmp(&port->p_element.system_id,
                   &system_id_null,
                   sizeof port->p_element.system_id)) {
            const char *none_str = "<None>";
            const char *descr = NULL;
            struct ds id = DS_EMPTY_INITIALIZER;
            struct ds system = DS_EMPTY_INITIALIZER;

            if (port->p_chassis) {
                if (port->p_chassis->c_id_len > 0) {
                    ds_put_hex_with_delimiter(&id, port->p_chassis->c_id,
                                   port->p_chassis->c_id_len, ":");
                }

                descr = port->p_chassis->c_descr;
            }

            ds_put_hex_with_delimiter(&system,
                                      (uint8_t *) &port->p_element.system_id,
                                      sizeof port->p_element.system_id, ":");

            ds_put_format(ds, "  Auto Attach Primary Server Id: %s\n",
                          id.length ? ds_cstr_ro(&id) : none_str);
            ds_put_format(ds, "  Auto Attach Primary Server Descr: %s\n",
                          descr ? descr : none_str);
            ds_put_format(ds, "  Auto Attach Primary Server System Id: %s\n",
                          id.length ? ds_cstr_ro(&system) : none_str);

            ds_destroy(&id);
            ds_destroy(&system);
        }
    }
}

/* Auto Attach server broadcast an LLDP message periodically.  Display
 * the discovered server.
 */
static void
aa_print_element_status(struct ds *ds, struct lldp *lldp) OVS_REQUIRES(mutex)
{
    struct lldpd_hardware *hw;

    ds_put_format(ds, "LLDP: %s\n", lldp->name);

    if (!lldp->lldpd) {
        return;
    }

    LIST_FOR_EACH (hw, h_entries, &lldp->lldpd->g_hardware) {
        aa_print_element_status_port(ds, hw);
    }
}

static void
aa_print_isid_status_port_isid(struct lldp *lldp, struct lldpd_port *port)
    OVS_REQUIRES(mutex)
{
    struct lldpd_aa_isid_vlan_maps_tlv *mapping;

    if (ovs_list_is_empty(&port->p_isid_vlan_maps)) {
        return;
    }

    LIST_FOR_EACH (mapping, m_entries, &port->p_isid_vlan_maps) {
        uint32_t isid = mapping->isid_vlan_data.isid;
        struct aa_mapping_internal *m = mapping_find_by_isid(lldp, isid);

        VLOG_INFO("h_rport: isid=%u, vlan=%u, status=%d",
                  isid,
                  mapping->isid_vlan_data.vlan,
                  mapping->isid_vlan_data.status);

        /* Update the status of our internal state for the mapping. */
        if (m) {
            VLOG_INFO("Setting status for ISID=%"PRIu32" to %"PRIu16,
                      isid, mapping->isid_vlan_data.status);
            m->status = mapping->isid_vlan_data.status;
        } else {
            VLOG_WARN("Couldn't find mapping for I-SID=%"PRIu32, isid);
        }
    }
}

static void
aa_print_isid_status_port(struct lldp *lldp, struct lldpd_hardware *hw)
    OVS_REQUIRES(mutex)
{
    struct lldpd_port *port;

    LIST_FOR_EACH (port, p_entries, &hw->h_rports) {
        aa_print_isid_status_port_isid(lldp, port);
    }
}

/* The Auto Attach server will broadcast the status of the configured mappings
 * via LLDP.  Display the status.
 */
static void
aa_print_isid_status(struct ds *ds, struct lldp *lldp) OVS_REQUIRES(mutex)
{
    struct lldpd_hardware *hw;
    struct aa_mapping_internal *m;

    if (!lldp->lldpd) {
        return;
    }

    ds_put_format(ds, "LLDP: %s\n", lldp->name);

    LIST_FOR_EACH (hw, h_entries, &lldp->lldpd->g_hardware) {
        aa_print_isid_status_port(lldp, hw);
    }

    ds_put_format(ds, "%-8s %-4s %-11s %-8s\n",
                      "I-SID",
                      "VLAN",
                      "Source",
                      "Status");
    ds_put_format(ds, "-------- ---- ----------- --------\n");

    HMAP_FOR_EACH (m, hmap_node_isid, &lldp->mappings_by_isid) {
        ds_put_format(ds, "%-8"PRIu32" %-4"PRIu16" %-11s %-11s\n",
                      m->isid, m->vlan, "Switch", aa_status_to_str(m->status));
    }
}

static void
lldp_print_neighbor_port_dot1(struct ds *ds, struct lldpd_port *port)
{
    if (port->p_dot1_enable &
        ((1 << LLDP_TLV_DOT1_PVID) | (1 << LLDP_TLV_DOT1_VLANNAME))) {
        ds_put_format(ds, "  VLAN: \t");
    }
    if (port->p_dot1_enable & (1 << LLDP_TLV_DOT1_PVID)) {
        ds_put_format(ds, "  %d, ", port->p_dot1.pvid);
        if (!(port->p_dot1_enable & (1 << LLDP_TLV_DOT1_VLANNAME)) &&
            port->p_dot1.pvid > 0) {
            ds_put_format(ds, "pvid: yes");
        }
    }
    if (port->p_dot1_enable & (1 << LLDP_TLV_DOT1_VLANNAME)) {
        ds_put_format(ds, "pvid: %s",
                      port->p_dot1.pvid == port->p_dot1.vlan_id ? "yes"
                                                                : "no");
        if (port->p_dot1.vlan_name) {
            ds_put_format(ds, ", %s", port->p_dot1.vlan_name);
        }
    }
    ds_put_format(ds, "\n");
}

static void
lldp_print_neighbor_port_dot1_json(struct json *interface_item_json,
                                   struct lldpd_port *port)
{
    struct json *vlan_json = NULL;
    if (port->p_dot1_enable & (1 << LLDP_TLV_DOT1_PVID)) {
        if (!vlan_json) {
            vlan_json = json_object_create();
        }
        json_object_put(vlan_json, "vlan-id",
                        json_integer_create(port->p_dot1.pvid));

        if (!(port->p_dot1_enable & (1 << LLDP_TLV_DOT1_VLANNAME)) &&
            port->p_dot1.pvid > 0) {
            json_object_put(vlan_json, "pvid", json_boolean_create(true));
        }
    }
    if (port->p_dot1_enable & (1 << LLDP_TLV_DOT1_VLANNAME)) {
        if (!vlan_json) {
            vlan_json = json_object_create();
        }
        json_object_put(
            vlan_json, "pvid",
            json_boolean_create(
                port->p_dot1.pvid == port->p_dot1.vlan_id ? true : false));
        if (port->p_dot1.vlan_name) {
            json_object_put(vlan_json, "value",
                            json_string_create(port->p_dot1.vlan_name));
        }
    }
    if (vlan_json) {
        json_object_put(interface_item_json, "vlan", vlan_json);
    }

    if (port->p_dot1_enable & (1 << LLDP_TLV_DOT1_PPVID)) {
        struct json *ppid_json = json_object_create();
        json_object_put(ppid_json, "supported",
                        port->p_dot1.ppvid & LLDP_PPVID_CAP_SUPPORTED
                            ? json_boolean_create(true)
                            : json_boolean_create(false));
        json_object_put(ppid_json, "enabled",
                        port->p_dot1.ppvid & LLDP_PPVID_CAP_ENABLED
                            ? json_boolean_create(true)
                            : json_boolean_create(false));
        json_object_put(interface_item_json, "ppid", ppid_json);
    }
}

static void
lldp_dot3_autoneg_advertised(struct ds *ds, uint16_t pmd_auto_nego, int bithd,
                             int bitfd, const char *type)
{
    if (!((pmd_auto_nego & bithd) || (pmd_auto_nego & bitfd))) {
        return;
    }

    ds_put_format(ds, "      Adv:\t %s", type);
    if (bithd != bitfd) {
        ds_put_format(ds, ", HD: %s, FD: %s\n",
                      (pmd_auto_nego & bithd) ? "yes" : "no",
                      (pmd_auto_nego & bitfd) ? "yes" : "no");
    }
}

static void
lldp_dot3_autoneg_advertised_json(struct json **advertised_json,
                             uint16_t pmd_auto_nego, int bithd, int bitfd,
                             const char *type)
{
    if (!((pmd_auto_nego & bithd) || (pmd_auto_nego & bitfd))) {
        return;
    }

    if (!*advertised_json) {
        *advertised_json = json_array_create_empty();
    }

    struct json *advertised_item_json = json_object_create();
    json_object_put(advertised_item_json, "type", json_string_create(type));
    if (bithd != bitfd) {
        json_object_put(advertised_item_json, "hd",
                        json_boolean_create((pmd_auto_nego & bithd) ? true
                                                                    : false));
        json_object_put(advertised_item_json, "fd",
                        json_boolean_create((pmd_auto_nego & bitfd) ? true
                                                                    : false));
    }
    json_array_add(*advertised_json, advertised_item_json);
}

static void
lldp_print_neighbor_port_dot3(struct ds *ds, struct lldpd_port *port)
{
    if (port->p_dot3_enable & (1 << LLDP_TLV_DOT3_MFS)) {
        ds_put_format(ds, "    MFS:\t %d\n", port->p_dot3.mfs);
    }

    if (port->p_dot3_enable & (1 << LLDP_TLV_DOT3_MAC)) {
        ds_put_format(
            ds, "    PMD autoneg:  supported: %s, enabled: %s\n",
            port->p_dot3.auto_nego & LLDP_DOT3_LINK_AUTONEG_SUPPORT ? "yes"
                                                                    : "no",
            port->p_dot3.auto_nego & LLDP_DOT3_LINK_AUTONEG_ENABLED ? "yes"
                                                                    : "no");

        lldp_dot3_autoneg_advertised(ds, port->p_dot3.pmd_auto_nego,
                                     LLDP_DOT3_LINK_AUTONEG_10BASE_T,
                                     LLDP_DOT3_LINK_AUTONEG_10BASE_T_FD,
                                     "10Base-T");
        lldp_dot3_autoneg_advertised(ds, port->p_dot3.pmd_auto_nego,
                                     LLDP_DOT3_LINK_AUTONEG_100BASE_T4,
                                     LLDP_DOT3_LINK_AUTONEG_100BASE_T4,
                                     "100Base-T4");
        lldp_dot3_autoneg_advertised(ds, port->p_dot3.pmd_auto_nego,
                                     LLDP_DOT3_LINK_AUTONEG_100BASE_TX,
                                     LLDP_DOT3_LINK_AUTONEG_100BASE_TX_FD,
                                     "100Base-TX");
        lldp_dot3_autoneg_advertised(ds, port->p_dot3.pmd_auto_nego,
                                     LLDP_DOT3_LINK_AUTONEG_100BASE_T2,
                                     LLDP_DOT3_LINK_AUTONEG_100BASE_T2_FD,
                                     "100Base-T2");
        lldp_dot3_autoneg_advertised(ds, port->p_dot3.pmd_auto_nego,
                                     LLDP_DOT3_LINK_AUTONEG_1000BASE_X,
                                     LLDP_DOT3_LINK_AUTONEG_1000BASE_X_FD,
                                     "1000Base-X");
        lldp_dot3_autoneg_advertised(ds, port->p_dot3.pmd_auto_nego,
                                     LLDP_DOT3_LINK_AUTONEG_1000BASE_T,
                                     LLDP_DOT3_LINK_AUTONEG_1000BASE_T_FD,
                                     "1000Base-T");
        lldp_dot3_autoneg_advertised(ds, port->p_dot3.pmd_auto_nego,
                                     LLDP_DOT3_LINK_AUTONEG_FDX_PAUSE,
                                     LLDP_DOT3_LINK_AUTONEG_FDX_PAUSE,
                                     "FDX_PAUSE");
        lldp_dot3_autoneg_advertised(ds, port->p_dot3.pmd_auto_nego,
                                     LLDP_DOT3_LINK_AUTONEG_FDX_APAUSE,
                                     LLDP_DOT3_LINK_AUTONEG_FDX_APAUSE,
                                     "FDX_APAUSE");
        lldp_dot3_autoneg_advertised(ds, port->p_dot3.pmd_auto_nego,
                                     LLDP_DOT3_LINK_AUTONEG_FDX_SPAUSE,
                                     LLDP_DOT3_LINK_AUTONEG_FDX_SPAUSE,
                                     "FDX_SPAUSE");
        lldp_dot3_autoneg_advertised(ds, port->p_dot3.pmd_auto_nego,
                                     LLDP_DOT3_LINK_AUTONEG_FDX_BPAUSE,
                                     LLDP_DOT3_LINK_AUTONEG_FDX_BPAUSE,
                                     "FDX_BPAUSE");

        ds_put_format(ds, "      MAU oper type:\t %d\n", port->p_dot3.mau);
    }

    if (port->p_dot3_enable & (1 << LLDP_TLV_DOT3_POWER)) {
        ds_put_format(
            ds,
            "    MDI Power:\t supported: %s, enabled: %s, pair control: %s\n",
            port->p_dot3.mdi & LLDP_DOT3_POWER_SUPPORT ? "yes" : "no",
            port->p_dot3.mdi & LLDP_DOT3_POWER_ENABLED ? "yes" : "no",
            port->p_dot3.mdi & LLDP_DOT3_POWER_PAIRCONTROL ? "yes" : "no");

        ds_put_format(ds, "      Device type:\t %s\n",
                      port->p_dot3.mdi & LLDP_DOT3_POWER_PORT_CLASS ? "PSE"
                                                                    : "PD");
    }
}

static void
lldp_print_neighbor_port_dot3_json(struct json *port_json,
                                   struct lldpd_port *port)
{
    if (port->p_dot3_enable & (1 << LLDP_TLV_DOT3_MAC)) {
        struct json *auto_nego_json = json_object_create();
        json_object_put(auto_nego_json, "supported",
                        port->p_dot3.auto_nego & LLDP_DOT3_LINK_AUTONEG_SUPPORT
                            ? json_boolean_create(true)
                            : json_boolean_create(false));
        json_object_put(auto_nego_json, "enabled",
                        port->p_dot3.auto_nego & LLDP_DOT3_LINK_AUTONEG_ENABLED
                            ? json_boolean_create(true)
                            : json_boolean_create(false));

        struct json *advertised_json = NULL;
        lldp_dot3_autoneg_advertised_json(&advertised_json,
                                          port->p_dot3.pmd_auto_nego,
                                          LLDP_DOT3_LINK_AUTONEG_10BASE_T,
                                          LLDP_DOT3_LINK_AUTONEG_10BASE_T_FD,
                                          "10Base-T");
        lldp_dot3_autoneg_advertised_json(&advertised_json,
                                          port->p_dot3.pmd_auto_nego,
                                          LLDP_DOT3_LINK_AUTONEG_100BASE_T4,
                                          LLDP_DOT3_LINK_AUTONEG_100BASE_T4,
                                          "100Base-T4");
        lldp_dot3_autoneg_advertised_json(&advertised_json,
                                          port->p_dot3.pmd_auto_nego,
                                          LLDP_DOT3_LINK_AUTONEG_100BASE_TX,
                                          LLDP_DOT3_LINK_AUTONEG_100BASE_TX_FD,
                                          "100Base-TX");
        lldp_dot3_autoneg_advertised_json(&advertised_json,
                                          port->p_dot3.pmd_auto_nego,
                                          LLDP_DOT3_LINK_AUTONEG_100BASE_T2,
                                          LLDP_DOT3_LINK_AUTONEG_100BASE_T2_FD,
                                          "100Base-T2");
        lldp_dot3_autoneg_advertised_json(&advertised_json,
                                          port->p_dot3.pmd_auto_nego,
                                          LLDP_DOT3_LINK_AUTONEG_1000BASE_X,
                                          LLDP_DOT3_LINK_AUTONEG_1000BASE_X_FD,
                                          "1000Base-X");
        lldp_dot3_autoneg_advertised_json(&advertised_json,
                                          port->p_dot3.pmd_auto_nego,
                                          LLDP_DOT3_LINK_AUTONEG_1000BASE_T,
                                          LLDP_DOT3_LINK_AUTONEG_1000BASE_T_FD,
                                          "1000Base-T");
        lldp_dot3_autoneg_advertised_json(&advertised_json,
                                          port->p_dot3.pmd_auto_nego,
                                          LLDP_DOT3_LINK_AUTONEG_FDX_PAUSE,
                                          LLDP_DOT3_LINK_AUTONEG_FDX_PAUSE,
                                          "FDX_PAUSE");
        lldp_dot3_autoneg_advertised_json(&advertised_json,
                                          port->p_dot3.pmd_auto_nego,
                                          LLDP_DOT3_LINK_AUTONEG_FDX_APAUSE,
                                          LLDP_DOT3_LINK_AUTONEG_FDX_APAUSE,
                                          "FDX_APAUSE");
        lldp_dot3_autoneg_advertised_json(&advertised_json,
                                          port->p_dot3.pmd_auto_nego,
                                          LLDP_DOT3_LINK_AUTONEG_FDX_SPAUSE,
                                          LLDP_DOT3_LINK_AUTONEG_FDX_SPAUSE,
                                          "FDX_SPAUSE");
        lldp_dot3_autoneg_advertised_json(&advertised_json,
                                          port->p_dot3.pmd_auto_nego,
                                          LLDP_DOT3_LINK_AUTONEG_FDX_BPAUSE,
                                          LLDP_DOT3_LINK_AUTONEG_FDX_BPAUSE,
                                          "FDX_BPAUSE");
        if (advertised_json) {
            json_object_put(auto_nego_json, "advertised", advertised_json);
        }

        json_object_put(auto_nego_json, "current",
                        json_integer_create(port->p_dot3.mau));

        json_object_put(port_json, "auto-negotiation", auto_nego_json);
    }

    if (port->p_dot3_enable & (1 << LLDP_TLV_DOT3_POWER)) {
        struct json *power_json = json_object_create();

        json_object_put(
            power_json, "device-type",
            json_string_create(
                port->p_dot3.mdi & LLDP_DOT3_POWER_PORT_CLASS ? "PSE" : "PD"));

        json_object_put(
            power_json, "supported",
            json_boolean_create(
                port->p_dot3.mdi & LLDP_DOT3_POWER_SUPPORT ? true : false));

        json_object_put(
            power_json, "enabled",
            json_boolean_create(
                port->p_dot3.mdi & LLDP_DOT3_POWER_ENABLED ? true : false));

        json_object_put(power_json, "paircontrol",
                        json_boolean_create(port->p_dot3.mdi &
                                                    LLDP_DOT3_POWER_PAIRCONTROL
                                                ? true
                                                : false));

        json_object_put(port_json, "power", power_json);
    }

    if (port->p_dot3_enable & (1 << LLDP_TLV_DOT3_MFS)) {
        json_object_put(port_json, "mfs",
                        json_integer_create(port->p_dot3.mfs));
    }
}

static void
lldp_print_neighbor(struct ds *ds, struct lldp *lldp) OVS_REQUIRES(mutex)
{
    struct lldpd_hardware *hw;
    struct lldpd_port *port;
    const char *none_str = "<None>";

    if (!lldp->lldpd) {
        return;
    }

    LIST_FOR_EACH (hw, h_entries, &lldp->lldpd->g_hardware) {
        LIST_FOR_EACH (port, p_entries, &hw->h_rports) {
            if (!port->p_chassis) {
                continue;
            }
            ds_put_format(ds, "Interface: %s\n", lldp->name);
            ds_put_format(ds, "  Chassis:\n");

            struct ds id = DS_EMPTY_INITIALIZER;
            if (port->p_chassis->c_id_len > 0) {
                ds_put_hex_with_delimiter(&id, port->p_chassis->c_id,
                                          port->p_chassis->c_id_len, ":");
            }
            ds_put_format(ds, "    Chassis ID:\t %s\n",
                          id.length ? ds_cstr_ro(&id) : none_str);
            ds_put_format(ds, "    SysName:\t %s\n",
                          strlen(port->p_chassis->c_name)
                              ? port->p_chassis->c_name
                              : none_str);
            ds_put_format(ds, "    SysDescr:\t %s\n",
                          strlen(port->p_chassis->c_descr)
                              ? port->p_chassis->c_descr
                              : none_str);
            ds_destroy(&id);

            struct lldpd_mgmt *mgmt;
            LIST_FOR_EACH (mgmt, m_entries, &port->p_chassis->c_mgmt) {
                struct in6_addr ip;
                switch (mgmt->m_family) {
                case LLDPD_AF_IPV4:
                    in6_addr_set_mapped_ipv4(&ip, mgmt->m_addr.inet.s_addr);
                    break;
                case LLDPD_AF_IPV6: ip = mgmt->m_addr.inet6; break;
                default: continue;
                }
                ds_put_format(ds, "    MgmtIP:\t ");
                ipv6_format_mapped(&ip, ds);
                ds_put_format(ds, "\n");
                ds_put_format(ds, "    MgmtIface:\t %d\n", mgmt->m_iface);
            }

            if (port->p_chassis->c_cap_available & LLDP_CAP_BRIDGE) {
                ds_put_format(ds, "    Capability:\t Bridge, %s\n",
                              port->p_chassis->c_cap_enabled & LLDP_CAP_BRIDGE
                                  ? "on"
                                  : "off");
            }
            if (port->p_chassis->c_cap_available & LLDP_CAP_ROUTER) {
                ds_put_format(ds, "    Capability:\t Router, %s\n",
                              port->p_chassis->c_cap_enabled & LLDP_CAP_ROUTER
                                  ? "on"
                                  : "off");
            }
            if (port->p_chassis->c_cap_available & LLDP_CAP_WLAN) {
                ds_put_format(ds, "    Capability:\t Wlan, %s\n",
                              port->p_chassis->c_cap_enabled & LLDP_CAP_WLAN
                                  ? "on"
                                  : "off");
            }
            if (port->p_chassis->c_cap_available & LLDP_CAP_STATION) {
                ds_put_format(ds, "    Capability:\t Station, %s\n",
                              port->p_chassis->c_cap_enabled & LLDP_CAP_STATION
                                  ? "on"
                                  : "off");
            }

            ds_put_format(ds, "  Port:\n");

            if (port->p_id_subtype == LLDP_PORTID_SUBTYPE_LLADDR) {
                ds_init(&id);
                if (port->p_id_len > 0) {
                    ds_put_hex_with_delimiter(&id, (uint8_t *) port->p_id,
                                              port->p_id_len, ":");
                }
                ds_put_format(ds, "    PortID:\t %s\n",
                              id.length ? ds_cstr_ro(&id) : none_str);
                ds_destroy(&id);
            } else {
                ds_put_format(ds, "    PortID:\t %.*s\n",
                              (int) (port->p_id ? port->p_id_len
                                                : strlen(none_str)),
                              port->p_id ?: none_str);
            }
            ds_put_format(ds, "    PortDescr:\t %s\n",
                          strlen(port->p_descr) ? port->p_descr : none_str);
            ds_put_format(ds, "    TTL:\t %d\n", port->p_chassis->c_ttl);

            lldp_print_neighbor_port_dot3(ds, port);
            lldp_print_neighbor_port_dot1(ds, port);

            ds_put_format(ds, "-----------------------------------------------"
                              "--------------------------------\n");
        }
    }
}

static void
lldp_print_neighbor_json(struct json *interface_array_json, struct lldp *lldp)
    OVS_REQUIRES(mutex)
{
    struct lldpd_hardware *hw;
    struct lldpd_port *port;
    const char *none_str = "<None>";

    if (!lldp->lldpd) {
        return;
    }

    LIST_FOR_EACH (hw, h_entries, &lldp->lldpd->g_hardware) {
        LIST_FOR_EACH (port, p_entries, &hw->h_rports) {
            if (!port->p_chassis) {
                continue;
            }

            struct json *interface_item_json = json_object_create();
            struct json *interface_item_warp_json = json_object_create();
            struct json *chassis_json = json_object_create();
            struct json *chassis_sys_json = json_object_create();
            struct json *chassis_id_json = json_object_create();
            struct json *chassis_mgmt_ip_json = json_array_create_empty();
            struct json *chassis_mgmt_iface_json = json_array_create_empty();
            struct json *chassis_capability_json = json_array_create_empty();
            struct json *chassis_capability_item_json;
            struct json *port_json = json_object_create();
            struct json *port_id_json = json_object_create();

            struct ds id = DS_EMPTY_INITIALIZER;
            if (port->p_chassis->c_id_len > 0) {
                ds_put_hex_with_delimiter(&id, port->p_chassis->c_id,
                                          port->p_chassis->c_id_len, ":");
            }

            json_object_put(chassis_id_json, "type",
                            json_string_create("mac"));
            json_object_put(chassis_id_json, "value",
                            json_string_create(id.length ? ds_cstr_ro(&id)
                                                         : none_str));
            json_object_put(chassis_sys_json, "id", chassis_id_json);

            json_object_put(chassis_json,
                            strlen(port->p_chassis->c_name)
                                ? port->p_chassis->c_name
                                : none_str,
                            chassis_sys_json);

            json_object_put(chassis_sys_json, "descr",
                            json_string_create(strlen(port->p_chassis->c_descr)
                                                   ? port->p_chassis->c_descr
                                                   : none_str));

            ds_destroy(&id);

            struct lldpd_mgmt *mgmt;
            struct in6_addr ip;
            char addr_str[INET6_ADDRSTRLEN];
            LIST_FOR_EACH (mgmt, m_entries, &port->p_chassis->c_mgmt) {
                switch (mgmt->m_family) {
                case LLDPD_AF_IPV4:
                    in6_addr_set_mapped_ipv4(&ip, mgmt->m_addr.inet.s_addr);
                    break;
                case LLDPD_AF_IPV6: ip = mgmt->m_addr.inet6; break;
                default: continue;
                }

                ipv6_string_mapped(addr_str, &ip);
                json_array_add(chassis_mgmt_ip_json,
                               json_string_create(addr_str));
                json_array_add(chassis_mgmt_iface_json,
                               json_integer_create(mgmt->m_iface));
            }
            json_object_put(chassis_sys_json, "mgmt-ip", chassis_mgmt_ip_json);
            json_object_put(chassis_sys_json, "mgmt-iface",
                            chassis_mgmt_iface_json);

            if (port->p_chassis->c_cap_available & LLDP_CAP_BRIDGE) {
                chassis_capability_item_json = json_object_create();
                json_object_put(chassis_capability_item_json, "type",
                                json_string_create("Bridge"));
                json_object_put(
                    chassis_capability_item_json, "enabled",
                    json_boolean_create(port->p_chassis->c_cap_enabled &
                                        LLDP_CAP_BRIDGE));
                json_array_add(chassis_capability_json,
                               chassis_capability_item_json);
            }
            if (port->p_chassis->c_cap_available & LLDP_CAP_ROUTER) {
                chassis_capability_item_json = json_object_create();
                json_object_put(chassis_capability_item_json, "type",
                                json_string_create("Router"));
                json_object_put(
                    chassis_capability_item_json, "enabled",
                    json_boolean_create(port->p_chassis->c_cap_enabled &
                                        LLDP_CAP_ROUTER));
                json_array_add(chassis_capability_json,
                               chassis_capability_item_json);
            }
            if (port->p_chassis->c_cap_available & LLDP_CAP_WLAN) {
                chassis_capability_item_json = json_object_create();
                json_object_put(chassis_capability_item_json, "type",
                                json_string_create("Wlan"));
                json_object_put(
                    chassis_capability_item_json, "enabled",
                    json_boolean_create(port->p_chassis->c_cap_enabled &
                                        LLDP_CAP_WLAN));
                json_array_add(chassis_capability_json,
                               chassis_capability_item_json);
            }
            if (port->p_chassis->c_cap_available & LLDP_CAP_STATION) {
                chassis_capability_item_json = json_object_create();
                json_object_put(chassis_capability_item_json, "type",
                                json_string_create("Station"));
                json_object_put(
                    chassis_capability_item_json, "enabled",
                    json_boolean_create(port->p_chassis->c_cap_enabled &
                                        LLDP_CAP_STATION));
                json_array_add(chassis_capability_json,
                               chassis_capability_item_json);
            }
            json_object_put(chassis_sys_json, "capability",
                            chassis_capability_json);

            if (port->p_id_subtype == LLDP_PORTID_SUBTYPE_LLADDR) {
                ds_init(&id);
                if (port->p_id_len > 0) {
                    ds_put_hex_with_delimiter(&id, port->p_id, port->p_id_len,
                                              ":");
                }
                json_object_put(port_id_json, "type",
                                json_string_create("mac"));
                json_object_put(port_id_json, "value",
                                json_string_create(id.length ? ds_cstr_ro(&id)
                                                             : none_str));

                ds_destroy(&id);
            } else {
                json_object_put(port_id_json, "type",
                                json_string_create("ifname"));
                if (port->p_id) {
                    struct ds port_ds = DS_EMPTY_INITIALIZER;
                    ds_put_buffer(&port_ds, port->p_id, port->p_id_len);
                    json_object_put(port_id_json, "value",
                                    json_string_create(ds_cstr_ro(&port_ds)));
                    ds_destroy(&port_ds);
                } else {
                    json_object_put(port_id_json, "value",
                                    json_string_create(none_str));
                }
            }
            json_object_put(port_json, "id", port_id_json);

            json_object_put(port_json, "desc",
                            json_string_create(strlen(port->p_descr)
                                                   ? port->p_descr
                                                   : none_str));
            json_object_put(port_json, "ttl",
                            json_integer_create(port->p_chassis->c_ttl));

            lldp_print_neighbor_port_dot1_json(interface_item_json, port);
            lldp_print_neighbor_port_dot3_json(port_json, port);

            json_object_put(interface_item_json, "chassis", chassis_json);
            json_object_put(interface_item_json, "port", port_json);

            json_object_put(interface_item_warp_json, lldp->name,
                            interface_item_json);
            json_array_add(interface_array_json, interface_item_warp_json);
        }
    }
}

static void
aa_unixctl_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
    OVS_EXCLUDED(mutex)
{
    struct lldp *lldp;
    struct ds ds = DS_EMPTY_INITIALIZER;

    ovs_mutex_lock(&mutex);

    HMAP_FOR_EACH (lldp, hmap_node, all_lldps) {
        aa_print_element_status(&ds, lldp);
    }
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

    ovs_mutex_unlock(&mutex);
}

static void
aa_unixctl_show_isid(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
    OVS_EXCLUDED(mutex)
{
    struct lldp *lldp;
    struct ds ds = DS_EMPTY_INITIALIZER;

    ovs_mutex_lock(&mutex);

    HMAP_FOR_EACH (lldp, hmap_node, all_lldps) {
        aa_print_isid_status(&ds, lldp);
    }
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

    ovs_mutex_unlock(&mutex);
}

static void
aa_unixctl_statistics(struct unixctl_conn *conn, int argc OVS_UNUSED,
                      const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
    OVS_EXCLUDED(mutex)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct lldp *lldp;

    ovs_mutex_lock(&mutex);

    /* Cycle through all ports and dump the stats for each one */
    HMAP_FOR_EACH (lldp, hmap_node, all_lldps) {
        aa_print_lldp_and_aa_stats(&ds, lldp);
    }

    ovs_mutex_unlock(&mutex);

    unixctl_command_reply(conn, ds_cstr(&ds));
}

static void
lldp_unixctl_show_neighbor(struct unixctl_conn *conn, int argc,
                           const char *argv[], void *aux OVS_UNUSED)
    OVS_EXCLUDED(mutex)
{
    struct lldp *lldp;

    if (unixctl_command_get_output_format(conn) == UNIXCTL_OUTPUT_FMT_JSON) {
        struct json *lldp_json = json_object_create();
        struct json *interface_json = json_object_create();
        struct json *interface_array_json = json_array_create_empty();

        ovs_mutex_lock(&mutex);
        HMAP_FOR_EACH (lldp, hmap_node, all_lldps) {
            if (argc > 1 && strcmp(argv[1], lldp->name)) {
                continue;
            }
            lldp_print_neighbor_json(interface_array_json,lldp);
        }
        ovs_mutex_unlock(&mutex);

        json_object_put(interface_json, "interface", interface_array_json);
        json_object_put(lldp_json, "lldp", interface_json);

        unixctl_command_reply_json(conn, lldp_json);
    } else {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "--------------------------------------------------"
                           "-----------------------------\nLLDP neighbor:\n"
                           "--------------------------------------------------"
                           "-----------------------------\n");

        ovs_mutex_lock(&mutex);
        HMAP_FOR_EACH (lldp, hmap_node, all_lldps) {
            if (argc > 1 && strcmp(argv[1], lldp->name)) {
                continue;
            }
            lldp_print_neighbor(&ds, lldp);
        }
        ovs_mutex_unlock(&mutex);

        unixctl_command_reply(conn, ds_cstr(&ds));
        ds_destroy(&ds);
    }
}

/* An Auto Attach mapping was configured.  Populate the corresponding
 * structures in the LLDP hardware.
 */
static void
update_mapping_on_lldp(struct lldp *lldp, struct lldpd_hardware *hardware,
                       struct aa_mapping_internal *m)
{
    struct lldpd_aa_isid_vlan_maps_tlv *lm = xzalloc(sizeof *lm);

    VLOG_INFO("     hardware->h_ifname=%s", hardware->h_ifname);

    lm->isid_vlan_data.isid = m->isid;
    lm->isid_vlan_data.vlan = m->vlan;

    ovs_list_push_back(&hardware->h_lport.p_isid_vlan_maps, &lm->m_entries);

    /* TODO Should be done in the Auto Attach state machine when a mapping goes
     * from "pending" to "active".
     */
    struct bridge_aa_vlan *node = xmalloc(sizeof *node);

    node->port_name = xstrdup(hardware->h_ifname);
    node->vlan = m->vlan;
    node->oper = BRIDGE_AA_VLAN_OPER_ADD;

    ovs_list_push_back(&lldp->active_mapping_queue, &node->list_node);
}

/* Bridge will poll the list of VLAN that needs to be auto configure based on
 * the Auto Attach mappings that have been exchanged with the server.
 */
int
aa_get_vlan_queued(struct ovs_list *list)
{
    struct lldp *lldp;

    ovs_mutex_lock(&mutex);

    HMAP_FOR_EACH (lldp, hmap_node, all_lldps) {
        struct bridge_aa_vlan *node;

        LIST_FOR_EACH_POP (node, list_node, &lldp->active_mapping_queue) {
            struct bridge_aa_vlan *copy;

            copy = xmalloc(sizeof *copy);
            copy->port_name = xstrdup(node->port_name);
            copy->vlan = node->vlan;
            copy->oper = node->oper;

            ovs_list_push_back(list, &copy->list_node);

            /* Cleanup */
            free(node->port_name);
            free(node);
        }
    }

    ovs_mutex_unlock(&mutex);

    return 0;
}

/* Bridge will poll whether or not VLAN have been auto-configured.
 */
unsigned int
aa_get_vlan_queue_size(void)
{
    struct lldp *lldp;
    unsigned int size = 0;

    ovs_mutex_lock(&mutex);

    HMAP_FOR_EACH (lldp, hmap_node, all_lldps) {
        size += ovs_list_size(&lldp->active_mapping_queue);
    }

    ovs_mutex_unlock(&mutex);

    return size;
}

/* Configure Auto Attach.
 */
int
aa_configure(const struct aa_settings *s)
{
    struct lldp *lldp;

    ovs_mutex_lock(&mutex);

    /* TODO Change all instances for now */
    HMAP_FOR_EACH (lldp, hmap_node, all_lldps) {
        struct lldpd_chassis *chassis;

        LIST_FOR_EACH (chassis, list, &lldp->lldpd->g_chassis) {
            /* System Description */
            free(chassis->c_descr);
            chassis->c_descr = s && s->system_description[0] ?
                xstrdup(s->system_description) : xstrdup(PACKAGE_STRING);

            /* System Name */
            if (s) {
                free(chassis->c_name);
                chassis->c_name = xstrdup(s->system_name);
            }
        }
    }

    ovs_mutex_unlock(&mutex);

    return 0;
}

/* Add a new Auto Attach mapping.
 */
int
aa_mapping_register(void *aux, const struct aa_mapping_settings *s)
{
    struct aa_mapping_internal *bridge_m;
    struct lldp *lldp;

    VLOG_INFO("Adding mapping ISID=%"PRIu32", VLAN=%"PRIu16", aux=%p",
              s->isid, s->vlan, aux);

    ovs_mutex_lock(&mutex);

    /* TODO These mappings should be stores per bridge.  This is used
     * When a port is added.  Auto Attach mappings need to be added on this
     * port.
     */
    bridge_m = xzalloc(sizeof *bridge_m);
    bridge_m->isid = s->isid;
    bridge_m->vlan = s->vlan;
    bridge_m->aux = aux;
    bridge_m->status = AA_STATUS_PENDING;
    hmap_insert(all_mappings, &bridge_m->hmap_node_isid,
                hash_int(bridge_m->isid, 0));


    /* Update mapping on the all the LLDP instances. */
    HMAP_FOR_EACH (lldp, hmap_node, all_lldps) {
        struct lldpd_hardware *hw;
        struct aa_mapping_internal *m;

        VLOG_INFO("   lldp->name=%s", lldp->name);

        if (mapping_find_by_isid(lldp, s->isid)) {
            continue;
        }

        m = xzalloc(sizeof *m);
        m->isid = s->isid;
        m->vlan = s->vlan;
        m->status = AA_STATUS_PENDING;
        m->aux = aux;
        hmap_insert(&lldp->mappings_by_isid, &m->hmap_node_isid,
                    hash_int(m->isid, 0));
        hmap_insert(&lldp->mappings_by_aux,
                    &m->hmap_node_aux,
                    hash_pointer(m->aux, 0));

        /* Configure the mapping on each port of the LLDP stack. */
        LIST_FOR_EACH (hw, h_entries, &lldp->lldpd->g_hardware) {
            update_mapping_on_lldp(lldp, hw, m);
        }
    }

    ovs_mutex_unlock(&mutex);

    return 0;
}

static void
aa_mapping_unregister_mapping(struct lldp *lldp,
                              struct lldpd_hardware *hw,
                              struct aa_mapping_internal *m)
{
    struct lldpd_aa_isid_vlan_maps_tlv *lm;

    LIST_FOR_EACH_SAFE (lm, m_entries,
                        &hw->h_lport.p_isid_vlan_maps) {
        uint32_t isid = lm->isid_vlan_data.isid;

        if (isid == m->isid) {
            VLOG_INFO("     Removing lport, isid=%u, vlan=%u",
                      isid,
                      lm->isid_vlan_data.vlan);

            ovs_list_remove(&lm->m_entries);

            /* TODO Should be done in the AA SM when a mapping goes
             * from "pending" to "active".
             */
            struct bridge_aa_vlan *node = xmalloc(sizeof *node);

            node->port_name = xstrdup(hw->h_ifname);
            node->vlan = m->vlan;
            node->oper = BRIDGE_AA_VLAN_OPER_REMOVE;

            ovs_list_push_back(&lldp->active_mapping_queue, &node->list_node);

            break;
        }
    }
}

/* Remove an existing Auto Attach mapping.
 */
int
aa_mapping_unregister(void *aux)
{
    struct lldp *lldp;

    VLOG_INFO("Removing mapping aux=%p", aux);

    ovs_mutex_lock(&mutex);

    HMAP_FOR_EACH (lldp, hmap_node, all_lldps) {
        struct lldpd_hardware *hw;
        struct aa_mapping_internal *m = mapping_find_by_aux(lldp, aux);

        /* Remove from internal hash tables. */
        if (m) {
            uint32_t isid = m->isid;
            uint16_t vlan = m->vlan;
            struct aa_mapping_internal *p = mapping_find_by_isid(lldp, isid);

            VLOG_INFO("   Removing mapping ISID=%"PRIu32", VLAN=%"PRIu16
                      " (lldp->name=%s)", isid, vlan, lldp->name);

            if (p) {
                hmap_remove(&lldp->mappings_by_isid, &p->hmap_node_isid);
            }

            hmap_remove(&lldp->mappings_by_aux, &m->hmap_node_aux);

            /* Remove from all the lldp instances */
            LIST_FOR_EACH (hw, h_entries, &lldp->lldpd->g_hardware) {
                VLOG_INFO("     hardware->h_ifname=%s", hw->h_ifname);
                aa_mapping_unregister_mapping(lldp, hw, m);
            }
            free(m);

            /* Remove from the all_mappings */
            HMAP_FOR_EACH (m, hmap_node_isid, all_mappings) {
                if (m && isid == m->isid && vlan == m->vlan) {
                    hmap_remove(all_mappings, &m->hmap_node_isid);
                    break;
                }
            }
        }
    }

    ovs_mutex_unlock(&mutex);

    return 0;
}

void
lldp_init(void)
{
    unixctl_command_register("autoattach/status", "[bridge]", 0, 1,
                             aa_unixctl_status, NULL);
    unixctl_command_register("autoattach/show-isid", "[bridge]", 0, 1,
                             aa_unixctl_show_isid, NULL);
    unixctl_command_register("autoattach/statistics", "[bridge]", 0, 1,
                             aa_unixctl_statistics, NULL);
    unixctl_command_register("lldp/neighbor", "[interface]", 0, 1,
                             lldp_unixctl_show_neighbor, NULL);
}

/* Returns true if 'lldp' should process packets from 'flow'.  Sets
 * fields in 'wc' that were used to make the determination.
 */
bool
lldp_should_process_flow(struct lldp *lldp, const struct flow *flow)
{
    return (flow->dl_type == htons(ETH_TYPE_LLDP) && lldp->enabled);
}


/* Process an LLDP packet that was received on a bridge port.
 */
void
lldp_process_packet(struct lldp *lldp, const struct dp_packet *p)
{
    if (lldp) {
        lldpd_recv(lldp->lldpd, lldpd_first_hardware(lldp->lldpd),
                   (char *) dp_packet_data(p), dp_packet_size(p));
    }
}

/* This code is called periodically to check if the LLDP module has an LLDP
 * message it wishes to send.  It is called several times every second.
 */
bool
lldp_should_send_packet(struct lldp *cfg) OVS_EXCLUDED(mutex)
{
    bool ret;

    ovs_mutex_lock(&mutex);
    ret = timer_expired(&cfg->tx_timer);
    ovs_mutex_unlock(&mutex);

    /* LLDP must be enabled */
    ret &= cfg->enabled;

    return ret;
}

/* Returns the next wake up time.
 */
long long int
lldp_wake_time(const struct lldp *lldp) OVS_EXCLUDED(mutex)
{
    long long int retval;

    if (!lldp || !lldp->enabled) {
        return LLONG_MAX;
    }

    ovs_mutex_lock(&mutex);
    retval = lldp->tx_timer.t;
    ovs_mutex_unlock(&mutex);

    return retval;
}

/* Put the monitor thread to sleep until it's next wake time.
 */
long long int
lldp_wait(struct lldp *lldp) OVS_EXCLUDED(mutex)
{
    long long int wake_time = lldp_wake_time(lldp);
    poll_timer_wait_until(wake_time);
    return wake_time;
}

/* Prepare the LLDP packet to be sent on a bridge port.
 */
void
lldp_put_packet(struct lldp *lldp, struct dp_packet *packet,
                const struct eth_addr eth_src) OVS_EXCLUDED(mutex)
{
    struct lldpd *mylldpd = lldp->lldpd;
    struct lldpd_hardware *hw = lldpd_first_hardware(mylldpd);
    static const struct eth_addr eth_addr_lldp = ETH_ADDR_C(01,80,c2,00,00,0e);

    ovs_mutex_lock(&mutex);

    eth_compose(packet, eth_addr_lldp, eth_src, ETH_TYPE_LLDP, 0);

    lldpd_send(hw, packet);

    timer_set_duration(&lldp->tx_timer, lldp->lldpd->g_config.c_tx_interval);
    ovs_mutex_unlock(&mutex);
}

/* Is LLDP enabled?
 */
bool
lldp_is_enabled(struct lldp *lldp)
{
    return lldp ? lldp->enabled : false;
}

/* Configures the LLDP stack.
 */
bool
lldp_configure(struct lldp *lldp, const struct smap *cfg) OVS_EXCLUDED(mutex)
{
    if (lldp) {
        if (cfg && smap_get_bool(cfg, "enable", false)) {
            lldp->enabled = true;
        } else {
            lldp->enabled = false;
        }

        ovs_mutex_lock(&mutex);
        timer_set_expired(&lldp->tx_timer);
        timer_set_duration(&lldp->tx_timer, LLDP_DEFAULT_TRANSMIT_INTERVAL_MS);
        lldp->lldpd->g_config.c_tx_interval =
            LLDP_DEFAULT_TRANSMIT_INTERVAL_MS;
        ovs_mutex_unlock(&mutex);
    }

    return true;
}

/* Create an LLDP stack instance.  At the moment there is one per bridge port.
 */
struct lldp *
lldp_create(const struct netdev *netdev,
            const uint32_t mtu,
            const struct smap *cfg) OVS_EXCLUDED(mutex)
{
    struct lldp *lldp;
    struct lldpd_chassis *lchassis;
    struct lldpd_hardware *hw;
    struct aa_mapping_internal *m;

    if (!cfg || !smap_get_bool(cfg, "enable", false)) {
        return NULL;
    }

    lldp = xzalloc(sizeof *lldp);
    lldp->name = xstrdup(netdev_get_name(netdev));
    lldp->lldpd = xzalloc(sizeof *lldp->lldpd);

    hmap_init(&lldp->mappings_by_isid);
    hmap_init(&lldp->mappings_by_aux);
    ovs_list_init(&lldp->active_mapping_queue);

    lchassis = xzalloc(sizeof *lchassis);
    lchassis->c_cap_available = LLDP_CAP_BRIDGE;
    lchassis->c_cap_enabled = LLDP_CAP_BRIDGE;
    lchassis->c_id_subtype = LLDP_CHASSISID_SUBTYPE_LLADDR;
    lchassis->c_id_len = ETH_ADDR_LEN;

    struct eth_addr *mac = xmalloc(ETH_ADDR_LEN);
    netdev_get_etheraddr(netdev, mac);
    lchassis->c_id = &mac->ea[0];

    ovs_list_init(&lchassis->c_mgmt);
    lchassis->c_ttl = LLDP_CHASSIS_TTL;
    lldpd_assign_cfg_to_protocols(lldp->lldpd);
    ovs_list_init(&lldp->lldpd->g_chassis);
    ovs_list_push_back(&lldp->lldpd->g_chassis, &lchassis->list);

    hw = lldpd_alloc_hardware(lldp->lldpd, netdev_get_name(netdev), 0);

    ovs_refcount_init(&lldp->ref_cnt);
#ifndef _WIN32
    hw->h_flags |= IFF_RUNNING;
#endif
    hw->h_mtu = mtu;
    hw->h_lport.p_id_subtype = LLDP_PORTID_SUBTYPE_IFNAME;
    hw->h_lport.p_id = xstrdup(netdev_get_name(netdev));

    /* p_id is not necessarily a null terminated string. */
    hw->h_lport.p_id_len = strlen(netdev_get_name(netdev));

    /* Auto Attach element tlv */
    hw->h_lport.p_element.type = LLDP_TLV_AA_ELEM_TYPE_CLIENT_VIRTUAL_SWITCH;
    hw->h_lport.p_element.mgmt_vlan = 0;
    memcpy(&hw->h_lport.p_element.system_id.system_mac,
           lchassis->c_id, lchassis->c_id_len);
    hw->h_lport.p_element.system_id.conn_type =
        LLDP_TLV_AA_ELEM_CONN_TYPE_SINGLE;
    hw->h_lport.p_element.system_id.rsvd = 0;
    hw->h_lport.p_element.system_id.rsvd2[0] = 0;
    hw->h_lport.p_element.system_id.rsvd2[1] = 0;

    ovs_list_init(&hw->h_lport.p_isid_vlan_maps);
    ovs_list_init(&lldp->lldpd->g_hardware);
    ovs_list_push_back(&lldp->lldpd->g_hardware, &hw->h_entries);

    ovs_mutex_lock(&mutex);

    /* Update port with Auto Attach mappings configured. */
    HMAP_FOR_EACH (m, hmap_node_isid, all_mappings) {
        struct aa_mapping_internal *p;

        if (mapping_find_by_isid(lldp, m->isid)) {
            continue;
        }

        p = xmemdup(m, sizeof *p);
        hmap_insert(&lldp->mappings_by_isid, &p->hmap_node_isid,
                    hash_int(p->isid, 0));
        hmap_insert(&lldp->mappings_by_aux,
                    &p->hmap_node_aux,
                    hash_pointer(p->aux, 0));

        update_mapping_on_lldp(lldp, hw, p);
    }

    hmap_insert(all_lldps, &lldp->hmap_node,
                hash_string(netdev_get_name(netdev), 0));

    ovs_mutex_unlock(&mutex);

    return lldp;
}


struct lldp *
lldp_create_dummy(void)
{
    struct lldp *lldp;
    struct lldpd_chassis *lchassis;
    struct lldpd_hardware *hw;

    lldp = xzalloc(sizeof *lldp);
    lldp->name = "dummy-lldp";
    lldp->lldpd = xzalloc(sizeof *lldp->lldpd);

    hmap_init(&lldp->mappings_by_isid);
    hmap_init(&lldp->mappings_by_aux);
    ovs_list_init(&lldp->active_mapping_queue);

    lchassis = xzalloc(sizeof *lchassis);
    lchassis->c_cap_available = LLDP_CAP_BRIDGE;
    lchassis->c_cap_enabled = LLDP_CAP_BRIDGE;
    lchassis->c_id_subtype = LLDP_CHASSISID_SUBTYPE_LLADDR;
    lchassis->c_id_len = ETH_ADDR_LEN;

    ovs_list_init(&lchassis->c_mgmt);
    lchassis->c_ttl = LLDP_CHASSIS_TTL;
    lldpd_assign_cfg_to_protocols(lldp->lldpd);
    ovs_list_init(&lldp->lldpd->g_chassis);
    ovs_list_push_back(&lldp->lldpd->g_chassis, &lchassis->list);

    hw = lldpd_alloc_hardware(lldp->lldpd, "dummy-hw", 0);

    ovs_refcount_init(&lldp->ref_cnt);
#ifndef _WIN32
    hw->h_flags |= IFF_RUNNING;
#endif
    hw->h_mtu = 1500;
    hw->h_lport.p_id_subtype = LLDP_PORTID_SUBTYPE_IFNAME;
    hw->h_lport.p_id = "dummy-port";

    /* p_id is not necessarily a null terminated string. */
    hw->h_lport.p_id_len = strlen(hw->h_lport.p_id);

    /* Auto Attach element tlv */
    hw->h_lport.p_element.type = LLDP_TLV_AA_ELEM_TYPE_CLIENT_VIRTUAL_SWITCH;
    hw->h_lport.p_element.mgmt_vlan = 0;
    hw->h_lport.p_element.system_id.conn_type =
        LLDP_TLV_AA_ELEM_CONN_TYPE_SINGLE;
    hw->h_lport.p_element.system_id.rsvd = 0;
    hw->h_lport.p_element.system_id.rsvd2[0] = 0;
    hw->h_lport.p_element.system_id.rsvd2[1] = 0;

    ovs_list_init(&hw->h_lport.p_isid_vlan_maps);
    ovs_list_init(&lldp->lldpd->g_hardware);
    ovs_list_push_back(&lldp->lldpd->g_hardware, &hw->h_entries);

    return lldp;
}

/* Unreference a specific LLDP instance.
 */
void
lldp_unref(struct lldp *lldp)
{
    if (!lldp) {
        return;
    }

    ovs_mutex_lock(&mutex);
    if (ovs_refcount_unref_relaxed(&lldp->ref_cnt) != 1) {
        ovs_mutex_unlock(&mutex);
        return;
    }

    hmap_remove(all_lldps, &lldp->hmap_node);
    ovs_mutex_unlock(&mutex);

    lldpd_cleanup(lldp->lldpd);
    free(lldp->lldpd);
    free(lldp->name);
    free(lldp);
}

/* Reference a specific LLDP instance.
 */
struct lldp *
lldp_ref(const struct lldp *lldp_)
{
    struct lldp *lldp = CONST_CAST(struct lldp *, lldp_);
    if (lldp) {
        ovs_refcount_ref(&lldp->ref_cnt);
    }
    return lldp;
}

void
lldp_destroy_dummy(struct lldp *lldp)
{
    struct lldpd_hardware *hw;
    struct lldpd_chassis *chassis;
    struct lldpd *cfg;

    if (!lldp) {
        return;
    }

    cfg = lldp->lldpd;

    if (cfg) {
        LIST_FOR_EACH_SAFE (hw, h_entries, &cfg->g_hardware) {
            ovs_list_remove(&hw->h_entries);
            free(hw->h_lport.p_lastframe);
            free(hw);
        }

        LIST_FOR_EACH_SAFE (chassis, list, &cfg->g_chassis) {
            ovs_list_remove(&chassis->list);
            free(chassis);
        }

        free(lldp->lldpd);
    }

    free(lldp);
}

