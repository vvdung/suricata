/* Copyright (C) 2023 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 */

#include "suricata-common.h"
#include "util-exception-policy.h"
#include "util-misc.h"
#include "stream-tcp-reassemble.h"

void ExceptionPolicyApply(Packet *p, enum ExceptionPolicy policy, enum PacketDropReason drop_reason)
{
    SCLogDebug("start: pcap_cnt %" PRIu64 ", policy %u", p->pcap_cnt, policy);
    if (EngineModeIsIPS()) {
        switch (policy) {
            case EXCEPTION_POLICY_IGNORE:
                break;
            case EXCEPTION_POLICY_REJECT:
                SCLogDebug("EXCEPTION_POLICY_REJECT");
                PacketDrop(p, ACTION_REJECT, drop_reason);
                /* fall through */
            case EXCEPTION_POLICY_DROP_FLOW:
                SCLogDebug("EXCEPTION_POLICY_DROP_FLOW");
                if (p->flow) {
                    p->flow->flags |= FLOW_ACTION_DROP;
                    FlowSetNoPayloadInspectionFlag(p->flow);
                    FlowSetNoPacketInspectionFlag(p->flow);
                    StreamTcpDisableAppLayer(p->flow);
                }
                /* fall through */
            case EXCEPTION_POLICY_DROP_PACKET:
                SCLogDebug("EXCEPTION_POLICY_DROP_PACKET");
                DecodeSetNoPayloadInspectionFlag(p);
                DecodeSetNoPacketInspectionFlag(p);
                PacketDrop(p, ACTION_DROP, drop_reason);
                break;
            case EXCEPTION_POLICY_BYPASS_FLOW:
                PacketBypassCallback(p);
                /* fall through */
            case EXCEPTION_POLICY_PASS_FLOW:
                SCLogDebug("EXCEPTION_POLICY_PASS_FLOW");
                if (p->flow) {
                    p->flow->flags |= FLOW_ACTION_PASS;
                    FlowSetNoPacketInspectionFlag(p->flow); // TODO util func
                }
                /* fall through */
            case EXCEPTION_POLICY_PASS_PACKET:
                SCLogDebug("EXCEPTION_POLICY_PASS_PACKET");
                DecodeSetNoPayloadInspectionFlag(p);
                DecodeSetNoPacketInspectionFlag(p);
                PacketSetActionOnCurrentPkt(p, ACTION_PASS);
                break;
        }
    }
    SCLogDebug("end");
}

static enum ExceptionPolicy PickPacketAction(const char *option, enum ExceptionPolicy p)
{
    switch (p) {
        case EXCEPTION_POLICY_DROP_FLOW:
            SCLogWarning(SC_ERR_INVALID_VALUE,
                    "flow actions not supported for %s, defaulting to \"drop-packet\"", option);
            return EXCEPTION_POLICY_DROP_PACKET;
        case EXCEPTION_POLICY_PASS_FLOW:
            SCLogWarning(SC_ERR_INVALID_VALUE,
                    "flow actions not supported for %s, defaulting to \"pass-packet\"", option);
            return EXCEPTION_POLICY_PASS_PACKET;
        case EXCEPTION_POLICY_BYPASS_FLOW:
            SCLogWarning(SC_ERR_INVALID_VALUE,
                    "flow actions not supported for %s, defaulting to \"ignore\"", option);
            return EXCEPTION_POLICY_IGNORE;
        /* add all cases, to make sure new cases not handle will raise
         * errors */
        case EXCEPTION_POLICY_DROP_PACKET:
            break;
        case EXCEPTION_POLICY_PASS_PACKET:
            break;
        case EXCEPTION_POLICY_REJECT:
            break;
        case EXCEPTION_POLICY_IGNORE:
            break;
    }
    return p;
}

enum ExceptionPolicy ExceptionPolicyParse(const char *option, const bool support_flow)
{
    enum ExceptionPolicy policy = EXCEPTION_POLICY_IGNORE;
    const char *value_str = NULL;
    if ((ConfGet(option, &value_str)) == 1 && value_str != NULL) {
        if (strcmp(value_str, "drop-flow") == 0) {
            policy = EXCEPTION_POLICY_DROP_FLOW;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "pass-flow") == 0) {
            policy = EXCEPTION_POLICY_PASS_FLOW;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "bypass") == 0) {
            policy = EXCEPTION_POLICY_BYPASS_FLOW;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "drop-packet") == 0) {
            policy = EXCEPTION_POLICY_DROP_PACKET;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "pass-packet") == 0) {
            policy = EXCEPTION_POLICY_PASS_PACKET;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "reject") == 0) {
            policy = EXCEPTION_POLICY_REJECT;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "ignore") == 0) { // TODO name?
            policy = EXCEPTION_POLICY_IGNORE;
            SCLogConfig("%s: %s", option, value_str);
        } else {
            FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                    "\"%s\" is not a valid exception policy value. Valid options are drop-flow, "
                    "pass-flow, bypass, drop-packet, pass-packet or ignore.",
                    value_str);
        }

        if (!support_flow) {
            policy = PickPacketAction(option, policy);
        }

    } else {
        SCLogConfig("%s: ignore", option);
    }
    return policy;
}

#ifndef DEBUG

int ExceptionSimulationCommandlineParser(const char *name, const char *arg)
{
    return 0;
}

#else

/* exception policy simulation (eps) handling */

uint64_t g_eps_applayer_error_offset_ts = UINT64_MAX;
uint64_t g_eps_applayer_error_offset_tc = UINT64_MAX;
uint64_t g_eps_pcap_packet_loss = UINT64_MAX;
uint64_t g_eps_stream_ssn_memcap = UINT64_MAX;
uint64_t g_eps_stream_reassembly_memcap = UINT64_MAX;
uint64_t g_eps_flow_memcap = UINT64_MAX;
uint64_t g_eps_defrag_memcap = UINT64_MAX;
bool g_eps_is_alert_queue_fail_mode = false;

/* 1: parsed, 0: not for us, -1: error */
int ExceptionSimulationCommandlineParser(const char *name, const char *arg)
{
    if (strcmp(name, "simulate-applayer-error-at-offset-ts") == 0) {
        BUG_ON(arg == NULL);
        uint64_t offset = 0;
        if (ParseSizeStringU64(arg, &offset) < 0) {
            return -1;
        }
        g_eps_applayer_error_offset_ts = offset;
    } else if (strcmp(name, "simulate-applayer-error-at-offset-tc") == 0) {
        BUG_ON(arg == NULL);
        uint64_t offset = 0;
        if (ParseSizeStringU64(arg, &offset) < 0) {
            return TM_ECODE_FAILED;
        }
        g_eps_applayer_error_offset_tc = offset;
    } else if (strcmp(name, "simulate-packet-loss") == 0) {
        BUG_ON(arg == NULL);
        uint64_t pkt_num = 0;
        if (ParseSizeStringU64(arg, &pkt_num) < 0) {
            return TM_ECODE_FAILED;
        }
        g_eps_pcap_packet_loss = pkt_num;
    } else if (strcmp(name, "simulate-packet-tcp-reassembly-memcap") == 0) {
        BUG_ON(arg == NULL);
        uint64_t pkt_num = 0;
        if (ParseSizeStringU64(arg, &pkt_num) < 0) {
            return TM_ECODE_FAILED;
        }
        g_eps_stream_reassembly_memcap = pkt_num;
    } else if (strcmp(name, "simulate-packet-tcp-ssn-memcap") == 0) {
        BUG_ON(arg == NULL);
        uint64_t pkt_num = 0;
        if (ParseSizeStringU64(arg, &pkt_num) < 0) {
            return TM_ECODE_FAILED;
        }
        g_eps_stream_ssn_memcap = pkt_num;
    } else if (strcmp(name, "simulate-packet-flow-memcap") == 0) {
        BUG_ON(arg == NULL);
        uint64_t pkt_num = 0;
        if (ParseSizeStringU64(arg, &pkt_num) < 0) {
            return TM_ECODE_FAILED;
        }
        g_eps_flow_memcap = pkt_num;
    } else if (strcmp(name, "simulate-packet-defrag-memcap") == 0) {
        BUG_ON(arg == NULL);
        uint64_t pkt_num = 0;
        if (ParseSizeStringU64(arg, &pkt_num) < 0) {
            return TM_ECODE_FAILED;
        }
        g_eps_defrag_memcap = pkt_num;
    } else if (strcmp(name, "simulate-alert-queue-realloc-failure") == 0) {
        g_eps_is_alert_queue_fail_mode = true;
    } else {
        // not for us
        return 0;
    }
    return 1;
}
#endif
