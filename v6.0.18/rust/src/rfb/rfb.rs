/* Copyright (C) 2020 Open Information Security Foundation
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

// Author: Frank Honza <frank.honza@dcso.de>
//         Sascha Steinbiss <sascha.steinbiss@dcso.de>

use super::parser;
use crate::applayer;
use crate::applayer::*;
use crate::core::{self, AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_TCP};
use nom;
use std;
use std::ffi::{CStr, CString};
use std::mem::transmute;

static mut ALPROTO_RFB: AppProto = ALPROTO_UNKNOWN;

#[derive(FromPrimitive, Debug)]
pub enum RFBEvent {
    UnimplementedSecurityType = 0,
    UnknownSecurityResult,
    MalformedMessage,
    ConfusedState,
}

impl RFBEvent {
    fn from_i32(value: i32) -> Option<RFBEvent> {
        match value {
            0 => Some(RFBEvent::UnimplementedSecurityType),
            1 => Some(RFBEvent::UnknownSecurityResult),
            2 => Some(RFBEvent::MalformedMessage),
            3 => Some(RFBEvent::ConfusedState),
            _ => None,
        }
    }
}

pub struct RFBTransaction {
    tx_id: u64,
    pub complete: bool,
    pub chosen_security_type: Option<u32>,

    pub tc_server_protocol_version: Option<parser::ProtocolVersion>,
    pub ts_client_protocol_version: Option<parser::ProtocolVersion>,
    pub tc_supported_security_types: Option<parser::SupportedSecurityTypes>,
    pub ts_security_type_selection: Option<parser::SecurityTypeSelection>,
    pub tc_server_security_type: Option<parser::ServerSecurityType>,
    pub tc_vnc_challenge: Option<parser::VncAuth>,
    pub ts_vnc_response: Option<parser::VncAuth>,
    pub ts_client_init: Option<parser::ClientInit>,
    pub tc_security_result: Option<parser::SecurityResult>,
    pub tc_failure_reason: Option<parser::FailureReason>,
    pub tc_server_init: Option<parser::ServerInit>,

    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    tx_data: applayer::AppLayerTxData,
}

impl RFBTransaction {
    pub fn new() -> RFBTransaction {
        RFBTransaction {
            tx_id: 0,
            complete: false,
            chosen_security_type: None,

            tc_server_protocol_version: None,
            ts_client_protocol_version: None,
            tc_supported_security_types: None,
            ts_security_type_selection: None,
            tc_server_security_type: None,
            tc_vnc_challenge: None,
            ts_vnc_response: None,
            ts_client_init: None,
            tc_security_result: None,
            tc_failure_reason: None,
            tc_server_init: None,

            de_state: None,
            events: std::ptr::null_mut(),
            tx_data: applayer::AppLayerTxData::new(),
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            core::sc_detect_engine_state_free(state);
        }
    }

    fn set_event(&mut self, event: RFBEvent) {
        core::sc_app_layer_decoder_events_set_event_raw(&mut self.events, event as u8);
    }
}

impl Drop for RFBTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct RFBState {
    tx_id: u64,
    transactions: Vec<RFBTransaction>,
    state: parser::RFBGlobalState,
}

impl RFBState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            transactions: Vec::new(),
            state: parser::RFBGlobalState::TCServerProtocolVersion,
        }
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&RFBTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self) -> RFBTransaction {
        let mut tx = RFBTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn get_current_tx(&mut self) -> Option<&mut RFBTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == self.tx_id {
                return Some(tx);
            }
        }
        return None;
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        let mut current = input;
        let mut consumed = 0;
        SCLogDebug!("request_state {}, input_len {}", self.state, input.len());
        loop {
            if current.len() == 0 {
                return AppLayerResult::ok();
            }
            match self.state {
                parser::RFBGlobalState::TSClientProtocolVersion => {
                    match parser::parse_protocol_version(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            if request.major == "003" && request.minor == "003" {
                                // in version 3.3 the server decided security type
                                self.state = parser::RFBGlobalState::TCServerSecurityType;
                            } else {
                                self.state = parser::RFBGlobalState::TCSupportedSecurityTypes;
                            }

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.ts_client_protocol_version = Some(request);
                            } else {
                                debug_validate_fail!(
                                    "no transaction set at protocol selection stage"
                                );
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            // We even failed to parse the protocol version.
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TSSecurityTypeSelection => {
                    match parser::parse_security_type_selection(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            let chosen_security_type = request.security_type;

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.ts_security_type_selection = Some(request);
                                current_transaction.chosen_security_type =
                                    Some(chosen_security_type as u32);
                            } else {
                                debug_validate_fail!("no transaction set at security type stage");
                            }

                            match chosen_security_type {
                                2 => self.state = parser::RFBGlobalState::TCVncChallenge,
                                1 => self.state = parser::RFBGlobalState::TSClientInit,
                                _ => {
                                    if let Some(current_transaction) = self.get_current_tx() {
                                        current_transaction
                                            .set_event(RFBEvent::UnimplementedSecurityType);
                                    }
                                    // We have just have seen a security type we don't know about.
                                    // This is not bad per se, it might just mean this is a
                                    // proprietary one not in the spec.
                                    // Continue the flow but stop trying to map the protocol.
                                    self.state = parser::RFBGlobalState::Skip;
                                    return AppLayerResult::ok();
                                }
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // We failed to parse the security type.
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::TSVncResponse => {
                    match parser::parse_vnc_auth(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            self.state = parser::RFBGlobalState::TCSecurityResult;

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.ts_vnc_response = Some(request);
                            } else {
                                debug_validate_fail!("no transaction set at security result stage");
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::TSClientInit => {
                    match parser::parse_client_init(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            self.state = parser::RFBGlobalState::TCServerInit;

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.ts_client_init = Some(request);
                            } else {
                                debug_validate_fail!("no transaction set at client init stage");
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // We failed to parse the client init.
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::Skip => {
                    // End of parseable handshake reached, skip rest of traffic
                    return AppLayerResult::ok();
                }
                _ => {
                    // We have gotten out of sync with the expected state flow.
                    // This could happen since we use a global state (i.e. that
                    // is used for both directions), but if traffic can not be
                    // parsed as expected elsewhere, we might not have advanced
                    // a state for one direction but received data in the
                    // "unexpected" direction, causing the parser to end up
                    // here. Let's stop trying to parse the traffic but still
                    // accept it.
                    SCLogDebug!("Invalid state for request: {}", self.state);
                    if let Some(current_transaction) = self.get_current_tx() {
                        current_transaction.set_event(RFBEvent::ConfusedState);
                        current_transaction.complete = true;
                    }
                    self.state = parser::RFBGlobalState::Skip;
                    return AppLayerResult::ok();
                }
            }
        }
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        let mut current = input;
        let mut consumed = 0;
        SCLogDebug!(
            "response_state {}, response_len {}",
            self.state,
            input.len()
        );
        loop {
            if current.len() == 0 {
                return AppLayerResult::ok();
            }
            match self.state {
                parser::RFBGlobalState::TCServerProtocolVersion => {
                    match parser::parse_protocol_version(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            self.state = parser::RFBGlobalState::TSClientProtocolVersion;
                            let tx = self.new_tx();
                            self.transactions.push(tx);

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_server_protocol_version = Some(request);
                            } else {
                                debug_validate_fail!("no transaction set but we just set one");
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            // We even failed to parse the protocol version.
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TCSupportedSecurityTypes => {
                    match parser::parse_supported_security_types(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            SCLogDebug!(
                                "supported_security_types: {}, types: {}",
                                request.number_of_types,
                                request
                                    .types
                                    .iter()
                                    .map(ToString::to_string)
                                    .map(|v| v + " ")
                                    .collect::<String>()
                            );

                            self.state = parser::RFBGlobalState::TSSecurityTypeSelection;
                            if request.number_of_types == 0 {
                                self.state = parser::RFBGlobalState::TCFailureReason;
                            }

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_supported_security_types = Some(request);
                            } else {
                                debug_validate_fail!("no transaction set at security type stage");
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::TCServerSecurityType => {
                    // In RFB 3.3, the server decides the authentication type
                    match parser::parse_server_security_type(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            let chosen_security_type = request.security_type;
                            SCLogDebug!("chosen_security_type: {}", chosen_security_type);
                            match chosen_security_type {
                                0 => self.state = parser::RFBGlobalState::TCFailureReason,
                                1 => self.state = parser::RFBGlobalState::TSClientInit,
                                2 => self.state = parser::RFBGlobalState::TCVncChallenge,
                                _ => {
                                    if let Some(current_transaction) = self.get_current_tx() {
                                        current_transaction
                                            .set_event(RFBEvent::UnimplementedSecurityType);
                                        current_transaction.complete = true;
                                    } else {
                                        debug_validate_fail!(
                                            "no transaction set at security type stage"
                                        );
                                    }
                                    // We have just have seen a security type we don't know about.
                                    // This is not bad per se, it might just mean this is a
                                    // proprietary one not in the spec.
                                    // Continue the flow but stop trying to map the protocol.
                                    self.state = parser::RFBGlobalState::Skip;
                                    return AppLayerResult::ok();
                                }
                            }

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_server_security_type = Some(request);
                                current_transaction.chosen_security_type =
                                    Some(chosen_security_type);
                            } else {
                                debug_validate_fail!("no transaction set at security type stage");
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::TCVncChallenge => {
                    match parser::parse_vnc_auth(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            self.state = parser::RFBGlobalState::TSVncResponse;

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_vnc_challenge = Some(request);
                            } else {
                                debug_validate_fail!("no transaction set at auth stage");
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::TCSecurityResult => {
                    match parser::parse_security_result(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            if request.status == 0 {
                                self.state = parser::RFBGlobalState::TSClientInit;

                                if let Some(current_transaction) = self.get_current_tx() {
                                    current_transaction.tc_security_result = Some(request);
                                } else {
                                    debug_validate_fail!(
                                        "no transaction set at security result stage"
                                    );
                                }
                            } else if request.status == 1 {
                                self.state = parser::RFBGlobalState::TCFailureReason;
                            } else {
                                if let Some(current_transaction) = self.get_current_tx() {
                                    current_transaction.set_event(RFBEvent::UnknownSecurityResult);
                                    current_transaction.complete = true;
                                }
                                // Continue the flow but stop trying to map the protocol.
                                self.state = parser::RFBGlobalState::Skip;
                                return AppLayerResult::ok();
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::TCFailureReason => {
                    match parser::parse_failure_reason(current) {
                        Ok((_rem, request)) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_failure_reason = Some(request);
                            } else {
                                debug_validate_fail!("no transaction set at failure reason stage");
                            }
                            return AppLayerResult::ok();
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::TCServerInit => {
                    match parser::parse_server_init(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            self.state = parser::RFBGlobalState::Skip;

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_server_init = Some(request);
                                // connection initialization is complete and parsed
                                current_transaction.complete = true;
                            } else {
                                debug_validate_fail!("no transaction set at server init stage");
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::Skip => {
                    //todo implement RFB messages, for now we stop here
                    return AppLayerResult::ok();
                }
                _ => {
                    // We have gotten out of sync with the expected state flow.
                    // This could happen since we use a global state (i.e. that
                    // is used for both directions), but if traffic can not be
                    // parsed as expected elsewhere, we might not have advanced
                    // a state for one direction but received data in the
                    // "unexpected" direction, causing the parser to end up
                    // here. Let's stop trying to parse the traffic but still
                    // accept it.
                    SCLogDebug!("Invalid state for response: {}", self.state);
                    if let Some(current_transaction) = self.get_current_tx() {
                        current_transaction.set_event(RFBEvent::ConfusedState);
                        current_transaction.complete = true;
                    }
                    self.state = parser::RFBGlobalState::Skip;
                    return AppLayerResult::ok();
                }
            }
        }
    }

    fn tx_iterator(
        &mut self, min_tx_id: u64, state: &mut u64,
    ) -> Option<(&RFBTransaction, u64, bool)> {
        let mut index = *state as usize;
        let len = self.transactions.len();

        while index < len {
            let tx = &self.transactions[index];
            if tx.tx_id < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64;
            return Some((tx, tx.tx_id - 1, (len - index) > 1));
        }

        return None;
    }
}

// C exports.

export_tx_get_detect_state!(rs_rfb_tx_get_detect_state, RFBTransaction);
export_tx_set_detect_state!(rs_rfb_tx_set_detect_state, RFBTransaction);

#[no_mangle]
pub extern "C" fn rs_rfb_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = RFBState::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let _drop: Box<RFBState> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, RFBState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_rfb_parse_request(
    _flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    input: *const u8, input_len: u32, _data: *const std::os::raw::c_void, _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, RFBState);
    let buf = build_slice!(input, input_len as usize);
    return state.parse_request(buf);
}

#[no_mangle]
pub extern "C" fn rs_rfb_parse_response(
    _flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    input: *const u8, input_len: u32, _data: *const std::os::raw::c_void, _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, RFBState);
    let buf = build_slice!(input, input_len as usize);
    return state.parse_response(buf);
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, RFBState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return unsafe { transmute(tx) };
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, RFBState);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_progress_completion_status(_direction: u8) -> std::os::raw::c_int {
    // This parser uses 1 to signal transaction completion status.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_rfb_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, RFBTransaction);
    if tx.complete {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_get_events(
    tx: *mut std::os::raw::c_void,
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, RFBTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_get_event_info(
    event_name: *const std::os::raw::c_char, event_id: *mut std::os::raw::c_int,
    event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    if event_name == std::ptr::null() {
        return -1;
    }
    let c_event_name: &CStr = unsafe { CStr::from_ptr(event_name) };
    let event = match c_event_name.to_str() {
        Ok(s) => {
            match s {
                "unimplemented_security_type" => RFBEvent::UnimplementedSecurityType as i32,
                "unknown_security_result" => RFBEvent::UnknownSecurityResult as i32,
                "malformed_message" => RFBEvent::MalformedMessage as i32,
                "confused_state" => RFBEvent::ConfusedState as i32,
                _ => -1, // unknown event
            }
        }
        Err(_) => -1, // UTF-8 conversion failed
    };
    unsafe {
        *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as std::os::raw::c_int;
    };
    0
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_get_event_info_by_id(
    event_id: std::os::raw::c_int, event_name: *mut *const std::os::raw::c_char,
    event_type: *mut core::AppLayerEventType,
) -> i8 {
    if let Some(e) = RFBEvent::from_i32(event_id as i32) {
        let estr = match e {
            RFBEvent::UnimplementedSecurityType => "unimplemented_security_type\0",
            RFBEvent::UnknownSecurityResult => "unknown_security_result\0",
            RFBEvent::MalformedMessage => "malformed_message\0",
            RFBEvent::ConfusedState => "confused_state\0",
        };
        unsafe {
            *event_name = estr.as_ptr() as *const std::os::raw::c_char;
            *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        };
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_get_tx_iterator(
    _ipproto: u8, _alproto: AppProto, state: *mut std::os::raw::c_void, min_tx_id: u64,
    _max_tx_id: u64, istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, RFBState);
    match state.tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = unsafe { transmute(tx) };
            let ires = applayer::AppLayerGetTxIterTuple::with_values(c_tx, out_tx_id, has_next);
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"rfb\0";

export_tx_data_get!(rs_rfb_get_tx_data, RFBTransaction);

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_register_parser() {
    let default_port = CString::new("[5900]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 16,
        state_new: rs_rfb_state_new,
        state_free: rs_rfb_state_free,
        tx_free: rs_rfb_state_tx_free,
        parse_ts: rs_rfb_parse_request,
        parse_tc: rs_rfb_parse_response,
        get_tx_count: rs_rfb_state_get_tx_count,
        get_tx: rs_rfb_state_get_tx,
        tx_get_comp_st: rs_rfb_state_progress_completion_status,
        tx_get_progress: rs_rfb_tx_get_alstate_progress,
        get_de_state: rs_rfb_tx_get_detect_state,
        set_de_state: rs_rfb_tx_set_detect_state,
        get_events: Some(rs_rfb_state_get_events),
        get_eventinfo: Some(rs_rfb_state_get_event_info),
        get_eventinfo_byid: Some(rs_rfb_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(rs_rfb_state_get_tx_iterator),
        get_tx_data: rs_rfb_get_tx_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_RFB = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust rfb parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for RFB.");
    }
}
