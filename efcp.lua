--
-- Copyright (c) 2020 SIDN Labs
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
-- 
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
--

efcp_proto = Proto("efcp", "EFCP", "Error and Flow Control protocol")

local PDU_TYPE_DT = 0x80
local PDU_TYPE_CACK = 0xC0
local PDU_TYPE_ACK = 0xC1
local PDU_TYPE_NACK = 0xC2
local PDU_TYPE_FC = 0xC4
local PDU_TYPE_ACK_AND_FC = 0xC5
local PDU_TYPE_NACK_AND_FC = 0xC6
local PDU_TYPE_SACK = 0xC9
local PDU_TYPE_SNACK = 0xCA
local PDU_TYPE_SACK_AND_FC = 0xCD
local PDU_TYPE_SNACK_AND_FC = 0xCE
local PDU_TYPE_RENDEZVOUS = 0xCF
local PDU_TYPE_MGMT = 0x40

local pduTypes = {
	[PDU_TYPE_DT] = "Data Transfer PDU",
	[PDU_TYPE_CACK] = "Control Ack PDU",
	[PDU_TYPE_ACK] = "ACK only",
	[PDU_TYPE_NACK] = "Forced Retransmission PDU (NACK)",
	[PDU_TYPE_FC] = "Flow Control only",
	[PDU_TYPE_ACK_AND_FC] = "ACK and Flow Control",
	[PDU_TYPE_NACK_AND_FC] = "NACK and Flow Control",
	[PDU_TYPE_SACK] = "Selective ACK",
	[PDU_TYPE_SNACK] = "Selective NACK",
	[PDU_TYPE_SACK_AND_FC] = "Selective ACK and Flow Control",
	[PDU_TYPE_SNACK_AND_FC] = "Selective NACK and Flow Control",
	[PDU_TYPE_RENDEZVOUS] = "Rendezvous",
	[PDU_TYPE_MGMT] = "Management",
}

local DEFAULT_VERSION_LENGTH = 1
local DEFAULT_FLAGS_LENGTH = 1
local DEFAULT_PDU_TYPE_LENGTH = 1
local DEFAULT_ADDRESS_LENGTH = 2
local DEFAULT_CEP_ID_LENGTH = 2
local DEFAULT_SEQ_NUM_LENGTH = 4
local DEFAULT_CTRL_SEQ_NUM_LENGTH = 4
local DEFAULT_RATE_LENGTH = 4
local DEFAULT_FRAME_LENGTH = 4
local DEFAULT_LENGTH_LENGTH = 2
local DEFAULT_PORT_ID_LENGTH = 2
local DEFAULT_QOS_ID_LENGTH = 2

local PDU_FLAGS_EXPLICIT_CONGESTION_CONTROL = 0x01
local PDU_FLAGS_DATA_RUN = 0x80
local PDU_FLAGS_ALLOWED_MASK = bit32.bor(PDU_FLAGS_EXPLICIT_CONGESTION_CONTROL, PDU_FLAGS_DATA_RUN)

local efcp_packet = ProtoField.bytes("efcp.packet", "Raw EFCP packet")

local efcp_version = ProtoField.uint8("efcp.version", "EFCP version", base.HEX)
local efcp_dst_addr = ProtoField.uint16("efcp.dest", "Destination address", base.HEX)
local efcp_src_addr = ProtoField.uint16("efcp.src", "Source address", base.HEX)
local efcp_qos_id = ProtoField.uint16("efcp.qosid", "Quality of Service ID", base.DEC)
local efcp_dst_cep = ProtoField.int16("efcp.dstcep", "Destination Connection Endpoint ID", base.DEC)
local efcp_src_cep = ProtoField.int16("efcp.srccep", "Source Connection Endpoint ID", base.DEC)
local efcp_pdu_type = ProtoField.uint8("efcp.pdutype", "PDU Type", base.HEX, pduTypes)
local efcp_pdu_flags = ProtoField.uint8("efcp.pduflags", "PDU Flags", base.HEX)
local efcp_pdu_flags_explicit_congestion = ProtoField.bool("efcp.pduflags.explicit_congestion", "Explicit Congestion", 8, nil, PDU_FLAGS_EXPLICIT_CONGESTION_CONTROL)
local efcp_pdu_flags_data_run = ProtoField.bool("efcp.pduflags.data_run", "Data run", 8, nil, PDU_FLAGS_DATA_RUN)
local efcp_len = ProtoField.uint16("efcp.len", "Length", base.DEC)

-- For data transfer and management
local efcp_sn = ProtoField.uint32("efcp.sn", "Sequence number", base.DEC)

-- For control
local efcp_ctrl_sn = ProtoField.uint32("efcp.ctrl_sn", "Control sequence number", base.DEC)
local efcp_last_csn_rcvd = ProtoField.uint32("efcp.last_csn_rcvd", "Last control sequence number received", base.DEC)
local efcp_new_lwe = ProtoField.uint32("efcp.new_lwe", "New LWE", base.DEC)
local efcp_new_rwe = ProtoField.uint32("efcp.new_rwe", "New RWE", base.DEC)
local efcp_my_lwe = ProtoField.uint32("efcp.my_lwe", "My LWE", base.DEC)
local efcp_my_rwe = ProtoField.uint32("efcp.my_rwe", "My RWE", base.DEC)
local efcp_sndr_rate = ProtoField.uint32("efcp.sndr_rate", "Sender rate", base.DEC)
local efcp_time_frame = ProtoField.uint32("efcp.time_frame", "Time frame", base.DEC)
local efcp_acked_sn = ProtoField.uint32("efcp.acked_sn", "Acked sequence number", base.DEC)


local efcp_payload = ProtoField.bytes("efcp.payload", "Payload")

local efcp_len_expert = ProtoExpert.new("efcp.len", "Incorrect length field", expert.group.MALFORMED, expert.severity.ERROR)
local efcp_pdu_flags_expert = ProtoExpert.new("efcp.pduflags", "Unknown flag", expert.group.MALFORMED, expert.severity.ERROR)
local efcp_pdu_type_expert = ProtoExpert.new("efcp.pdutype", "Unknown PDU type", expert.group.MALFORMED, expert.severity.ERROR)

efcp_proto.fields = {
	efcp_packet,
	efcp_version,
	efcp_dst_addr,
	efcp_src_addr,
	efcp_qos_id,
	efcp_dst_cep,
	efcp_src_cep,
	efcp_pdu_type,
	efcp_pdu_flags,
	efcp_pdu_flags_explicit_congestion,
	efcp_pdu_flags_data_run,
	efcp_len,
	efcp_sn,
	efcp_ctrl_sn,
	efcp_last_csn_rcvd,
	efcp_new_lwe,
	efcp_new_rwe,
	efcp_my_lwe,
	efcp_my_rwe,
	efcp_sndr_rate,
	efcp_time_frame,
	efcp_acked_sn,
	efcp_payload,
}

efcp_proto.experts = {
	efcp_len_expert,
	efcp_pdu_flags_expert,
	efcp_pdu_type_expert,
}

function val_to_str(key, map, default)
	local str = map[key]
	if str == nil then
		str = string.format(default, key)
	end
	return str
end

function dissect_data_transfer(buffer, pinfo, tree)
	offset = 0

	tree:add_packet_field(efcp_sn, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	return offset
end

function dissect_management(buffer, pinfo, tree)
	offset = 0

	tree:add_packet_field(efcp_sn, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	pinfo.private["pb_msg_type"] = "message,gpb.CDAPMessage"
	local len = Dissector.get("protobuf"):call(buffer(offset):tvb(), pinfo, tree)
	offset = offset + len

	return offset
end

function dissect_cack(buffer, pinfo, tree)
	offset = 0

	tree:add_packet_field(efcp_ctrl_sn, buffer(offset, efcp_proto.prefs.ctrl_seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.ctrl_seq_num_length

	tree:add_packet_field(efcp_last_csn_rcvd, buffer(offset, efcp_proto.prefs.ctrl_seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.ctrl_seq_num_length

	tree:add_packet_field(efcp_new_lwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_new_rwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_my_lwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_my_rwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_sndr_rate, buffer(offset, efcp_proto.prefs.rate_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.rate_length

	tree:add_packet_field(efcp_time_frame, buffer(offset, efcp_proto.prefs.frame_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.frame_length

	return offset
end

function dissect_fc(buffer, pinfo, tree)
	offset = 0

	tree:add_packet_field(efcp_ctrl_sn, buffer(offset, efcp_proto.prefs.ctrl_seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.ctrl_seq_num_length

	tree:add_packet_field(efcp_new_rwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_my_lwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_my_rwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_sndr_rate, buffer(offset, efcp_proto.prefs.rate_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.rate_length

	tree:add_packet_field(efcp_time_frame, buffer(offset, efcp_proto.prefs.frame_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.frame_length

	return offset
end

function dissect_ack(buffer, pinfo, tree)
	offset = 0

	tree:add_packet_field(efcp_ctrl_sn, buffer(offset, efcp_proto.prefs.ctrl_seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.ctrl_seq_num_length

	tree:add_packet_field(efcp_acked_sn, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	return offset
end

function dissect_ack_fc(buffer, pinfo, tree)
	offset = 0

	tree:add_packet_field(efcp_ctrl_sn, buffer(offset, efcp_proto.prefs.ctrl_seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.ctrl_seq_num_length

	tree:add_packet_field(efcp_acked_sn, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_last_csn_rcvd, buffer(offset, CTRL_SEQ_NUM_LENGTH), ENC_LITTLE_ENDIAN)
	offset = offset + CTRL_SEQ_NUM_LENGTH

	tree:add_packet_field(efcp_new_lwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_new_rwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_my_lwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_my_rwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_sndr_rate, buffer(offset, efcp_proto.prefs.rate_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.rate_length

	tree:add_packet_field(efcp_time_frame, buffer(offset, efcp_proto.prefs.frame_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.frame_length

	return offset
end


function dissect_rendezvous(buffer, pinfo, tree)
	offset = 0

	tree:add_packet_field(efcp_ctrl_sn, buffer(offset, efcp_proto.prefs.ctrl_seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.ctrl_seq_num_length

	tree:add_packet_field(efcp_last_csn_rcvd, buffer(offset, efcp_proto.prefs.ctrl_seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.ctrl_seq_num_length

	tree:add_packet_field(efcp_new_lwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_new_rwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_my_lwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_my_rwe, buffer(offset, efcp_proto.prefs.seq_num_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.seq_num_length

	tree:add_packet_field(efcp_sndr_rate, buffer(offset, efcp_proto.prefs.rate_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.rate_length

	tree:add_packet_field(efcp_time_frame, buffer(offset, efcp_proto.prefs.frame_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.frame_length

	return offset
end

function efcp_proto.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol:set("EFCP")

	tree:add(efcp_packet, buffer())

	local t = tree:add(buffer(), "EFCP")
	local offset = 0

	t:add(efcp_version, buffer(offset, efcp_proto.prefs.version_length))
	offset = offset + efcp_proto.prefs.version_length

	t:add_packet_field(efcp_dst_addr, buffer(offset, efcp_proto.prefs.address_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.address_length

	t:add_packet_field(efcp_src_addr, buffer(offset, efcp_proto.prefs.address_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.address_length

	t:add_packet_field(efcp_qos_id, buffer(offset, efcp_proto.prefs.qos_id_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.qos_id_length

	t:add_packet_field(efcp_dst_cep, buffer(offset, efcp_proto.prefs.cep_id_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.cep_id_length

	t:add_packet_field(efcp_src_cep, buffer(offset, efcp_proto.prefs.cep_id_length), ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.cep_id_length

	local pdu_type = buffer(offset, efcp_proto.prefs.pdu_type_length)
	local pdu_type_val = pdu_type:le_uint()
	local pdu_type_t = t:add_packet_field(efcp_pdu_type, pdu_type, ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.pdu_type_length

	local pdu_flags = buffer(offset, efcp_proto.prefs.flags_length)
	local pdu_flags_t = t:add_packet_field(efcp_pdu_flags, pdu_flags, ENC_LITTLE_ENDIAN)
	pdu_flags_t:add(efcp_pdu_flags_explicit_congestion, pdu_flags)
	pdu_flags_t:add(efcp_pdu_flags_data_run, pdu_flags)
	offset = offset + efcp_proto.prefs.flags_length

	if bit32.bor(PDU_FLAGS_ALLOWED_MASK, pdu_flags:le_uint()) ~= PDU_FLAGS_ALLOWED_MASK then
		pdu_flags_t:add_tvb_expert_info(efcp_pdu_flags_expert, pdu_flags, string.format("Unknown PDU flags (0x%02x)", pdu_flags:le_uint()))
	end

	local len = buffer(offset, efcp_proto.prefs.length_length)
	efcp_len_t = t:add_packet_field(efcp_len, len, ENC_LITTLE_ENDIAN)
	offset = offset + efcp_proto.prefs.length_length

	if len:le_uint() ~= buffer:len() then
		efcp_len_t:add_tvb_expert_info(efcp_len_expert, len, string.format("Unexpected EFCP length (%d), expected %d", len:le_uint(), buffer:len()))
	end

	if pdu_type_val == PDU_TYPE_DT then
		local len = dissect_data_transfer(buffer(offset), pinfo, t)
		offset = offset + len
	elseif pdu_type_val == PDU_TYPE_MGMT then
		local len = dissect_management(buffer(offset), pinfo, t)
		offset = offset + len
	elseif pdu_type_val == PDU_TYPE_CACK then
		local len = dissect_cack(buffer(offset), pinfo, t)
		offset = offset + len
	elseif pdu_type_val == PDU_TYPE_FC then
		local len = dissect_fc(buffer(offset), pinfo, t)
		offset = offset + len
	elseif pdu_type_val == PDU_TYPE_ACK or pdu_type_val == PDU_TYPE_NACK or pdu_type_val == PDU_TYPE_SACK or pdu_type_val == PDU_TYPE_SNACK then
		local len = dissect_ack(buffer(offset), pinfo, t)
		offset = offset + len
	elseif pdu_type_val == PDU_TYPE_ACK_AND_FC or pdu_type_val == PDU_TYPE_NACK_AND_FC or pdu_type_val == PDU_TYPE_SACK_AND_FC or pdu_type_val == PDU_TYPE_SNACK_AND_FC then
		local len = dissect_ack_fc(buffer(offset), pinfo, t)
		offset = offset + len
	elseif pdu_type_val == PDU_TYPE_RENDEZVOUS then
		local len = dissect_rendezvous(buffer(offset), pinfo, t)
		offset = offset + len
	else
		pdu_type_t:add_tvb_expert_info(efcp_pdu_type_expert, pdu_type, string.format("Unknown PDU type (0x%02x)", pdu_type_val))
	end

	if buffer:len() > offset then
		t:add(efcp_payload, buffer(offset))
	end

	pinfo.cols.info:clear()
	pinfo.cols.info:append(string.format("%s", val_to_str(pdu_type_val, pduTypes, "Unknown (0x%02x)")))
end

DissectorTable.get("ethertype"):add(0xD1F0, efcp_proto)

efcp_proto.prefs.version_length = Pref.uint("Version length", DEFAULT_VERSION_LENGTH, string.format("Version length (default: %d)", DEFAULT_VERSION_LENGTH))
efcp_proto.prefs.flags_length = Pref.uint("Flags length", DEFAULT_FLAGS_LENGTH, string.format("Flags length (default: %d)", DEFAULT_FLAGS_LENGTH))
efcp_proto.prefs.pdu_type_length = Pref.uint("PDU Type length", DEFAULT_PDU_TYPE_LENGTH, string.format("PDU Type length (default: %d)", DEFAULT_PDU_TYPE_LENGTH))
efcp_proto.prefs.address_length = Pref.uint("Address length", DEFAULT_ADDRESS_LENGTH, string.format("Address length (default: %d)", DEFAULT_ADDRESS_LENGTH))
efcp_proto.prefs.cep_id_length = Pref.uint("CEP ID length", DEFAULT_CEP_ID_LENGTH, string.format("CEP ID length (default: %d)", DEFAULT_CEP_ID_LENGTH))
efcp_proto.prefs.seq_num_length = Pref.uint("Sequence number length", DEFAULT_SEQ_NUM_LENGTH, string.format("Sequence number length (default: %d)", DEFAULT_SEQ_NUM_LENGTH))
efcp_proto.prefs.ctrl_seq_num_length = Pref.uint("Control sequence number length", DEFAULT_CTRL_SEQ_NUM_LENGTH, string.format("Control sequence number length (default: %d)", DEFAULT_CTRL_SEQ_NUM_LENGTH))
efcp_proto.prefs.rate_length = Pref.uint("Rate length", DEFAULT_RATE_LENGTH, string.format("Rate length (default: %d)", DEFAULT_RATE_LENGTH))
efcp_proto.prefs.frame_length = Pref.uint("Frame length", DEFAULT_FRAME_LENGTH, string.format("Frame length (default: %d)", DEFAULT_FRAME_LENGTH))
efcp_proto.prefs.length_length = Pref.uint("Length length", DEFAULT_LENGTH_LENGTH, string.format("Length length (default: %d)", DEFAULT_LENGTH_LENGTH))
efcp_proto.prefs.port_id_length = Pref.uint("Port ID length", DEFAULT_PORT_ID_LENGTH, string.format("Port ID length (default: %d)", DEFAULT_PORT_ID_LENGTH))
efcp_proto.prefs.qos_id_length = Pref.uint("QoS ID length", DEFAULT_QOS_ID_LENGTH, string.format("QoS ID length (default: %d)", DEFAULT_QOS_ID_LENGTH))
