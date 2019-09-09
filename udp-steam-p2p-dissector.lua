TYPE_STRINGIFIERS = {
    ['nil'] = function(v) return 'nil' end,
    boolean = function(v) return tostring(v) end,
    number = function(v) return v end,
    string = function(v) return "'" .. v .. "'" end,
    userdata = function(v) return 'userdata' end,
    ['function'] = function(v) return 'function' end,
    thread = function(v) return 'thread' end,
    table = function(v) return tostring(v) end,
}

function dump_table(tab, recursive, depth)
    depth = depth or 1

    local indentation = string.rep('  ', depth)
    local str = '{'
    local ordered_keys = {}

    for i, v in ipairs(tab) do
        ordered_keys[i] = true
        str = str .. '\n' .. indentation .. '[' .. i .. '] = '

        if recursive and type(v) == 'table' then
            str = str .. dump_table(v, true, depth + 1) .. ','
        else
            str = str .. TYPE_STRINGIFIERS[type(v)](v) .. ','
        end
    end

    for k, v in pairs(tab) do
        if not ordered_keys[k] then
            str = str .. '\n' .. indentation .. '[' .. TYPE_STRINGIFIERS[type(k)](k) .. '] = '

            if recursive and type(v) == 'table' then
                str = str .. dump_table(v, true, depth + 1) .. ','
            else
                str = str .. TYPE_STRINGIFIERS[type(v)](v) .. ','
            end
        end
    end

    str = str .. '\n' .. string.rep('  ', depth - 1) .. '}'

    return str
end

function dump(v, recursive)
    if type(v) == 'table' then
        return dump_table(v, recursive, 1)
    else
        return TYPE_STRINGIFIERS[type(v)](v)
    end
end

-- Diagnostics table
local D = {}

local LAST_FRAME = 2340

local function print_diagnostics()
    print(dump_table(D, true))
end

-- Steam P2P Protocol

local steamp2p_protocol = Proto("steamp2p", "Steam P2P")
local classicstun_dissector = Dissector.get('classicstun-heur')

-- Header
steamp2p_protocol.fields.mode = ProtoField.new("Mode", "steamp2p.mode", ftypes.UINT8, nil, base.HEX)
steamp2p_protocol.fields.data_length = ProtoField.new("Data Length", "steamp2p.data_length", ftypes.INT32, nil, base.DEC)
steamp2p_protocol.fields.data = ProtoField.new("Data", "steamp2p.data", ftypes.BYTES, nil, base.NONE)

-- Shared (Unreliable/Reliable)
steamp2p_protocol.fields.has_channel = ProtoField.new("Has Channel", "steamp2p.has_channel", ftypes.BOOLEAN)
steamp2p_protocol.fields.channel = ProtoField.new("Channel", "steamp2p.channel", ftypes.INT32, nil, base.DEC)

-- Reliable
steamp2p_protocol.fields.sequence_sent = ProtoField.new("Sequence Number (Sent)", "steamp2p.sequence_sent", ftypes.UINT32, nil, base.DEC)
steamp2p_protocol.fields.sequence_received = ProtoField.new("Sequence Number (Received)", "steamp2p.sequence_received", ftypes.UINT32, nil, base.DEC)
steamp2p_protocol.fields.packet_type = ProtoField.new("Packet Type", "steamp2p.packet_type", ftypes.UINT16, nil, base.HEX)
steamp2p_protocol.fields.ack = ProtoField.new("ACK", "steamp2p.ack", ftypes.BOOLEAN)
steamp2p_protocol.fields.receive_buffer_size = ProtoField.new("Receive Buffer Size", "steamp2p.receive_buffer_size", ftypes.UINT16, nil, base.DEC)
steamp2p_protocol.fields.time_sent = ProtoField.new("Time Sent", "steamp2p.time_sent", ftypes.RELATIVE_TIME)
steamp2p_protocol.fields.time_received = ProtoField.new("Time Received", "steamp2p.time_received", ftypes.RELATIVE_TIME)
steamp2p_protocol.fields.message_length = ProtoField.new("Message Length", "steamp2p.message_length", ftypes.INT32, nil, base.DEC)
steamp2p_protocol.fields.outstanding_data_length = ProtoField.new("Outstanding Data Length", "steamp2p.outstanding_data_length", ftypes.INT32, nil, base.DEC)
steamp2p_protocol.fields.fragment_data = ProtoField.new("Fragment Data", "steamp2p.data", ftypes.BYTES, nil, base.NONE)
steamp2p_protocol.fields.fragment_data_length = ProtoField.new("Fragment Data Length", "steamp2p.fragment_data_length", ftypes.UINT32, nil, base.DEC)
steamp2p_protocol.fields.command = ProtoField.new("Command", "steamp2p.command", ftypes.UINT8, nil, base.HEX)

local MODE_UNRELIABLE = 0
local MODE_RELIABLE = 1

local PACKET_TYPE_DATA = 0
local PACKET_TYPE_COMMAND = 2

local PACKET_TYPE_DESCRIPTIONS = {
    [PACKET_TYPE_DATA] = '(Data)',
    [PACKET_TYPE_COMMAND] = '(Command)'
}

-- SteamP2P is just awfully designed and ridiculously stateful. You can't even parse a reliable packet without already having parsed every prior packet!
local connections = {} -- Indexed by { ["source_ip:destination_ip"] = { [sequence_sent] = { [frame] = packet_info } } }

local function get_previous_packet(frame, source_ip, destination_ip, sequence_number)
    local connection_fragments = connections[source_ip .. ":" .. destination_ip]

    if connection_fragments then
        local sequence_number_fragments = connection_fragments[sequence_number]

        if sequence_number_fragments then
            -- We may start and close multiple connections with the same client, so we do our best to look-up the correct value, it's not perfect though!
            local past_match
            local future_match

            for candidate_frame, candidate in pairs(sequence_number_fragments) do
                if candidate_frame < frame and (past_match == nil or candidate_frame > past_match.frame) then
                    past_match = candidate
                end

                if candidate_frame > frame and (future_match == nil or candidate_frame < future_match.frame) then
                    future_match = candidate
                end
            end

            if past_match then
                if future_match then
                    local past_distance = frame - past_match.frame
                    local future_distance = future_match.frame - frame

                    -- Typically, we'll be a continuation of a frame that arrived before us. However, packets can arrive out of order, so we'll prefer frames
                    -- prior, but consider frames after if they're substantially "closer" to us.
                    if future_distance < past_distance / 3 then
                        return future_match
                    else
                        return past_match
                    end
                else
                    return past_match
                end
            elseif future_match then
                return future_match
            end
        end
    end

    return nil
end

local function set_previous_packet(frame, source_ip, destination_ip, sequence_number, outstanding_length, parsed_out_of_order)
    local connection_key = source_ip .. ":" .. destination_ip
    local connection = connections[connection_key]

    if not connection then
        connection = {}
        connections[connection_key] = connection
    end

    local sequence_number_packets = connection[sequence_number]

    if not sequence_number_packets then
        sequence_number_packets = {}
        connection[sequence_number] = sequence_number_packets
    end

    local packet = {
        frame = frame,
        outstanding_length = outstanding_length,
        sequence_number = sequence_number,
        parsed_out_of_order = parsed_out_of_order,
    }

    sequence_number_packets[packet.frame] = packet
end

local function steamp2p_subtree(tree, buffer)
    return tree:add(steamp2p_protocol, buffer(), "Steam P2P")
end

local function dissect_unreliable(buffer, pinfo, tree)
    local length = buffer:len()

    if length < 2 then
        return false
    end

    local mode = buffer(0, 1)

    if mode:uint() ~= MODE_UNRELIABLE then
        return false
    end

    local has_channel = buffer(1, 1)
    local data_index = 1
    local channel

    if has_channel:int() == 1 then
        if length < 6 then
            return false
        end

        if length > 19 then
            -- We *might* be looking at a STUN packet.
            local stun_message_length = buffer(2, 2):uint()

            if stun_message_length == length - 20 then
                -- Yep, this is almost certainly a STUN binding request packet. Let's let STUN have a go at decoding the packet.
                if classicstun_dissector(buffer, pinfo, tree) then
                    return false
                end
            end
        end

        channel = buffer(2, 4)
        data_index = data_index + 4
    end

    local subtree = steamp2p_subtree(tree, buffer)
    pinfo.cols.protocol = "Steam P2P (Unreliable)"

    subtree:add(steamp2p_protocol.fields.mode, mode, mode:uint(), nil, '(Unreliable)')
    subtree:add(steamp2p_protocol.fields.has_channel, has_channel, has_channel:int() == 1)

    if channel then
        subtree:add(steamp2p_protocol.fields.channel, channel, channel:le_int())
    end

    local data = buffer(data_index):tvb()
    subtree:add(steamp2p_protocol.fields.data_length, data:len()):set_generated()
    subtree:add(steamp2p_protocol.fields.data, data())

    return true
end

local function dissect_time(time)
    return NSTime(time:uint() / 1000, (time:uint() % 1000) * 1000000)
end

local function parse_reliable_data_message(buffer)
    local length = buffer:len()

    if length < 5 then
        return nil
    end

    local message_length = buffer(0, 4)
    local has_channel = buffer(4, 1)

    local message = {
        message_length = message_length:uint(),
        has_channel = has_channel:int() == 1,
        _ranges = {
            message_length = message_length,
            has_channel = has_channel,
        }
    }

    if message.has_channel then
        if buffer:len() < 9 then
            return nil
        end

        local channel = buffer(5, 4)

        message.channel = channel:le_int()
        message._ranges.channel = channel
    end

    message._header_length = message.has_channel and 9 or 5
    message._data_length = message.message_length - (message._header_length - 4)

    return message
end

local parsed_unordered = {}

local function quick_parse(frame, source_ip, destination_ip, buffer, sequence_sent)
    local length = buffer:len()
    local previous_packet = get_previous_packet(frame, source_ip, destination_ip, sequence_sent)

    if not previous_packet then
        return false
    end

    local offset = 0
    local index = 1

    while offset < length do
        if index == 1 and previous_packet.outstanding_length > 0 then
            -- Fragment (message continuation)
            offset = offset + previous_packet.outstanding_length
        else
            local message = parse_reliable_data_message(buffer(offset):tvb())
            offset = offset + message._header_length + message._data_length
        end

        index = index + 1
    end

    local next_sequence_sent = sequence_sent + length
    local outstanding = offset - length
    set_previous_packet(frame, source_ip, destination_ip, next_sequence_sent, outstanding, false)

    parsed_unordered[sequence_sent] = nil

    local out_of_order_next_packet = parsed_unordered[next_sequence_sent]

    if out_of_order_next_packet then
        local frame, source_ip, destination_ip, bytes, sequence_sent = table.unpack(out_of_order_next_packet)
        quick_parse(frame, source_ip, destination_ip, bytes:tvb(), sequence_sent)
    end
end

CONTENT_DISSECTORS = {
    [PACKET_TYPE_DATA] = function(buffer, pinfo, tree, sequence_sent)
        local length = buffer:len()

        if length == 0 then
            tree:add(steamp2p_protocol.fields.ack, true, '[ACK]')
            return -- ACK
        end

        local frame = pinfo.number
        local source_ip = tostring(pinfo.src)
        local destination_ip = tostring(pinfo.dst)

        local previous_outstanding_length
        local parsed_out_of_order = false

        if sequence_sent == 0 then
            previous_outstanding_length = 0
        else
            local previous_packet = get_previous_packet(frame, source_ip, destination_ip, sequence_sent)

            if previous_packet then
                previous_outstanding_length = previous_packet.outstanding_length
                parsed_out_of_order = previous_packet.parsed_out_of_order
            else
                previous_outstanding_length = 0
                parsed_unordered[sequence_sent] = { frame, source_ip, destination_ip, buffer:bytes(), sequence_sent}
                parsed_out_of_order = true
            end
        end

        local offset = 0
        local index = 1

        while offset < length do
            local message_tree = tree:add(steamp2p_protocol, buffer(), "Message #" .. index)

            if index == 1 and previous_outstanding_length > 0 then
                 -- Fragment (message continuation)
                local available_data_length = math.min(previous_outstanding_length, length - offset)

                tree:add(steamp2p_protocol.fields.fragment_data_length, available_data_length):set_generated()
                tree:add(steamp2p_protocol.fields.fragment_data, buffer(offset, available_data_length))

                if available_data_length == previous_outstanding_length then
                    message_tree:append_text(" (Final Fragment)")
                else
                    message_tree:append_text(" (Fragment)")
                    tree:add(steamp2p_protocol.fields.outstanding_data_length, previous_outstanding_length - available_data_length):set_generated()
                end

                offset = offset + previous_outstanding_length
            else
                local message = parse_reliable_data_message(buffer(offset):tvb())

                tree:add(steamp2p_protocol.fields.message_length, message._ranges.message_length, message.message_length)
                tree:add(steamp2p_protocol.fields.has_channel, message._ranges.has_channel, message.has_channel)

                if message.has_channel then
                    tree:add(steamp2p_protocol.fields.channel, message._ranges.channel, message.channel)
                end

                tree:add(steamp2p_protocol.fields.data_length, message._data_length):set_generated()

                local available_data_length = math.min(message._data_length, length - offset - message._header_length)

                if message._data_length > 0 then
                    local data_field

                    if available_data_length == message._data_length then
                        data_field = steamp2p_protocol.fields.data
                    else
                        data_field = steamp2p_protocol.fields.fragment_data
                        tree:add(steamp2p_protocol.fields.fragment_data_length, available_data_length):set_generated()
                    end

                    tree:add(data_field, buffer(offset + message._header_length, available_data_length))

                    if available_data_length ~= message._data_length then
                        message_tree:append_text(" (Initial Fragment)")
                        tree:add(steamp2p_protocol.fields.outstanding_data_length, message._data_length - available_data_length):set_generated()
                    end
                end

                offset = offset + message._header_length + message._data_length
            end

            index = index + 1
        end

        local next_sequence_sent = sequence_sent + length
        local outstanding = offset - length

        local frame = pinfo.number
        local source_ip = tostring(pinfo.src)
        local destination_ip = tostring(pinfo.dst)

        set_previous_packet(frame, source_ip, destination_ip, next_sequence_sent, outstanding, parsed_out_of_order)

        if not parsed_out_of_order then
            parsed_unordered[sequence_sent] = nil

            local unparsed_next_packet = parsed_unordered[next_sequence_sent]

            if unparsed_next_packet then
                local frame, source_ip, destination_ip, bytes, sequence_sent = table.unpack(unparsed_next_packet)
                quick_parse(frame, source_ip, destination_ip, bytes:tvb(), sequence_sent)
            end
        end
    end,
    [PACKET_TYPE_COMMAND] = function(buffer, pinfo, tree, sequence_sent)
        local command = buffer(0, 1)
        tree:add(steamp2p_protocol.fields.command, command)

        local length = buffer:len()
        local next_sequence_sent = sequence_sent + length

        local frame = pinfo.number
        local source_ip = tostring(pinfo.src)
        local destination_ip = tostring(pinfo.dst)

        set_previous_packet(frame, source_ip, destination_ip, next_sequence_sent, 0, false)

        local unparsed_next_packet = parsed_unordered[next_sequence_sent]

        if unparsed_next_packet then
            local frame, source_ip, destination_ip, bytes, sequence_sent = table.unpack(unparsed_next_packet)
            quick_parse(frame, source_ip, destination_ip, bytes:tvb(), sequence_sent)
        end
    end,
}

local CONTENT_VALIDATORS = {
    [PACKET_TYPE_DATA] = function(buffer, pinfo, sequence_sent)
        local length = buffer:len()

        if length == 0 then
            return true -- ACK
        end

        if length < 4 then
            return false
        end

        return true
    end,
    [PACKET_TYPE_COMMAND] = function(buffer)
        return buffer:len() > 0
    end,
}

local RELIABLE_PACKET_HEADER_SIZE = 25

local function dissect_reliable(buffer, pinfo, tree)
    local length = buffer:len()

    if length < RELIABLE_PACKET_HEADER_SIZE then
        return false
    end

    local mode = buffer(0, 1)

    if mode:uint() ~= MODE_RELIABLE then
        return false
    end

    -- The Steam P2P protocol is multiplexed with STUN. The first two bytes of a stun message are the message type, 0x0100 is not a valid STUN message type, so
    -- Steam uses this message type to distinguish itself from STUN. Our mode is already 0x1, so we just need to worry about the next byte being 0x0.
    -- In practice, the 3 following bytes all seem to be zero'd as well. The first two of these 3 bytes would be STUN's message length, setting it to zero again
    -- ensures Steam P2P packets can't be interpreted as a STUN message, as all Steam P2P packets are minimum 25 bytes, whilst a STUN message with zero data is
    -- 20 bytes. It's unclear at present why the remaining byte also always appears to be set to 0 (semantically this has no bearing on STUN interpretation).

    local null_int = buffer(1, 4)

    if null_int:uint() ~= 0 then
        return false
    end

    local sequence_sent = buffer(5, 4)
    local sequence_received = buffer(9, 4)
    local packet_type = buffer(13, 2)
    local receive_buffer_size = buffer(15, 2)
    local time_sent = buffer(17, 4)
    local time_received = buffer(21, 4)

    local content = buffer(RELIABLE_PACKET_HEADER_SIZE)
    local validator = CONTENT_VALIDATORS[packet_type:uint()]

    if validator and not validator(content, pinfo, sequence_sent:uint(), sequence_received:uint()) then
        return false
    end

    local subtree = steamp2p_subtree(tree, buffer)
    pinfo.cols.protocol = "Steam P2P (Reliable)"

    subtree:add(steamp2p_protocol.fields.mode, mode, mode:uint(), nil, '(Reliable)')
    local sequence_sent_subtree = subtree:add(steamp2p_protocol.fields.sequence_sent, sequence_sent)
    subtree:add(steamp2p_protocol.fields.sequence_received, sequence_received)
    subtree:add(steamp2p_protocol.fields.packet_type, packet_type, packet_type:uint(), nil, PACKET_TYPE_DESCRIPTIONS[packet_type:uint()])
    subtree:add(steamp2p_protocol.fields.receive_buffer_size, receive_buffer_size)
    subtree:add(steamp2p_protocol.fields.time_sent, time_sent, dissect_time(time_sent))
    subtree:add(steamp2p_protocol.fields.time_received, time_received, dissect_time(time_received))

    sequence_sent_subtree:add('Next Sequence Number', sequence_sent:uint() + content:len()):set_generated()

    local content_dissector = CONTENT_DISSECTORS[packet_type:uint()]

    if content_dissector then
        content_dissector(content, pinfo, subtree, sequence_sent:uint(), sequence_received:uint())
    end

    return true
end

local function steamp2p_dissect(buffer, pinfo, tree)
    if dissect_unreliable(buffer, pinfo, tree) or dissect_reliable(buffer, pinfo, tree) then
        if pinfo.number == LAST_FRAME then
            print_diagnostics()
        end

        return true
    end

    return false
end

function steamp2p_protocol.dissector(buffer, pinfo, tree)
    steamp2p_dissect(buffer, pinfo, tree)
end

local function heuristic_dissector(buffer, pinfo, tree)
    return steamp2p_dissect(buffer, pinfo, tree)
end

steamp2p_protocol:register_heuristic("udp", heuristic_dissector)
