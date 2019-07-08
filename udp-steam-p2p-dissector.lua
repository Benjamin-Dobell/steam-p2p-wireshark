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
steamp2p_protocol.fields.remaining_data_length = ProtoField.new("Remaining Data Length", "steamp2p.remaining_data_length", ftypes.INT32, nil, base.DEC)
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

local fragmented_packets = {} -- Indexed by sequence_sent, value is remaining bytes in fragment

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

local function validate_reliable_message(buffer, content_length, is_continuation)
    if content_length < 2 and not is_continuation then
        return false
    end

    local buffer_length = buffer:len() -- NOTE: This *can* be zero i.e. we're a fragment with *zero* data.

    if not is_continuation and buffer_length > 0 then
        local message_has_channel = buffer(0, 1)

        if message_has_channel:int() == 1 and content_length < 6 then
            return false
        end
    end

    return true
end

-- message_length: is_fragment_continuation ? int : buffer slice
local function dissect_reliable_message(tree, buffer, message_length, is_fragment_continuation)
    local data_offset = 0
    local buffer_length = buffer:len()

    if not is_fragment_continuation then
        tree:add(steamp2p_protocol.fields.message_length, message_length)
    end

    if not is_fragment_continuation and buffer_length > 0 then
        local message_has_channel = buffer(0, 1)
        tree:add(steamp2p_protocol.fields.has_channel, message_has_channel, message_has_channel:int() == 1)

        data_offset = data_offset + 1

        if message_has_channel and message_has_channel:int() == 1 then
            local channel = buffer(1, 4)
            tree:add(steamp2p_protocol.fields.channel, channel, channel:le_int())
            data_offset = data_offset + 4
        end
    end

    local length = is_fragment_continuation and message_length or message_length:uint()
    local remaining_data_length = length - data_offset
    local message_data_length = math.min(remaining_data_length, buffer_length - data_offset)
    local data = message_data_length > 0 and buffer(data_offset, message_data_length):tvb() or nil

    local post_message_remaining_data_length = remaining_data_length - message_data_length
    local is_fragment = is_fragment_continuation or post_message_remaining_data_length > 0

    if is_fragment then
        if is_fragment_continuation then
            tree:add(steamp2p_protocol.fields.remaining_data_length, remaining_data_length):set_generated()
        else
            tree:add(steamp2p_protocol.fields.data_length, remaining_data_length):set_generated()
        end

        tree:add(steamp2p_protocol.fields.fragment_data_length, message_data_length):set_generated()

        if data then
            tree:add(steamp2p_protocol.fields.fragment_data, data())
        end
    else
        tree:add(steamp2p_protocol.fields.data_length, remaining_data_length):set_generated()
        tree:add(steamp2p_protocol.fields.data, data())
    end

    return post_message_remaining_data_length
end

local function dissect_time(time)
    return NSTime(time:uint() / 1000, (time:uint() % 1000) * 1000000)
end

local CONTENT_DISSECTORS = {
    [PACKET_TYPE_DATA] = function(buffer, tree, sequence_sent)
        local length = buffer:len()

        if length == 0 then
            tree:add(steamp2p_protocol.fields.ack, true, '[ACK]')
            return -- ACK
        end

        local continuation_remaining_length = fragmented_packets[sequence_sent] or 0
        local is_fragment_continuation_packet = continuation_remaining_length > 0

        local message_remaining_data_length = 0
        local packet_size = is_fragment_continuation_packet and continuation_remaining_length or buffer(0, 4)
        local packet_size_i = is_fragment_continuation_packet and continuation_remaining_length or packet_size:uint()

        if packet_size_i >= length - 4 then
            local content_offset = not is_fragment_continuation_packet and 4 or 0
            local content = buffer(content_offset):tvb()
            message_remaining_data_length = dissect_reliable_message(tree, content, packet_size, is_fragment_continuation_packet)
        else -- Multiple messages
            local index = 1
            local offset = 0

            while offset < length do
                local is_continuation_message = index == 1 and is_fragment_continuation_packet
                local message_tree = tree:add(steamp2p_protocol, buffer(), "Message #" .. index)

                local message_content_size = is_continuation_message and continuation_remaining_length or buffer(offset, 4)
                local message_content_size_i = is_continuation_message and message_content_size or message_content_size:uint()
                local message_content_offset = offset + (not is_continuation_message and 4 or 0)
                local content = buffer(message_content_offset):tvb()

                message_remaining_data_length = dissect_reliable_message(message_tree, content, message_content_size, is_continuation_message)

                if is_continuation_message then
                    message_tree:append_text(" (Final Fragment)")
                elseif message_remaining_data_length > 0 then
                    message_tree:append_text(" (Fragmented)")
                end

                offset = message_content_offset + message_content_size_i
                index = index + 1
            end
        end

        if message_remaining_data_length > 0 then
            local next_sequence_sent = sequence_sent + length
            fragmented_packets[next_sequence_sent] = message_remaining_data_length
        end
    end,
    [PACKET_TYPE_COMMAND] = function(buffer, tree)
        local command = buffer(offset, 1)
        tree:add(steamp2p_protocol.fields.command, command)
    end,
}

local CONTENT_VALIDATORS = {
    [PACKET_TYPE_DATA] = function(buffer, sequence_sent)
        local length = buffer:len()

        if length == 0 then
            return true -- ACK
        end

        if length < 4 then
            return false
        end

        local continuation_remaining_length = fragmented_packets[sequence_sent] or 0
        local is_fragment_continuation_packet = continuation_remaining_length > 0

        local size = is_fragment_continuation_packet and continuation_remaining_length or buffer(offset, 4):uint()

        if size >= length - 4 then
            local content_offset = not is_fragment_continuation_packet and 4 or 0

            if not validate_reliable_message(buffer(content_offset):tvb(), size, is_fragment_continuation_packet) then
                return false
            end
        else -- Multiple messages
            local index = 1
            local offset = 0

            while offset < length do
                local is_continuation_message = index == 1 and is_fragment_continuation_packet
                local message_content_size = is_continuation_message and continuation_remaining_length or buffer(offset, 4):uint()
                local message_content_offset = offset + (not is_continuation_message and 4 or 0)

                if not validate_reliable_message(buffer(message_content_offset):tvb(), message_content_size, is_continuation_message) then
                    return false
                end

                offset = message_content_offset + message_content_size
                index = index + 1
            end
        end

        return true
    end,
    [PACKET_TYPE_COMMAND] = function(buffer, sequence_sent)
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

    if validator and not validator(content, sequence_sent:uint(), sequence_received:uint()) then
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
        content_dissector(content, subtree, sequence_sent:uint(), sequence_received:uint())
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
