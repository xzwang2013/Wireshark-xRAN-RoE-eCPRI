-----------------------------------------------------------------
-- Version 1.10
-- wireshark analysis ROE protocol plugin
-- author yupzhang
-- 2018/07/10
-- Modified 2019/01/04 xzwang
-- 1. Fix some bug
-- 2. Add xRAN support
-- Modified 2019/01/10 xzwang
-- 1. Fix bugs, add multi-RoE decode
--
-- manual：
-- 1. copy RoE.lua and xranCplane.lua to wireshark root directory (in the same dir with init.lua)
-- 2. edit init.lua, check these lines
--
-- disable_lua = false
-- if disable_lua then
--    return
-- end
--
-- disable_lua should be false
--
-- 3.append dofile("RoE.lua") to the last line of init.lua
--
-----------------------------------------------------------------
--base mac layer protocol

do
    roe_proto = Proto("RoE","RoE Protocol");
    -- define RoE field
    local roe_sub_type    = ProtoField.uint8("RoE.subType", "Sub Type", base.DEC)
    local roe_flow_id     = ProtoField.uint8("RoE.flowID", "Flow Identity", base.DEC)
    local roe_length      = ProtoField.uint16("RoE.length", "RoE Length", base.DEC)
    local roe_order_info  = ProtoField.uint32("RoE.orderInfo", "Order Informaiton", base.DEC)
	local roe_opcode      = ProtoField.uint8("RoE.opCode", "opCode", base.HEX)
	local roe_tlv_type    = ProtoField.uint8("RoE.type", "type", base.HEX)
	local roe_tlv_length  = ProtoField.uint16("RoE.length", "length", base.DEC)
	local roe_tlv_value   = ProtoField.bytes("RoE.value", "value")
    local roe_content     = ProtoField.bytes("RoE.data", "Data")
	
	--add field into protocol
    roe_proto.fields = {
        roe_sub_type,
        roe_flow_id,
        roe_length,
        roe_order_info,
		roe_opcode,
		roe_tlv_type,
		roe_tlv_length,
		roe_tlv_value,
        roe_content,
		
		spirent_tag
    }
	
    --load bit operation library
	local bits = nil
    if _VERSION == "Lua 5.1" then
        bits = require "bit"
    elseif _VERSION == "Lua 5.2" then
        bits = require "bit32"
    else
        assert("we don't suport " .. _VERSION .. " please contact with author to get the new version...")    
    end

--[[        
    bit = {data32 = {}}
    for i = 1,32 do
        bit.data32[i] = 2^(32 - i)
    end
--]]    
    bit = {data32 = {2147483648,1073741824,536870912,268435456,134217728,67108864,33554432,16777216,
        8388608,4194304,2097152,1048576,524288,262144,131072,65536,
        32768,16384,8192,4096,2048,1024,512,256,128,64,32,16,8,4,2,1}}

    function bit:d2b(arg)
        local   tr = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
        for i = 1,32 do
            if arg >= bit.data32[i] then
                tr[i] = 1
                arg = arg - bit.data32[i]
            --else
                --tr[i] = 0
            end
        end
        return tr
    end   --bit:d2b

	function d2bstr(arg)
        local tr = bit:d2b(arg)
        local sr = ""
        table.insert(tr, 9, "|")
        table.insert(tr, 18, "|")
        table.insert(tr, 27, "|")
        local sr = table.concat(tr)
        return sr
    end
    
    function timestamp(arg)
        local tr = bit:d2b(arg)

        table.insert(tr, 2, "|")
        table.insert(tr, 5, "|")
        table.insert(tr, 30, "|")
        local sr = table.concat(tr)
        return sr
    end
    
    opcode_table = { "(RoE OAM TLV)", "(Ctrl_AxC words)", "(VSD)", "(Timing control packet)", "(Reserved)" }
    
    function parse_opcode(opcode_root, _opcode)
        if _opcode >= 0 and _opcode <= 3 then
            opcode_root:append_text(" " .. opcode_table[_opcode + 1])
        else
            opcode_root:append_text(" " .. opcode_table[5]) --Reserved
        end
    end
    
    tlv_type_table = { 
        "(Ethernet link)",
        "(CPRI port)",
        "(Mapper)",
        "(De-Mapper)",
        "(Mapper container)",
        "(De-mapper container)",
        "(Mapper FFT)",
        "(De-mapper FFT)",
        "(Mapper PRACH)",
        "(RoE 1914.1 TLV)",
        "(Reserved)"
    }
    
    function parse_tlv_type(tlv, _type)
        if _type >= 0 and _type <= 8 then
            tlv:append_text(" " .. tlv_type_table[_type + 1])
        elseif _type == 64 then
            tlv:append_text(" " .. tlv_type_table[10]) --RoE 1914.1 TLV
        else
            tlv:append_text(" " .. tlv_type_table[11]) --Reserved
        end
    end

    local data_dis = Dissector.get( "data" )
    local data
	
	-- global var 
	local g_roe_payload_len = 0
	local g_roe_tree
	
	function parse_roe_header(root, buf)
		local offset = 0
		g_roe_tree = root:add(roe_proto, buf:range(offset))
	    
		--subType field
	    local _sub_type = buf:range(offset, 1):uint()
        g_roe_tree:add(roe_sub_type, buf:range(offset, 1))
        offset = offset + 1
	    --flowID field
        g_roe_tree:add(roe_flow_id, buf:range(offset, 1))
        offset = offset + 1
	    --length filed
        g_roe_tree:add(roe_length, buf:range(offset, 2))
		local data_len = buf:range(offset, 2):uint()
		--payload total length
		g_roe_payload_len = data_len + 8
        offset = offset + 2
	    --orderInfo field
        local order_info_root = g_roe_tree:add(roe_order_info, buf:range(offset, 4))
        local order_info = buf:range(offset, 4):uint()
        local sequence_number = d2bstr(order_info)
        order_info_root:add("SequenceNumber: " .. sequence_number)

        tm_root = order_info_root:add("TimeStamp")
        sof = bits.rshift(order_info, 31)
        seq = bits.rshift(order_info, 29)
        seq = bits.band(seq, 3)        
        tmh = bits.rshift(order_info, 5)
        tmh = bits.band(tmh, 0xffffff)
        tml = bits.band(order_info, 0x1f)
        tm_root:add("SoF:", sof)
        tm_root:add("seqNum:", seq)
        tm_root:add("tmstamp(H):", tmh)
        tm_root:add("tmstamp(L):", tml)
		
		return _sub_type
	end
	
    --RoE main parser
    local function roe_proto_dissector(buf, pkt, root) 
        pkt.cols.protocol:set("RoE")
        pkt.cols.info:set("RoE Protocol")
       
        local offset = 0
        local total_length = buf:len()
        if (total_length < 8) then
            return false
        end
		
		--parse roe common header 8 byte
        local _sub_type = parse_roe_header(root, buf)
		offset = 8
		
		--control packet
        if _sub_type == 0 then
		    if offset < g_roe_payload_len then
		        --opCode field
				data = g_roe_tree:add("RoE Payload")
				data:append_text(" ("..(g_roe_payload_len - offset).." bytes)")
		
                local _opcode = buf:range(offset, 1):uint()
	            local opcode_root = data:add(roe_opcode, buf:range(offset, 1))
                parse_opcode(opcode_root, _opcode)
	            offset = offset + 1
	            while (offset < g_roe_payload_len) do	            
	                if _opcode == 0 then
					    local tlv = data:add("Tlv")
				        --tlv type is 7 bits
                        local _tlv_t = buf:range(offset, 1):uint()
						-- shift right 1 bit
                        _type = bits.rshift(_tlv_t, 1)
                        --_type = _tlv_t / 2
                        parse_tlv_type(tlv, _type)
						tlv:add(roe_tlv_type, _type)
			            offset = offset + 1
                        -- tlv length is 9 bits
                        local _tlv_l = buf:range(offset, 1):uint()
                        local _length = _tlv_l
						-- check type bit1 is 0 or 1
                        if bits.band(_tlv_t, 1) == 1 then
                            _length = _tlv_l + 256
                        end
                        --[[
                            if bit:_and(_tlv_t, 1) == 1 then
                                _length = _tlv_l + 256
                            end
                        --]]
						tlv:add(roe_tlv_length, _length)
                        offset = offset + 1
                        if offset + _length > g_roe_payload_len then
                            _length = g_roe_payload_len - offset
                            tlv:add("<<Tlv Length is wrong>>")
                        end                            
                        local _tlv_v = buf:range(offset, _length)                    
                        tlv:add(roe_tlv_value, _tlv_v)
                        offset = offset + _length
--[[						
	                elseif _opcode == 1 then
	                elseif _opcode == 2 then
	                elseif _opcode == 3 then
--]]
	                else
                        local roe_content_length = g_roe_payload_len - offset
                        data:add(roe_content, buf:range(offset, roe_content_length))
                        offset = offset + roe_content_length
	                    break
                    end
				end
                --call other protocol parser
                data_dis:call(buf(offset):tvb(), pkt, root)
            end
		elseif _sub_type >= 128 and _sub_type <= 131 then
			local xran_content_length = g_roe_payload_len - 8
			
            --call xRAN protocol parser
            xran_proto_parse(_sub_type, pkt, g_roe_tree, buf(offset), xran_content_length)
			offset = offset + xran_content_length
			
			--
			while (_sub_type == 129 or _sub_type == 131) do
				_sub_type = parse_roe_header(root, buf(offset))
				local xran_content_length = g_roe_payload_len - 8
				offset = offset + 8
				
				--call xRAN protocol parser
				xran_proto_parse(_sub_type, pkt, g_roe_tree, buf(offset), xran_content_length)
				offset = offset + xran_content_length
			end
			--
			
			--call other protocol parser
			data_dis:call(buf(offset):tvb(), pkt, root)
	    else			
	        --payload
            local roe_content_length = g_roe_payload_len - offset
            data = g_roe_tree:add("Unknow Payload")
			data:add(roe_content, buf:range(offset, roe_content_length))
            offset = offset + roe_content_length
            --call other protocol parser
            data_dis:call(buf(offset):tvb(), pkt, root)
	    end
        return true
    end
    
    function roe_proto.dissector(buf,pkt,root)
        if roe_proto_dissector(buf(offset):tvb(), pkt, root) then
        else
            data_dis:call(buf, pkt, root)
        end
    end
    
    --register protocol number
    local eth_proto_table = DissectorTable.get("ethertype")
    eth_proto_table:add(0xfc3d, roe_proto)
end
