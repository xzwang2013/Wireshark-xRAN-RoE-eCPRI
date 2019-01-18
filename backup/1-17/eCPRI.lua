-----------------------------------------------------------------
-- Version 1.10
-- wireshark analysis eCPRI protocol plugin
-- author xzwang
-- 2019/01/17
-----------------------------------------------------------------
--base mac layer protocol

do
    ecpri_proto = Proto("eCPRI","eCPRI Protocol");
	local ecpri_message = ProtoField.uint32("eCPRI.ecpriMessage", "Message", base.DEC)
	local ecpri_payload = ProtoField.uint32("eCPRI.ecpriPayload", "Payload", base.DEC)
    local ecpri_order_info  = ProtoField.uint32("eCPRI.orderInfo", "Order Informaiton", base.DEC)
    local ecpri_content     = ProtoField.bytes("eCPRI.data", "Data")

	--add field into protocol
    ecpri_proto.fields = {
		ecpri_message,
		ecpri_payload,
		ecpri_order_info,
		ecpri_content,
		
		spirent_tag
    }
	
	local data_dis = Dissector.get( "data" )
	
    --load bit operation library
	local bits = nil
    if _VERSION == "Lua 5.1" then
        bits = require "bit"
    elseif _VERSION == "Lua 5.2" then
        bits = require "bit32"
    else
        assert("we don't suport " .. _VERSION .. " please contact with author to get the new version...")    
    end

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
    
	local g_ecpri_tree
	local g_ecpriConcatenation
	local g_ecpriPayload
	local g_typeRoE
	
    function parse_ecpri_header(root, buf)
		local value
		local value_1
		
		g_ecpri_tree = root:add(ecpri_proto, buf:range(offset))
	    
		--ecpriVersion field
	    value = buf:range(0, 1):uint()
		value_1 = bits.rshift(value, 4)
        g_ecpri_tree:add("Version:", value_1)

		--ecpriReserved field
		value_1 = bits.band(value, 0x0E)
		value_1 = bits.rshift(value_1, 1)
		g_ecpri_tree:add("Reserved:", value_1)

		--ecpriConcatenation
		g_ecpriConcatenation = bits.band(value, 0x01)
		g_ecpri_tree:add("Concatenation:", g_ecpriConcatenation)

		--ecpriMessage
		local ecpriMessage = buf:range(1, 1):uint()
		g_ecpri_tree:add(ecpri_message, buf:range(1, 1))
		if ecpriMessage == 0 then 
			g_typeRoE = 128
		else
			g_typeRoE = 130
		end
			
		--ecpriPayload
		g_ecpriPayload = buf:range(2, 2):uint()
		g_ecpri_tree:add(ecpri_payload, buf:range(2, 2))
		g_ecpriPayload = g_ecpriPayload + 8
		
		--orderInfo field
        local order_info_root = g_ecpri_tree:add(ecpri_order_info, buf:range(4, 4))
        local order_info = buf:range(4, 4):uint()
        local sequence_number = d2bstr(order_info)
        order_info_root:add("SequenceNumber: " .. sequence_number)

        tm_root = order_info_root:add("TimeStamp")
        sof = bits.rshift(order_info, 31)
        seq = bits.rshift(order_info, 29)
        seq = bits.band(seq, 3)        
        tmh = bits.rshift(order_info, 5)
        tmh = bits.band(tmh, 0xffffff)
        tml = bits.band(order_info, 0x1F)
        tm_root:add("SoF:", sof)
        tm_root:add("seqNum:", seq)
        tm_root:add("tmstamp(H):", tmh)
        tm_root:add("tmstamp(L):", tml)
		
		return ecpriMessage
	end
	
    --eCPRI main parser
    local function ecpri_proto_dissector(buf, pkt, root) 
        pkt.cols.protocol:set("eCPRI")
        pkt.cols.info:set("eCPRI Protocol")
       
        local offset = 0
        local total_length = buf:len()
        if (total_length < 8) then
            return false
        end
		
		--parse eCPRI common header 8 byte
        local _sub_type = parse_ecpri_header(root, buf)
		offset = 8
		
		--control packet
        if _sub_type == 0 or _sub_type == 2 then
			local xran_content_length = g_ecpriPayload - 8
			
            --call xRAN protocol parser
			xran_proto_dissector(g_typeRoE, pkt, g_ecpri_tree, buf(offset), xran_content_length)
			offset = offset + xran_content_length
			
			--
			while (g_ecpriConcatenation == 1) do
				_sub_type = parse_ecpri_header(root, buf(offset))
				local xran_content_length = g_ecpriPayload - 8
				offset = offset + 8
				
				--call xRAN protocol parser
				xran_proto_dissector(g_typeRoE, pkt, g_ecpri_tree, buf(offset), xran_content_length)
				offset = offset + xran_content_length
			end
			--
			
			--call other protocol parser
			data_dis:call(buf(offset):tvb(), pkt, root)
	    else		
	        --payload
            local ecpri_content_length = g_ecpriPayload - offset
            data = g_ecpri_tree:add("Unknow Payload")
			data:add(ecpri_content, buf:range(offset, ecpri_content_length))
            offset = offset + ecpri_content_length
            --call other protocol parser
            data_dis:call(buf(offset):tvb(), pkt, root)
	    end
		
        return true
    end
    
    function ecpri_proto.dissector(buf,pkt,root)
        if ecpri_proto_dissector(buf(offset):tvb(), pkt, root) then
        else
            data_dis:call(buf, pkt, root)
        end
    end
    
    --register protocol number
    local eth_proto_table = DissectorTable.get("ethertype")
    eth_proto_table:add(0xAEFE, ecpri_proto)
	
	dofile("xRAN.lua")
end
