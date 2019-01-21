 -----------------------------------------------------------------
-- Version 1.10
-- wireshark analysis xRAN Cplane protocol plugin
-- author xzwang
-- 2019/01/10 xzwang
-- 1. First draft
--
-- manual：
-- Extend with RoE.lua
-----------------------------------------------------------------
--base mac layer protocol

 do
	xran_proto = Proto("xRAN", "xRAN Protocol");
	
	local xran_common_header_type     = ProtoField.bytes("xRAN.xran_header", "Common Header", base.HEX)	
	local xran_cplane_sections    = ProtoField.bytes("xRAN.cplane_sections", "Cplane Sections", base.HEX)	
	local xran_cplane_section    = ProtoField.bytes("xRAN.cplane_section", "Section", base.HEX)	
	local xran_cplane_extension    = ProtoField.bytes("xRAN.cplane_extension", "Extension", base.HEX)
	local xran_cplane_section_extension_data    = ProtoField.bytes("xRAN.cplane_section_extension_data", "Data", base.HEX)
	local xran_cplane_unknow_data    = ProtoField.bytes("xRAN.cplane_section_unknow", "Unknown", base.HEX)	
	
	local xran_uplane_sections    = ProtoField.bytes("xRAN.uplane_sections", "Uplane Sections", base.HEX)	
	local xran_uplane_section    = ProtoField.bytes("xRAN.uplane_section", "Section", base.HEX)	
	local xran_uplane_header    = ProtoField.bytes("xRAN.uplane_header", "Uplane Header", base.HEX)	
	local xran_uplane_prbu    = ProtoField.bytes("xRAN.uplane_prbu", "Prbu Data", base.HEX)	
	
	xran_proto.fields = {
		xran_common_header_type,
		xran_cplane_sections,
		xran_cplane_section,
		xran_cplane_extension,
		xran_cplane_section_extension_data,
		xran_cplane_unknow_data,
		xran_uplane_sections,
		xran_uplane_section,
		xran_uplane_header,
		xran_uplane_prbu
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

    bit = {data32 = {2147483648,1073741824,536870912,268435456,134217728,67108864,33554432,16777216,
        8388608,4194304,2097152,1048576,524288,262144,131072,65536,
        32768,16384,8192,4096,2048,1024,512,256,128,64,32,16,8,4,2,1}}

	function d2bstr_8(arg)
        local tr = d2b_8(arg)
        local sr = ""
        local sr = table.concat(tr)
        return sr
    end
	
	function d2b_8(arg)
        local tr = {0, 0, 0, 0, 0, 0, 0, 0}
        for i = 0,7 do
			local value = bits.lshift(arg, i)
			value = bits.rshift(arg, 7)
            tr[i] = value
        end
        return tr
    end   --bit:d2b
	
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
	
	------------------------------------------xRAN Cplane Part------------------------------------------------------
	----------------------------------------------------------------------------------------------------------------
	function parse_CplaneSectionExtension(_root, _value, _len)
		local ef = 1
		local extLen = 0
		local index = 0
		local sub_node
		local offset = 0
		local value
		
		if _len < 2 then
			return _len
		end
		
		while ef == 1 do
			sub_node = _root:add(xran_cplane_extension, _value:range(offset, 2))
			
			value = _value:range(offset, 1):uint()
			ef = bits.rshift(value, 7)
			sub_node:add("ef:", ef)
			
			value = bits.band(value, 0x07)
			sub_node:add("extType:", value)
			
			extLen = _value:range(offset + 1, 1):uint()
			sub_node:add("extLen:", extLen)
			extLen = extLen * 4
						
			sub_node:add(xran_cplane_section_extension_data, _value:range(offset + 2, extLen - 2))
			offset = offset + extLen
			
			sub_node:append_text(" ("..extLen.." bytes)")
			index = index + 1
		end
		
		return offset
	end
	
	function parse_CplaneSections_common(_root, _value, _len)
		local value 
		local value_1
	
		value = _value:range(0, 1):uint()
		value = bits.lshift(value, 4)
		value_1 = _value:range(1, 1):uint()
		value_1 = bits.rshift(value_1, 4)
		
		value = value + value_1
		_root:add("sectionId:", value)
				
		value = _value:range(1, 1):uint()
		value_1 = bits.band(value ,0x08)
		value_1 = bits.rshift(value_1, 3)
		_root:add("rb:", value_1)
		
		value_1 = bits.band(value ,0x04)
		value_1 = bits.rshift(value_1, 2)
		_root:add("symInc:", value_1)
		
		value_1 = bits.band(value ,0x03)
		value_1 = bits.lshift(value_1, 8)
		value = _value:range(2, 1):uint()
		value_1 = value_1 + value
		_root:add("startPrbe:", value_1)
		
		value = _value:range(3, 1):uint()
		_root:add("numPrbc:", value)
		
		value = _value:range(4, 1):uint()
		value = bits.lshift(value, 4)
		value_1 = _value:range(5, 1):uint()
		value_1 = bits.rshift(value_1, 4)
		value = value + value_1
		local sequence_number = d2bstr(value)
		sub_node = _root:add("reMask:", sequence_number)
		sub_node:append_text(" (12 bits)")
		
		value = _value:range(5, 1):uint()
		value = bits.band(value ,0x0F)
		_root:add("numSymbol:", value)
	end
	
	function parse_CplaneSections_0_1(_root, _value, _len)
		local value
		
		if _len < 7 then
			return _len
		end
		
		parse_CplaneSections_common(_root, _value, 6)
		
		value = _value:range(6, 2):uint()
		_root:add("reserved:", value)
		
		return 8
	end
	
	function parse_CplaneSections_0(_numberOfsections, _root, _value, _len)
		local offset = 0
		local len = 0
		local index = 0
		
		while (offset < _len and index < _numberOfsections) do	
			local sub_node = _root:add(xran_cplane_section, _value:range(offset, 6))
			len = parse_CplaneSections_0_1(sub_node, _value:range(offset, _len - offset), _len - offset)
			sub_node:append_text(""..index.." ("..len.." bytes)")
			offset = offset + len
			index = index + 1
		end	
		
		return offset
	end
	
	-- Parse one section detail
	function parse_CplaneSections_1_1(_root, _value, _len)
		local value 
		local value_1
		local ef = 0
		
		if _len < 7 then
			return _len
		end
		
		parse_CplaneSections_common(_root, _value, 6)
		
		value = _value:range(6, 1):uint()
		value_1 = bits.rshift(value, 7)
		_root:add("ef:", value_1)
		ef = value_1
		
		value_1 = bits.band(value ,0x7F)
		value_1 = bits.lshift(value_1, 8)
		value = _value:range(7, 1):uint()
		value_1 = value_1 + value
		_root:add("beamId:", value_1)
		
		len = 8
		if ef == 1 then
			sub_node = _root:add("Extensions:")
		
			local len_extensions = parse_CplaneSectionExtension(sub_node, _value:range(len, _len - len), _len - len)
			len = len + len_extensions
			sub_node:append_text(" ("..len_extensions.." bytes)")	
		end
		
		return len
	end
	
	-- Loop parse all sections
	function parse_CplaneSections_1(_numberOfsections, _root, _value, _len)
		local offset = 0
		local len = 0
		local index = 0
		
		while (offset < _len and index < _numberOfsections) do	
			local sub_node = _root:add(xran_cplane_section, _value:range(offset, 6))
			len = parse_CplaneSections_1_1(sub_node, _value:range(offset, _len - offset), _len - offset)
			sub_node:append_text(" ("..len.." bytes)")
			offset = offset + len
			index = index + 1
		end	
		
		return offset
	end

	function parse_CplaneSections_3_1(_root, _value, _len)
		local value 
		local value_1
		local ef = 0
		
		if _len < 7 then
			return _len
		end
		
		parse_CplaneSections_common(_root, _value, 6)
		
		value = _value:range(6, 1):uint()
		value_1 = bits.rshift(value, 7)
		_root:add("ef:", value_1)
		ef = value_1
		
		value_1 = bits.band(value ,0x7F)
		value_1 = bits.lshift(value_1, 8)
		value = _value:range(7, 1):uint()
		value_1 = value_1 + value
		_root:add("beamId:", value_1)
		
		value = _value:range(8, 3):uint()
		_root:add("frequencyOffset:", value)
		
		value = _value:range(11, 1):uint()
		_root:add("reserved:", value)
		
		len = 12
		if ef == 1 then
			sub_node = _root:add("Extensions:")
		
			local len_extensions = parse_CplaneSectionExtension(sub_node, _value:range(len, _len - len), _len - len)
			len = len + len_extensions
			sub_node:append_text(" ("..len_extensions.." bytes)")	
		end
		
		return len
	end
	
	function parse_CplaneSections_3(_numberOfsections, _root, _value, _len)
		local offset = 0
		local len = 0
		local index = 0
		
		while (offset < _len and index < _numberOfsections) do	
			--local sub_node = _root:add("Section_"..index..":")
			local sub_node = _root:add(xran_cplane_section, _value:range(offset, 6))
			len = parse_CplaneSections_3_1(sub_node, _value:range(offset, _len - offset), _len - offset)
			sub_node:append_text(" ("..len.." bytes)")
			offset = offset + len
			index = index + 1
		end	
		
		return offset
	end
	
	function parse_CplaneSections_5_1(_root, _value, _len)
		local value 
		local value_1
		local ef = 0
		
		if _len < 7 then
			return _len
		end
		
		parse_CplaneSections_common(_root, _value, 6)
		
		value = _value:range(6, 1):uint()
		value_1 = bits.rshift(value, 7)
		_root:add("ef:", value_1)
		ef = value_1
		
		value_1 = bits.band(value ,0x7F)
		value_1 = bits.lshift(value_1, 8)
		value = _value:range(7, 1):uint()
		value_1 = value_1 + value
		_root:add("ueId:", value_1)
		
		len = 8
		if ef == 1 then
			sub_node = _root:add("Extensions:")
		
			local len_extensions = parse_CplaneSectionExtension(sub_node, _value:range(len, _len - len), _len - len)
			len = len + len_extensions
			sub_node:append_text(" ("..len_extensions.." bytes)")	
		end
		
		return len
	end
	
	function parse_CplaneSections_5(_numberOfsections, _root, _value, _len)
		local offset = 0
		local len = 0
		local index = 0
		
		while (offset < _len and index < _numberOfsections) do	
			local sub_node = _root:add(xran_cplane_section, _value:range(offset, 6))
			len = parse_CplaneSections_5_1(sub_node, _value:range(offset, _len - offset), _len - offset)
			sub_node:append_text(" ("..len.." bytes)")
			offset = offset + len
			index = index + 1
		end	
		
		return offset
	end
	
	function parse_CplaneSections_6_1(_root, _value, _len)
		local value 
		local value_1
		local ef = 0
		
		if _len < 7 then
			return _len
		end
		
		value = _value:range(0, 1):uint()
		value_1 = bits.rshift(value, 7)
		_root:add("ef:", value_1)
		ef = value_1
		
		value_1 = bits.band(value ,0x7F)
		value_1 = bits.lshift(value_1, 8)
		value = _value:range(1, 1):uint()
		value_1 = value_1 + value
		_root:add("ueId:", value_1)
		
		value = _value:range(2, 2):uint()
		_root:add("regularizationFactor:", value)
		
		value = _value:range(4, 1):uint()
		value_1 = bits.rshift(value, 4)
		_root:add("reserved:", value_1)
		
		value_1 = bits.band(value, 0x08)
		value_1 = bits.rshift(value_1, 3)
		_root:add("rb:", value_1)
		
		value_1 = bits.band(value, 0x04)
		value_1 = bits.rshift(value_1, 2)
		_root:add("symInc:", value_1)
		
		value_1 = bits.band(value, 0x03)
		value_1 = bits.lshift(value_1, 8)
		value = _value:range(5, 1):uint()
		value = value + value_1
		_root:add("startPrbc:", value)
		
		value = _value:range(6, 1):uint()
		_root:add("numPrbc:", value)
		
		len = 7
		
		return len
	end
	
	function parse_CplaneSections_6(_numberOfsections, _root, _value, _len)
		local offset = 0
		local len = 0
		local index = 0
		
		--Can't fully support type 6 
		--while (offset < _len and index < _numberOfsections) do	
		while (offset < _len and index < 1) do
			local sub_node = _root:add(xran_cplane_section, _value:range(offset, 6))
			len = parse_CplaneSections_6_1(sub_node, _value:range(offset, _len - offset), _len - offset)
			sub_node:append_text(" ("..len.." bytes)")
			offset = offset + len
			index = index + 1
		end	
		
		_root:add(xran_cplane_unknow_data, _value:range(offset, _len - offset))
		
		return _len
	end

	
	function parse_CplaneSectionExtension_type7(_root, _value, _len)
		local value = 0
		local value_1 = 0
		local laaMsgType = 0
		local laaMsgLen = 0
		
		if _len < 2 then
			return _len
		end
		
		value = _value:range(0, 1):uint()
		laaMsgType = bits.rshift(value, 4)
		_root:add("laaMsgType", laaMsgType)
		
		laaMsgLen = bits.band(value, 0x0F)
		_root:add("laaMsgLen", laaMsgType)

		if laaMsgType == 0 then
			if _len < 8 then
				return _len
			end
			
			value = _value:range(1, 2):uint()
			_root:add("lbtHandle", value)
			
			value = _value:range(3, 1):uint()
			value = bits.lshift(value, 1)
			value_1 = _value:range(4, 1):uint()
			value_1 = bits.rshift(value_1, 6)
			value = value + value_1
			_root:add("lbtOffset", value)
			
			value = _value:range(4, 1):uint()
			value_1 = bits.rshift(value, 4)
			value_1 = bits.band(value_1, 0x03)
			_root:add("lbtMode", value_1)
			
			value_1 = bits.band(value, 0x0F)
			value_1 = bits.rshift(value, 3)
			_root:add("reserved", value_1)
			
			value_1 = bits.band(value, 0x07)
			_root:add("lbtDeferFactor", value)
			
			value = _value:range(5, 1):uint()
			value = bits.lshift(value, 1)
			value_1 = _value:range(6, 1):uint()
			value_1 = bits.rshift(value_1, 6)
			value = value + value_1
			_root:add("lbtBakoffCounter", value)
			
			value = _value:range(6, 1):uint()
			value_1 = bits.band(value, 0x3B)
			value_1 = bits.rshift(value_1, 2)
			_root:add("MCOT", value_1)
			
			value_1 = bits.band(value, 0x03)
			_root:add("reserved", value_1)
			
			value = _value:range(7, 1):uint()
			_root:add("reserved", value_1)
			
		elseif laaMsgType == 1 then
			if _len < 8 then
				return _len
			end
			
			value = _value:range(1, 2):uint()
			_root:add("lbtHandle", value)
			
			value = _value:range(3, 1):uint()
			value = bits.lshift(value, 1)
			value_1 = _value:range(4, 1):uint()
			value_1 = bits.rshift(value_1, 6)
			value = value + value_1
			_root:add("lbtOffset", value)
			
			value = _value:range(4, 1):uint()
			value_1 = bits.rshift(value, 4)
			value_1 = bits.band(value_1, 0x03)
			_root:add("lbtMode", value_1)
			
			value_1 = bits.band(value, 0x0F)
			_root:add("reserved", value_1)
			_root:add("reserved", value_1)
			
			value = _value:range(5, 1):uint()
			_root:add("reserved", value)
			
			value = _value:range(6, 1):uint()
			_root:add("reserved", value)
			
			value = _value:range(7, 1):uint()
			_root:add("reserved", value)
		elseif laaMsgType == 2 then
			if _len < 4 then
				return _len
			end	
			
			value = _value:range(1, 1):uint()
			_root:add("lbtHandle", value)
			
			value = _value:range(2, 1):uint()
			value_1 = bits.rshift(value, 6)
			_root:add("lbtPdschRes", value_1)
			
			value_1 = bits.band(value, 0x20)
			value_1 = bits.rshift(value_1, 5)
			_root:add("inParSF", value_1)
			
			value_1 = bits.band(value, 0x10)
			value_1 = bits.rshift(value_1, 4)
			_root:add("sfStatus", value_1)
			
			value = bits.lshift(value, 4)
			value_1 = _value:range(3, 1):uint()
			value_1 = value_1 + value
			_root:add("sfnSf", value_1)
		elseif laaMsgType == 3 then
			if _len < 4 then
				return _len
			end	
			
			value = _value:range(1, 1):uint()
			_root:add("lbtHandle", value)
			
			value = _value:range(2, 1):uint()
			value_1 = bits.rshift(value, 7)
			_root:add("lbtDrsRes", value_1)
			
			value_1 = bits.band(value, 0x7F)
			_root:add("reserved", value_1)
			
			value_1 = _value:range(3, 1):uint()
			_root:add("reserved", value_1)
		elseif laaMsgType == 4 then
			if _len < 4 then
				return _len
			end	
			
			value = _value:range(1, 1):uint()
			_root:add("lbtHandle", value)
			
			value = _value:range(2, 1):uint()
			value_1 = bits.rshift(value, 7)
			_root:add("lbtBufErr", value_1)
			
			value_1 = bits.band(value, 0x7F)
			_root:add("reserved", value_1)
			
			value_1 = _value:range(3, 1):uint()
			_root:add("reserved", value_1)	
		elseif laaMsgType == 5 then
			if _len < 8 then
				return _len
			end	
			
			value = _value:range(1, 2):uint()
			_root:add("lbtHandle", value)
			
			value = _value:range(3, 1):uint()
			_root:add("lbtCWConfigH", value_1)
			
			value = _value:range(4, 1):uint()
			_root:add("lbtCWConfigT", value)
			
			value = _value:range(5, 1):uint()
			value_1 = bits.rshift(value, 2)
			_root:add("lbtMode", value_1)
			
			value_1 = bits.band(value, 0x30)
			value_1 = bits.rshift(value, 4)
			_root:add("lbtTraffcClass", value_1)
			
			value_1 = bits.band(value, 0x0F)
			_root:add("reserved", value_1)
			
			value_1 = _value:range(6, 2):uint()
			_root:add("reserved", value_1)		
		elseif laaMsgType == 6 then
			if _len < 4 then
				return _len
			end	
			
			value = _value:range(1, 2):uint()
			_root:add("lbtHandle", value)
			
			value = _value:range(3, 1):uint()
			value_1 = bits.rshift(value, 7)
			_root:add("lbtCWR Rst", value_1)
			
			value_1 = bits.band(value, 0x7F)
			_root:add("reserved", value_1)			
		else
			return
		end
	end 

	function parse_CplaneSections_7_1(_root, _value, _len)
		local value
		
		if _len < 7 then
			return _len
		end
		
		parse_CplaneSections_common(_root, _value, 6)
		
		value = _value:range(6, 2):uint()
		_root:add("reserved:", value)
		
		len = 8
		sub_node = _root:add("Extensions:")
		local len_extensions = parse_CplaneSectionExtension_type7(sub_node, _value:range(len, _len - len), _len - len)
		len = len + len_extensions
		sub_node:append_text(" ("..len_extensions.." bytes)")	
			
		return 8
	end
	
	function parse_CplaneSections_7(_numberOfsections, _root, _value, _len)
		local offset = 0
		local len = 0
		local index = 0
		
		while (offset < _len and index < _numberOfsections) do	
			local sub_node = _root:add(xran_cplane_section, _value:range(offset, 6))
			len = parse_CplaneSections_7_1(sub_node, _value:range(offset, _len - offset), _len - offset)
			sub_node:append_text(" ("..len.." bytes)")
			offset = offset + len
			index = index + 1
		end	
		
		return offset
	end
	
	function parse_CplaneSections(_type, _numberOfsections, _root, _value, _len)
		local len = 0
		
		if _type == 0 then
			len = parse_CplaneSections_0(_numberOfsections, _root, _value, _len)
		elseif _type == 1 then
			len = parse_CplaneSections_1(_numberOfsections, _root, _value, _len)
		elseif _type == 3 then
			len = parse_CplaneSections_3(_numberOfsections, _root, _value, _len)
		elseif _type == 5 then
			len = parse_CplaneSections_5(_numberOfsections, _root, _value, _len)
		elseif _type == 6 then
			-- Not fully support type 6 
			len = parse_CplaneSections_6(_numberOfsections, _root, _value, _len)
		elseif _type == 7 then
			len = parse_CplaneSectionType_7(_root, _value, _len)
		else
			return _len
		end
		
		return len
	end
	
	------------------------------------------xRAN Uplane Part------------------------------------------------------
	----------------------------------------------------------------------------------------------------------------
	local g_numPrbu
	local g_udIqWidth
	local g_udCompMeth
	
	function parse_Uplane_Common_header(_root, _value, _len)
		local value
		local value_1
		
		value = _value:range(0, 1):uint()
		value = bits.lshift(value, 4)
		value_1 = _value:range(1, 1):uint()
		value_1 = bits.rshift(value_1, 4)
		value = value + value_1
		_root:add("sectionId:", value)
		
		value = _value:range(1, 1):uint()
		value_1 = bits.band(value, 0x08);
		value_1 = bits.rshift(value_1, 3)
		_root:add("rb:", value_1)
		
		value_1 = bits.band(value, 0x04);
		value_1 = bits.rshift(value_1, 2)
		_root:add("symInc:", value_1)
		
		value_1 = bits.band(value, 0x03);
		value_1 = bits.lshift(value_1, 8)
		value = _value:range(2, 1):uint()
		value = value + value_1
		_root:add("startPrbu:", value)
		
		g_numPrbu = _value:range(3, 1):uint()
		_root:add("numPrbu:", g_numPrbu)
		
		value = _value:range(4, 1):uint()
		g_udIqWidth = bits.rshift(value, 4)
		if (g_udIqWidth == 0) then
			g_udIqWidth = 16
		end	
		
		_root:add("udIqWidth:", g_udIqWidth)
		g_udCompMeth = bits.band(value, 0x0F)
		_root:add("udCompMeth:", g_udCompMeth)
		
		value = _value:range(5, 1):uint()
		_root:add("reserved:", value)
		
		return 6
	end
	
	function parse_uPlane_Prbu(_root, _value, _len)
		local offset = 0
		local value = 0
		local index = 0
		
		if (g_udCompMeth == 1 or g_udCompMeth == 2 or g_udCompMeth == 3) then
			value = _value:range(0, 1):uint()
			_root:add("udCompParam:", value)
			offset = offset + 1
		end
		
		local prbu_len = g_udIqWidth * 3 
		local sub_node = _root:add(xran_uplane_prbu, _value:range(offset, prbu_len))
		
		bin_node = sub_node:add("Bin:")
		while index < prbu_len do
			local bin = d2bstr_8(_value:range(offset + index, 1):uint())
			bin_node:append_text(" "..bin.."")
			if (index > 0 and (index + 1) % 8 == 0) then 
				bin_node:append_text(" |")
			end
			index = index + 1
		end
		
		sub_node:append_text(" ("..prbu_len.." bytes)")
		
		offset = offset + prbu_len
		
		return offset
		
	end
	
	function parse_UplaneSection(_root, _value, _len)
		local offset = 0
		local len = 0
		local index = 0
		
		if _len < 6 then
			return _len
		end
		
		local sub_node = _root:add(xran_uplane_header, _value:range(offset, 6))
		len = parse_Uplane_Common_header(sub_node, _value, 6)
		sub_node:append_text(" ("..len.." bytes)")
		offset = len
		
		while (offset < _len and index < g_numPrbu) do
			sub_node = _root:add("Prbu", _value:range(offset, 6))
			len = parse_uPlane_Prbu(sub_node, _value:range(offset, _len - offset),  _len - offset)
			sub_node:append_text(" ("..len.." bytes)")
			
			offset = offset + len
			index = index + 1
		end
		
		return offset
	end 
	
	function parse_UplaneSections(_type, _numberOfsections, _root, _value, _len)
		local offset = 0
		local len = 0
		local index = 0
		
		while (offset < _len and index < _numberOfsections) do	
			local sub_node = _root:add(xran_uplane_section, _value:range(offset, 6))
			len = parse_UplaneSection(sub_node, _value:range(offset, _len - offset), _len - offset)
			sub_node:append_text(" ("..len.." bytes)")
			
			offset = offset + len
			index = index + 1
		end	
		
		return offset
	end
	
	----------------------------------------------xRAN Root Part----------------------------------------------------
	----------------------------------------------------------------------------------------------------------------
	function parse_CommonHeaderType(_root, _value)
		local dataDirection = _value:range(0, 1):uint()
		dataDirection = bits.rshift(dataDirection, 7)
		_root:add("dataDirection:", dataDirection)

		local payloadVersion = _value:range(0, 1):uint()
		payloadVersion = bits.band(payloadVersion ,0x7f)
		payloadVersion = bits.rshift(payloadVersion, 4)
		_root:add("payloadVersion:", payloadVersion)
		
		local filterIndex = _value:range(0, 1):uint()
		filterIndex = bits.band(filterIndex ,0x0f)
		_root:add("filterIndex:", filterIndex)
		
		local frameId = _value:range(1, 1):uint()
		_root:add("frameId:", frameId)
		
		local subframeId = _value:range(2, 1):uint()
		subframeId = bits.rshift(subframeId, 4)
		_root:add("subframeId:", subframeId)
		
		local slotId = _value:range(2, 1):uint()
		slotId = bits.band(slotId ,0x0f)
        slotId = bits.lshift(slotId, 2)
		
		local startSymbolid = _value:range(3, 1):uint()
		local tmp = bits.rshift(startSymbolid, 6)
		slotId = slotId + tmp
		_root:add("slotID:", slotId)
		
		startSymbolid = bits.band(startSymbolid ,0x3f)
		_root:add("startSymbolid:", startSymbolid)
		
		local numberOfsections = _value:range(4, 1):uint()
		_root:add("numberOfSections:", numberOfsections)

		local sectionType = _value:range(5, 1):uint()
		_root:add("sectionType:", sectionType)
		
		return sectionType
    end
	
	function parse_CommonHeaderField_2_Cplane(_type, _root, _value)
		local value 
		local len = 0
		
		if _type == 0 then
			value = _value:range(0, 2):uint()
			_root:add("timeOffset:", value)
		
			value = _value:range(2, 1):uint()
			_root:add("frameStructure:", value)
			
			value = _value:range(3, 2):uint()
			_root:add("cpLength:", value)
			
			value = _value:range(5, 1):uint()
			_root:add("reserved:", value)
			
			len = 6
		elseif _type == 1 then
			value = _value:range(0, 1):uint()
			_root:add("reserved:", value)
		
			value = _value:range(1, 1):uint()
			_root:add("udCompHdr:", value)
			
			len = 2
		elseif _type == 3 then
			value = _value:range(0, 2):uint()
			_root:add("timeOffset:", value)
		
			value = _value:range(2, 1):uint()
			_root:add("frameStructure:", value)
			
			value = _value:range(3, 2):uint()
			_root:add("cpLength:", value)
			
			value = _value:range(5, 1):uint()
			_root:add("udCompHdr:", value)
			
			len = 6
		elseif _type == 5 then
			value = _value:range(0, 1):uint()
			_root:add("reserved:", value)
		
			value = _value:range(1, 1):uint()
			_root:add("udCompHdr:", value)
			
			len = 2
		elseif _type == 6 then
			value = _value:range(0, 1):uint()
			_root:add("numberOfUEs:", value)
		
			value = _value:range(1, 1):uint()
			_root:add("reserved:", value)
			
			len = 2
		elseif _type == 7 then
			value = _value:range(0, 1):uint()
			_root:add("reserved:", value)
		
			value = _value:range(1, 1):uint()
			_root:add("reserved:", value)
			
			len = 2
		else
			len = 0
		end
		
		return len
	end
	
    --xRAN main parser
    function xran_proto_dissector_one(_roeSubType, _root, _value, _len) 
		local node
		local g_offset = 0
		local len = 0
		
        node = _root:add("xRAN", _value:range(0, _len))
		local common_header_part = _value:range(g_offset, 6)
		local sub_node = node:add(xran_common_header_type, common_header_part)
		--local sub_node = node:add(xran_common_header_type, common_header_part)
		
		-- Parse the common header type first 6 byte. And get the type value
		local sectionType = parse_CommonHeaderType(sub_node, common_header_part)
		local numberOfsections = _value:range(4, 1):uint()
		g_offset = g_offset + 6
		
		if (_roeSubType == 130 or _roeSubType == 131) then
			-- Parse the left bytes in the common header type
			if sectionType >= 0 and sectionType <= 7 then
				len = parse_CommonHeaderField_2_Cplane(sectionType, sub_node, _value:range(g_offset, 6))
				g_offset = g_offset + len
			else
				--Error jump over
				return _len
			end
		end
		
		-- Adjust the common header length
		sub_node:append_text(" ("..g_offset.." bytes)")
		local plane_sections_buf = _value:range(g_offset, _len - g_offset)
		
		if (_roeSubType == 130 or _roeSubType == 131) then
			-- Parse the Cplane Sections
			if sectionType >= 0 and sectionType <= 7 then
				sub_node = node:add(xran_cplane_sections, plane_sections_buf)
			
				len = parse_CplaneSections(sectionType, numberOfsections, sub_node, plane_sections_buf, _len - g_offset)
				sub_node:append_text(" ("..len.." bytes)")
			else
				--Error jump over
				return _len
			end
		else
			-- Parse the Uplane Sections
			sub_node = node:add(xran_uplane_sections, plane_sections_buf)
			len = parse_UplaneSections(sectionType, numberOfsections, sub_node, plane_sections_buf, _len - g_offset)
			sub_node:append_text(" ("..len.." bytes)")
		end
		
		g_offset = g_offset + len
						
		if (_roeSubType == 130 or _roeSubType == 131) then
			node:append_text(" Cplane ("..g_offset.." bytes)")
		else
			node:append_text(" Uplane ("..g_offset.." bytes)")
		end
		
		return g_offset
    end
	
    function xran_proto_parse(_roeSubType, _pkt, _root, _value, _len) 
		_pkt.cols.protocol:set("xRAN")
        _pkt.cols.info:set("xRAN Protocol")
		
		local xran_buf = _value:range(0, _len)
		len = xran_proto_dissector_one(_roeSubType, _root, xran_buf, _len) 
	end
	
	dofile("RoE.lua")
	dofile("eCPRI.lua")
end    

