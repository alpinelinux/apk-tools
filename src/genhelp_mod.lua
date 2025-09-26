#!/usr/bin/lua5.3
-- Minimal module exposing the SCDOC parser for genhelp.lua and genbash.lua.

local M = {}

M.scdoc = {
	usage_prefix = "Usage: ",
}
M.scdoc.__index = M.scdoc

function M.scdoc:nop(ln)
	--print(self.section, ln)
end

function M.scdoc:SYNOPSIS_text(ln)
	table.insert(self.usage, self.usage_prefix .. ln)
	self.usage_prefix = "   or: "
end

function M.scdoc:COMMANDS_text(ln)
	ln = ln:gsub("apk%-(%S+)%(%d%)", "%1")
	local ch = ln:sub(1,1)
	local a, b = ln:match("^([[|:<]*)%s+(.+)")
	if ch == '|' then
		self.cur_cmd = { b, "" }
		table.insert(self.commands, self.cur_cmd)
	elseif ch == ':' and self.cur_cmd then
		self.cur_cmd[2] = b
		self.cur_cmd = nil
	end
end

function M.scdoc:COMMANDS_subsection(n)
	n = n:sub(1,1) .. n:sub(2):lower()
	table.insert(self.commands, n)
end

function M.scdoc:DESCRIPTION_text(ln)
	table.insert(self.description, ln)
end

function M.scdoc:DESCRIPTION_paragraph()
	if #self.description > 0 then
		self.section_text = self.nop
	end
end

function M.scdoc:OPTIONS_text(ln)
	local ch = ln:sub(1,1)
	if ch == '-' then
		self.cur_opt = { ln, {} }
		table.insert(self.options, self.cur_opt)
	elseif ch == '\t' then
		table.insert(self.cur_opt[2], ln:sub(2))
	end
end

function M.scdoc:NOTES_text(ln)
	table.insert(self.notes, ln)
end

function M.scdoc:parse_default(ln)
	if #ln == 0 then
		return (self[self.section .. "_paragraph"] or self.nop)(self)
	end
	local s,n = ln:match("^(#*) (.*)")
	if s and n then
		if #s == 1 then
			local optgroup, opts = n:match("^(%S*) ?(OPTIONS)$")
			if opts then
				if #optgroup == 0 then optgroup = self.applet end
				self.options = { name = optgroup }
				table.insert(self.optgroup, self.options)
				n = opts
			end
			self.section = n
			self.section_text = self[n .. "_text"] or self.nop
			self.subsection = nil
		else
			self.subsection = n
			local f = self[self.section.."_subsection"]
			if f then f(self, n) end
		end
		return
	end
	ln = ln:gsub("([^\\])%*(.-[^\\])%*", "%1%2")
	ln = ln:gsub("^%*(.-[^\\])%*", "%1")
	ln = ln:gsub("([^\\a-zA-Z0-9])_(.-[^\\])_([^a-zA-Z0-9])",
		function(a,s,e) return a..s:upper()..e end)
	ln = ln:gsub("([^\\a-zA-Z0-9])_(.-[^\\])_$",
		function(a,s) return a..s:upper() end)
	ln = ln:gsub("^_(.-[^\\])_([^a-zA-Z0-9])",
		function(s,e) return s:upper()..e end)
	ln = ln:gsub("^_(.-[^\\])_$",
		function(s) return s:upper() end)
	ln = ln:gsub("\\", "")
	self:section_text(ln)
end

function M.scdoc:parse_header(ln)
	self.manpage, self.mansection = ln:match("^(%S*)%((%d*)%)")
	if self.manpage:find("^apk%-") then
		self.applet = self.manpage:sub(5):lower()
	else
		self.applet = self.manpage:upper()
	end
	self.parser = self.parse_default
	self.section_text = self.nop
end

function M.scdoc:parse(fn)
	self.parser = self.parse_header
	for l in io.lines(fn) do
		self:parser(l)
	end
end

-- Factory to create a fresh scdoc instance
function M.new_scdoc()
	return setmetatable({
		width = 78,
		section = "HEADER",
		usage = {},
		description = {},
		commands = {},
		notes = {},
		optgroup = {},
	}, M.scdoc)
end

local function splittokens(s)
	local res = {}
	for w in s:gmatch("%S+") do
		res[#res+1] = w
	end
	return res
end

local function textwrap(text, linewidth)
	local spaceleft = linewidth
	local res = {}
	local line = {}

	for _, word in ipairs(splittokens(text)) do
		if #word + 1 > spaceleft then
			table.insert(res, table.concat(line, ' '))
			line = { word }
			spaceleft = linewidth - #word
		else
			table.insert(line, word)
			spaceleft = spaceleft - (#word + 1)
		end
	end
	table.insert(res, table.concat(line, ' '))
	return res
end

local function upperfirst(s)
	return s:sub(1,1):upper() .. s:sub(2):lower()
end

function M.scdoc:render_options(out, options)
	local width = self.width
	local nindent = 24

	table.insert(out, ("%s options:\n"):format(upperfirst(options.name)))
	for _, opt in ipairs(options) do
		local indent = (" "):rep(nindent)
		k, v = opt[1], opt[2]
		if #k > nindent - 4 then
			table.insert(out, ("  %s\n"):format(k, "", v))
			table.insert(out, indent)
		else
			local fmt = ("  %%-%ds  "):format(nindent - 4)
			table.insert(out, fmt:format(k, v))
		end

		v = table.concat(v, " ")
		local i = v:find("%.%s")
		if not i then i = v:find("%.$") end
		if i then v = v:sub(1, i-1) end
		v = textwrap(v, width - nindent - 1)

		table.insert(out, v[1])
		table.insert(out, "\n")
		for i = 2, #v do
			table.insert(out, indent)
			table.insert(out, v[i])
			table.insert(out, "\n")
		end
	end
end

function M.scdoc:render_optgroups(out, groups)
	for _, options in ipairs(self.optgroup) do
		if #options > 0 and (options.name == self.applet) ~= groups then
			table.insert(out, options.name .. "\0")
			self:render_options(out, options)
			if options.name == self.applet then
				self:render_footer(out)
			end
			table.insert(out, "\0")
		end
	end
end

function M.scdoc:render_footer(out)
	table.insert(out, ("\nFor more information: man %s %s\n"):format(self.mansection, self.manpage))
end

function M.scdoc:render(out)
	local width = self.width

	if not self.applet then return end
	table.insert(out, self.applet .. "\0")
	table.insert(out, table.concat(self.usage, "\n"))
	table.insert(out, "\n")
	if #self.commands > 0 then
		for _, cmd in ipairs(self.commands) do
			if type(cmd) == "string" then
				table.insert(out, "\n" .. cmd .. ":\n")
			else
				table.insert(out, ("  %-10s %s\n"):format(cmd[1], cmd[2]))
			end
		end
	elseif #self.description > 0 then
		table.insert(out, "\nDescription:\n")
		for _, ln in ipairs(textwrap(table.concat(self.description, ' '), width - 2)) do
			table.insert(out, ("  %s\n"):format(ln))
		end
	end
	if #self.notes > 0 then
		table.insert(out, "\n")
		table.insert(out, table.concat(self.notes, "\n"))
		if self.manpage == "apk" then self:render_footer(out)
		else table.insert(out, "\n") end
	end
	table.insert(out, "\0")
end

return M
