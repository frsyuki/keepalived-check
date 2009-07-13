#!/usr/bin/env ruby
#
# keepalived.conf parser
#
# Copyright (c) 2009 FURUHASHI Sadayuki
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

require 'phraser'
include Phraser

s = Phraser::Scanner.new

s.token :str,       /[^ \t\n\r\{\}]+/
s.token :comment,   /\![^\r\n]*/
s.token :blank,     /(:?[ \t]+)|(:?[ \t]+[\r\n]+)/
s.token :line_end,  /[ \t]*[\r\n][ \r\n\t]*/
s.token '{'
s.token '}'

Scanner = s


Rmail = rule do
	token(:str, /[a-zA-Z0-9\.\@]+/)
end

Rhost = rule do
	token(:str, /[a-zA-Z0-9\.]+/)
end

Rip = rule do
	token(:str, /[0-9\.]+/)
end

Rint = rule do
	token(:str, /[0-9]+/)
end

Rstr = rule do
	token(:str)
end

Rword = rule :word do
	token(:str, Regexp.new(tmpl[:word].to_s))
end


Rkey = rule :key do
	token(:str, Regexp.new(tmpl[:key].to_s))
end

Rblock = rule :body do
	token('{') ^ token(:line_end) ^
		(tmpl[:body] ^ token(:line_end)).* ^ token('}')
end


Rglobal_defs = rule do
	(Rkey[:notification_email] ^ Rblock[rule do Rmail end]) /
	(Rkey[:notification_email_from] ^ Rmail) /
	(Rkey[:smtp_server] ^ Rhost) /
	(Rkey[:smtp_connect_timeout] ^ Rint) /
	(Rkey[:router_id] ^ Rstr)
end


Rstatic_ipaddress = rule do
	# FIXME
	Rip ^ Rword[:dev] ^ token(:str) ^ (Rword[:scope] ^ token(:str)).opt
end


Rroot = rule do
	(Rkey[:global_defs] ^ Rblock[Rglobal_defs]) /
	(Rkey[:static_ipaddress] ^ Rblock[Rstatic_ipaddress])
end


Rule = rule do
	( Rroot ^ token(:line_end) ).* ^ eof
end


def parse(src)
	lx = Scanner.scan(src).delete_if {|r| r.token == :blank || r.token == :comment }
	Phraser::parse(Rule, lx)
end



src = <<EOF
global_defs {
	notification_email {
		a
		b
	}
	notification_email_from hoge@fuga
	smtp_server 127.0.0.1
	smtp_connect_timeout 0
	router_id LVS
}

static_ipaddress {
    192.168.200.16 dev eth0 scope link
    192.168.200.17 dev eth1 scope link
    192.168.200.18 dev eth2
}
EOF

cfg = parse(src)

