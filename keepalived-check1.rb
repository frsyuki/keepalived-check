#!/usr/bin/env ruby
#
# keepalived.conf parser and checker
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

s.token :sym,       /[^ \t\n\r\{\}]+/
s.token :comment,   /\![^\r\n]*/
s.token :blank,     /(:?[ \t]+)|(:?[ \t]+[\r\n]+)/
s.token :line_end,  /[ \t]*[\r\n][ \r\n\t]*/
s.token '{'
s.token '}'

Scanner = s


class Body < Array
	attr_accessor :conf
end

module Root
end

class Conf
	def initialize(key, values, body)
		@key = key
		@values = values
		@body = body
		@body.conf = self if @body
	end
	attr_reader :key, :values, :body
end

Rblock = rule do
	( token('{') ^ token(:line_end) ^ Rbody[:body] ^ token('}')
	).action {|x,e| e[:body] }
end

Rconf_key = rule do
	token(:sym)
end

Rconf_value = rule do
	( token(:sym).*[:values] ^ Rblock.opt[:body]
	).action {|x,e| [ e[:values], e[:body] ] }
end

Rconf = rule do
	( Rconf_key[:key] ^ Rconf_value[:value] ^ token(:line_end)
	).action {|x,e| Conf.new(e[:key], e[:value][0], e[:value][1]) }
end

Rbody = rule do
	( Rconf.*
	).action {|x,e| Body.new(x) }
end

Rule = rule do
	( Rbody ^ eof
	).action {|x,e| Conf.new('root', [], x[0]).extend(Root) }
end


def self.parse(src)
	lx = Scanner.scan(src).delete_if {|r| r.token == :blank || r.token == :comment }
	Phraser::parse(Rule, lx)
end


class Conf
	def to_s(nest_char = '  ', nest = 0)
		kv = "#{key}#{values.map {|v|" #{v}"}.join}"
		if body
			"#{kv} {\n#{body.to_s(nest_char, nest+1)}#{nest_char*nest}}\n"
		else
			"#{kv}\n"
		end
	end

	def inspect
		kv = "#{key}#{values.map {|v|" #{v}"}.join}"
		if body
			"#{kv} { #{body.inspect}} "
		else
			"#{kv}; "
		end
	end


	def match(pattern)
		unless values.length == pattern.length
			raise "require #{pattern.length} values at #{key}"
		end
		values.zip(pattern).each {|value,pat|
			unless pat.match(value).to_s == value
				raise "invalid value #{value.dump} at #{key}"
			end
		}
	end
end


class Body
	def to_s(nest_char = '  ', nest = 0)
		map do |conf|
			"#{nest_char*nest}#{conf.to_s(nest_char, nest)}"
		end.join('')
	end

	def inspect
		map {|conf| conf.inspect }.join('')
	end


	def match(pattern)
		conf.match(pattern)
	end

	def accept(key, pattern = nil, &pr)
		key = key.to_s if key.is_a?(Symbol)
		pr ||= Proc.new { match(pattern || []) }
		reject! {|conf|
			if key === conf.key
				raise "unexpected block at #{conf.key}" if conf.body
				conf.instance_eval(&pr)
				true
			end
		}
	end

	def accept_line(pattern = [], &pr)
		reject! {|conf|
			pr.call [conf.key] + conf.values
		}
	end

	def block(key, pattern = nil, &pr)
		key = key.to_s if key.is_a?(Symbol)
		reject! {|conf|
			if key === conf.key
				raise "block required at #{conf.key}" unless conf.body
				conf.body.instance_eval { match(pattern) } if pattern
				conf.body.instance_eval(&pr)
				unless conf.body.empty?
					keys = conf.body.map {|c| c.key.dump }
					raise "unexpected keys #{keys.join(', ')} at #{conf.key}"
				end
				true
			end
		}
	end
end


module Root
	def check(&pr)
		Body.new([self]).block(:root, [], &Accept)
	end
end


Astr    = /[a-zA-Z0-9_ ]+/
Aint    = /[0-9]+/
Ahost   = /[a-zA-Z0-9\.]+/
Aip     = /[0-9\.]+/
Aport   = /[0-9]+/
Amail   = /[a-zA-Z_\.\@]+/

Accept = Proc.new do
	block :global_defs, [] do
		block :notification_email, [] do
			accept Amail
		end
		accept :notification_email_from, [Amail]
		accept :smtp_server, [Ahost]
		accept :smtp_connect_timeout, [Aint]
		accept :router_id, [Astr]
	end

	block :static_ipaddress, [] do
		accept_line {|values|
			true  # FIXME
		}
	end

	block :static_routes, [] do
		accept_line {|values|
			true  # FIXME
		}
	end

	block :vrrp_script, [Astr] do
		accept :script, [Astr]
		accept :interval, [Aint]
		accept :weight do
			values.length == 0 && values[0] =~ Aint && (-254..254).include?(values.to_i)
		end
	end

	block :vrrp_sync_group, [Astr] do
		block :group, [] do
			accept Astr
		end
		accept :notify_master, [Astr]
		accept :notify_backup, [Astr]
		accept :notify_fault,  [Astr]
		accept :notify, [Astr]
		accept :smtp_alert, []
	end

	block :vrrp_instance, [Astr] do
		accept :state, [Regexp.union('MASTER','BACKUP')]
		accept :interface, [Astr]
		block :track_interface do
			accept_line do |values|
				values.length == 1 && values[0] =~ Astr
			end
			accept_line do |values|
				values.length == 3 && values[0] =~ Astr && values[1] == "weight" &&
					values[2] =~ Aint && (-254..254).include?(values[2].to_i)
			end
		end
	end

	block :virtual_server do
		match [Ahost, Aport]
		accept :protocol, [Regexp.union('TCP')]
	end
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

virtual_server 0.0.0.0 1000 {
	protocol TCP
}
EOF

cfg = parse(src)

cfg.check

