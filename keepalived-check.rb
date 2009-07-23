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

s.token :blank,     /[ \t]+/
s.token :comment,   /[\!\#][^\r\n]*$/
s.token :line_end,  /[\r\n]/
s.token :qstr,      /\'[^\']*\'/
s.token :qqstr,     /\"[^\"]*\"/
s.token '{'
s.token '}'
s.token :sym,       /[^ \t\n\r]+/

Scanner = s


Rblock = rule do
	( token('{') ^ token(:line_end).+ ^ Rbody[:body] ^ token('}')
	).action {|x,e| e[:body] }
end

Rconf_value = rule do
	token(:sym) / token(:qstr) / token(:qqstr)
end

Rconf = rule do
	( Rconf_value.+[:values] ^ Rblock.opt[:block] ^ token(:line_end).+
	).action {|x,e| Conf.new(e[:values], e[:block]) }
end

Rbody = rule do
	( Rconf.*
	).action {|x,e| Body.new(x) }
end

Rule = rule do
	( token(:line_end).* ^ Rbody[:body] ^ eof
	).action {|x,e| Conf.new(['root'], e[:body]).extend(Root) }
end


def self.parse(src)
	lx = Scanner.scan(src).delete_if {|r| r.token == :blank || r.token == :comment }
	Phraser::parse(Rule, lx)
end


Aany    = /.+/
Apath   = Aany
Astr    = /[a-zA-Z0-9_\.]+/
Anetif  = /[a-zA-Z0-9_\.:]+/
Aint    = /\-?[0-9]+/
Ahost   = /[a-zA-Z0-9_\-\.]+/
Aip     = /[0-9\.]+/
Aiprange= /[0-9\.\-]+/
Aipmask = /[0-9\.\/]+/
Aport   = /[0-9]+/
Amail   = /[a-zA-Z0-9_\-\+\.\@]+/
Amask   = Aip
Adigest = /[a-fA-F0-9]{32}/

Aint_254_254 = Proc.new {|v| Aint.match(v).to_s == v && (-254..254).include?(v.to_i) }
Aint_0_255   = Proc.new {|v| Aint.match(v).to_s == v && (0..255).include?(v.to_i) }


opt = {
	:verbose => false,
	:extend  => false,
}

Accept = Proc.new do
	block :global_defs do
		block :notification_email do
			accept Amail
		end
		accept :notification_email_from, Amail
		accept :smtp_server, Ahost
		accept :smtp_connect_timeout, Aint
		accept_one :router_id, Astr
		accept_one :lvs_id, Astr
	end

	block :static_ipaddress do
		try_accept Aip, :dev, Anetif
		try_accept Aip, :dev, Anetif, :scope, Regexp.union(*%w[site link host nowhere global_defs])
	end

	virtual_server_block = Proc.new do
		accept :delay_loop, Aint
		accept :lb_algo,    Regexp.union(*%w[rr wrr lc wlc lblc sh dh])
		accept :lvs_sched,  Regexp.union(*%w[rr wrr lc wlc lblc sh dh])
		accept :lb_kind,    Regexp.union(*%w[NAT DR TUN])
		accept :lvs_method, Regexp.union(*%w[NAT DR TUN])
		accept :nat_mask, Aip
		accept :persistence_timeout, Aint
		accept :persistence_granularity, Amask
		accept :protocol, Regexp.union(*%w[TCP UDP])
		accept :ha_suspend
		accept :virtualhost, Astr
		accept :alpha
		accept :omega
		accept :quality, Aint
		accept :hysteresis, Aint
		accept :quorum, Aint
		accept :quorum_up, Apath
		accept :quorum_down, Apath
		accept :sorry_server, Aip, Aport
		real_server_block = Proc.new do
			accept :weight, Aint
			accept :inhibit_on_failure
			accept :notify_master, Apath
			accept :notify_down, Apath

			http_block = Proc.new do
				block :url do
					accept :path, Apath
					accept :digest, Adigest
					accept :status_code, Aint
				end
				accept :connect_port, Aint
				accept :bindto, Aip
				accept :connect_timeout, Aint
				accept :nb_get_retry, Aint
				accept :delay_before_retry, Aint
			end
			block :HTTP_GET, &http_block
			block :SSL_GET, &http_block

			block :TCP_CHECK do
				accept :connect_port, Aport
				accept :bindto, Aip
				accept :connect_timeout, Aint
			end

			block :SMTP_CHECK do
				block :host do
					accept :connect_ip, Aip
					accept :connect_port, Aport
					accept :bindto, Aip
				end
				accept :connect_timeout, Aint
				accept :retry, Aint
				accept :delay_before_retry, Aint
				accept :helo_name, Aany
			end

			block :MISC_CHECK do
				accept :misc_path, Apath
				accept :misc_timeout, Aint
				accept :misc_dynamic
			end

			if opt[:extend]
				# http://dsas.blog.klab.org/archives/51030424.html
				block :DNS_CHECK do
					accept :port,    Aport
					accept :timeout, Aint
					accept :retry,   Aint
					accept :type,    Astr
					accept :name,    Astr
				end

				block :SSL_HELLO do
					accept :connect_port,       Aport
					accept :connect_timeout,    Aint
					accept :retry,              Aint
					accept :delay_before_retry, Aint
					accept :common_name,        Astr
				end

				block :FTP_CHECK do
					accept :connect_port,       Aport
					accept :bind_to,            Aip
					accept :connect_timeout,    Aint
					accept :retry,              Aint
					accept :delay_before_retry, Aint
				end
			end  # opt[:extend]

		end
		try_block :real_server, Aip, Aport, &real_server_block
		try_block :real_server, Aip, &real_server_block
	end
	try_block :virtual_server, Ahost, Aport, &virtual_server_block
	try_block :virtual_server, :fwmark, Aint, &virtual_server_block
	try_block :virtual_server, :group, Astr, &virtual_server_block

	block :virtual_server_group, Aany do
		accept Aiprange, Aport
		accept :fwmark, Aint
	end

	block :vrrp_sync_group, Astr do
		block :group do
			accept Astr
		end
		accept :notify_master, Apath
		accept :notify_backup, Apath
		accept :notify_fault, Apath
		accept :notify_stop, Apath
		accept :notify, Apath
		accept Astr
	end

	block :vrrp_script, Astr do
		accept :script, Apath
		accept :interval, Aint
		accept :weight, Aint
	end

	block :vrrp_instance, Astr do
		accept :state, Regexp.union(*%w[MASTER BACKUP])
		accept :interface, Anetif
		accept :lvs_sync_daemon_interface, Anetif
		block :track_interface do
			try_accept Anetif
			try_accept Anetif, :weight, Aint_254_254
		end
		block :track_script do
			try_accept Apath
			try_accept Apath, :weight, Aint_254_254
		end
		accept :dont_track_primary
		accept :mcast_src_ip, Aip
		accept :garp_master_delay, Aint
		accept_one :virtual_router_id, Aint_0_255
		accept :priority, Aint_0_255
		accept :advert_int, Aint
		block :authentication do
			accept :auth_type, Regexp.union(*%w[PASS AH])
			accept :auth_pass, Aany
		end
		block :virtual_ipaddress do
			try_accept Aipmask
			try_accept Aipmask, :dev, Anetif
			try_accept Aipmask, :label, Aany
		end
		block :virtual_ipaddress_excluded do
			try_accept Aipmask
		end
		block :virtual_routes do
			try_accept :src, Aip, Aipmask, :via, Aip, :dev, Anetif
			try_accept :blackhole, Aipmask
			try_accept Aipmask, :via, Aip, :dev, Anetif
			try_accept Aipmask, :via, Aip
			try_accept Aipmask, :dev, Anetif
			try_accept Aipmask, :dev, Anetif, :scope, Regexp.union(*%w[site link host nowhere global_defs])
		end
		accept :nopreempt
		accept :preempt_delay
		accept :debug
		accept :notify_master, Apath
		accept :notify_backup, Apath
		accept :notify_fault, Apath
		accept :notify_stop, Apath
		accept :notify, Apath
		accept :smtp_alert
	end

	block :static_route do
		try_accept :src, Aip, Aipmask, :via, Aip, :dev, Anetif
		try_accept Aipmask, :via, Aip, :dev, Anetif
		try_accept Aipmask, :via, Aip
		try_accept Aipmask, :dev, Anetif
	end
end


module TestUtil
	def check(v, a)
		case a
		when Regexp
			a.match(v).to_s == v
		when Symbol
			a.to_s == v
		when String
			a == v
		when Proc
			a.call(v)
		when NilClass
			v.nil?
		else
		  false
		end
	end

	def match(vs, as)
		as.zip(vs).find {|a,v| !check(v,a) }.nil?
	end
end


class Conf
	def initialize(values, body)
		@values = values
		@body = body
		@body.conf = self if @body
	end
	attr_reader :values, :body

	def key;  values[0];     end
	def args; values[1..-1]; end

	def to_s(nest_char = '  ', nest = 0)
		if body
			"#{values.join(' ')} {\n#{body.to_s(nest_char, nest+1)}#{nest_char*nest}}\n"
		else
			"#{values.join(' ')}\n"
		end
	end

	def inspect
		if body
			"#{values.join(' ')} { #{body.inspect}} "
		else
			"#{values.join(' ')}; "
		end
	end

	include TestUtil
end


class Body < Array
	attr_accessor :conf

	def to_s(nest_char = '  ', nest = 0)
		map do |conf|
			"#{nest_char*nest}#{conf.to_s(nest_char, nest)}"
		end.join('')
	end

	def inspect
		map {|conf| conf.inspect }.join('')
	end

	include TestUtil

	def block(*args, &pr)
		reject! {|conf|
			if check(conf.key, args.first)  # keyがマッチ
				unless conf.values.length == args.length && match(conf.values, args)
					raise "\"#{conf.values.join(' ')}\" requires #{args.inspect}"
				end

				conf.body.instance_eval(&pr)
				unless conf.body.empty?
					keys = conf.body.map {|c| c.key.dump }
					raise "unknown keys #{keys.join(', ')} at #{conf.key}"
				end

				true
			end
		}
	end

	def try_block(*args, &pr)
		reject! {|conf|
			if conf.values.length == args.length && match(conf.values, args)
				conf.body.instance_eval(&pr)
				unless conf.body.empty?
					keys = conf.body.map {|c| c.key.dump }
					raise "unknown keys #{keys.join(', ')} at #{conf.key}"
				end
				true
			end
		}
	end

	def block_if(*args, &pr)
		reject! {|conf|
			if conf.body.instance_eval(&pr)
				unless conf.body.empty?
					keys = conf.body.map {|c| c.key.dump }
					raise "unknown keys #{keys.join(', ')} at #{conf.key}"
				end
				true
			end
		}
	end

	def accept(*args)
		reject! {|conf|
			if check(conf.key, args.first)  # keyがマッチ
				unless conf.values.length == args.length && match(conf.values, args)
					raise "\"#{conf.values.join(' ')}\" requires #{args.inspect}"
				end
				true
			end
		}
	end

	def accept_n(n, *args)
		x = 0
		reject! {|conf|
			if check(conf.key, args.first)  # keyがマッチ
				unless conf.values.length == args.length && match(conf.values, args)
					raise "\"#{conf.values.join(' ')}\" requires #{args.inspect}"
				end
				if x >= n
					raise "\"#{conf.values.join(' ')}\" must be #{n} lines or less"
				end
				x += 1
				true
			end
		}
	end

	def accept_one(*args)
		accept_n(1, *args)
	end

	def try_accept(*args)
		reject! {|conf|
			if conf.values.length == args.length && match(conf.values, args)
				true
			end
		}
	end

	def accept_if(&pr)
		reject! {|conf|
			conf.instance_eval(&pr)
		}
	end
end


module Root
	def check
		Body.new([self]).block(:root, &Accept)
	end

	def to_s
		body.map {|conf| conf.to_s } .join('')
	end

	def inspect
		body.map {|conf| conf.inspect } .join('')
	end
end


if $0 == __FILE__

require 'optparse'

op = OptionParser.new
op.on('-v', '--verbose', 'verbose mode') {|b| opt[:verbose] = b }
op.on('-e', '--extend',  'enable some extended syntaxes') {|b| opt[:extend]  = b }
op.banner += " <keepalived.conf>"

op.parse!(ARGV)

if ARGV.length != 1
	puts op.to_s
	exit 1
end

path = ARGV.shift
if path == "-"
	src = STDIN.read
else
	src = File.read(path)
end


begin
	cfg = parse(src)
	
	if opt[:verbose]
		puts cfg
		puts ""
	end

	cfg.check

	msg = "ok"

rescue Phraser::ScanError
	before = $!.src[0..$!.pos]
	after  = $!.src[$!.pos..10]
	line = before.count("\n")
	msg = "scan error at line #{line}: #{after}"
	exp = $!

rescue Phraser::ParseError
	msg = "parse error while parsing '#{$!.tokens.first}' (#{$!.to_s.sub(/\:.*/m,'')})"
	exp = $!

rescue
	msg = $!.to_s
	exp = $!
end

puts msg

if exp
	if opt[:verbose]
		puts ""
		raise exp
	else
		exit 1
	end
end


end   # if $0 == __FILE__
