#
# Phraser: Simple lexer and parser combinator
#
# Copyright (c) 2008-2009 FURUHASHI Sadayuki
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

module Phraser


class ScanError  < StandardError
	def initialize(args)
		@src = args[0]
		@pos = args[1]
		super(args[2])
	end
	attr_reader :src, :pos
end

class ParseError < StandardError
	def initialize(args)
		@tokens = args[0]
		super(args[1])
	end
	attr_reader :tokens
end


class Scanner

	class Token
		def initialize(name, expr)
			@name = name
			@expr = expr
		end
		attr_reader :name, :expr
	end

	def initialize
		@tokens = []
	end

	def token(name, expr = nil)
		name = name.to_sym
		expr = /#{Regexp.escape(name.to_s)}/ unless expr
		@tokens.push Token.new(name, expr)
	end

	def scan(src)
		require 'strscan'
	
		result = []
	
		s = StringScanner.new(src)
		until s.empty?
			err = @tokens.each {|t|
				if m = s.scan(t.expr)
					pos = s.pos - m.length
					(class<<m; self; end).instance_eval {
						define_method(:token) { t.name }
						define_method(:inspect) { "\"#{m}\":#{t.name}" }
						define_method(:pos) { pos }
					}
					result.push(m)
					break nil
				end
			}
			raise ScanError, [src, s.pos, "error '#{s.peek(10)}'"] if err
		end
	
		result
	end
end


class Parser
	def initialize(&block)
		@block = block
		@action = Proc.new {|x,e| x }
		@name = nil
	end

	def action(&block)
		@action = block
		self
	end

	def [](name)
		@name = name
		self
	end

	def parse(i, e = {})
		r = @block[i, e]
		r[0] = @action.call(r[0], e)
		e[@name] = r[0] if @name
		r
	end

	def /(o)
		parser {|i,e|
			begin
				parse(i,e)
			rescue ParseError
				o.parse(i,e)
			end
		}
	end

	def ^(o)
		parser {|i,e|
			r1 = parse(i,e)
			r2 = o.parse(r1[1],e)
			[[r1[0], r2[0]], r2[1]]
		}
	end

	def apply(&rule)
		parser {|i,e|
			r = parse(i,e)
			[rule.call(r[0]), r[1]]
		}
	end

	def opt
		self / parser {|i,e| [nil, i] }
	end

	def *
		parser {|i,e|
			rs = []
			while true
				begin
					r = parse(i,e)
				rescue ParseError
					break
				end
				rs << r[0]
				i = r[1]
			end
			[rs, i]
		}
	end

	def +
		(self ^ self.*).apply {|i| i[1].unshift(i[0]) }
	end

	def not
		parser {|i,e|
			begin
				r = parse(i,e)
			rescue ParseError
			end
			raise ParseError, [i, "not error: #{i.inpsect}"] if r
			[nil, i]
		}
	end

	def and
		self.not.not
	end

	class Context
		def initialize(tmpl = nil)
			@tmpl = tmpl
		end
		attr_reader :tmpl

		def token(t, match = nil)
			parser {|i,e|
				unless i.first && i.first.token == t.to_sym && (match.nil? || i.first =~ match)
					raise ParseError, [i, "token error: #{i.inspect}"]
				end
				[i.first, i[1..-1]]
			}
		end
	
		def any
			parser {|i,e|
				unless i.length > 0
					raise ParseError, [i, "any error: #{i.inspect}"]
				end
				[i.first, i[1..-1]]
			}
		end

		def eof
			parser {|i,e|
				unless i.empty?
					raise ParseError, [i, "EOF error: #{i.inspect}"]
				end
				[nil, i]
			}
		end

		def parser(&block)
			Parser.new(&block)
		end
	end

	def parser(&block)
		Parser.new(&block)
	end
end

def rule(*arg_names, &block)
	if arg_names.empty?
		Parser.new {|i,e|
			Parser::Context.new.instance_eval(&block).parse(i)
		}
	else
		Proc.new {|*arg_values|
			tmpl = {}
			arg_names.zip(arg_values) {|k,v| tmpl[k] = v }
			Parser.new {|i,e|
				Parser::Context.new(tmpl).instance_eval(&block).parse(i)
			}
		}
	end
end


def self.parse(rule, src)
	rule.parse(src)[0]
end


end  # module Phraser

