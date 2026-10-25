require 'json'

module Binary
	module Reader
		def u8
			@data.getbyte(@pos).tap { @pos += 1 }
		end

		def u16
			bytes(2).unpack1 ?v
		end

		def u32
			bytes(4).unpack1 ?V
		end

		def array &block
			Array.new u8, &block
		end

		def bytes n
			@data[@pos...@pos += n]
		end

		def string
			var_bytes.force_encoding 'UTF-8'
		end

		def var_bytes
			n = u8
			n = u16 if n == 0xff
			n = u32 if n == 0xffff
			bytes n
		end

		def rest
			bytes @data.bytesize - @pos
		end

		def must_end
			raise 'trailing bytes' unless @pos == @data.bytesize
		end

		def back_up_state
			(@stack ||= []).push State.new @data, @pos
		end

		State = Struct.new :data, :pos do
			def restore instance
				instance.instance_variable_set :@data, data
				instance.instance_variable_set :@pos, pos
				Reader.instance_methods.each { instance.define_singleton_method _1, Reader.instance_method(_1) }
			end
		end
	end

	module Writer
		def u8 v
			@data.concat [v].pack ?C
			self
		end

		def u16 v
			@data.concat [v].pack ?v
			self
		end

		def u32 v
			@data.concat [v].pack ?V
			self
		end

		def array v, &block
			raise 'array too long' if v.size > 0xff
			u8 v.size
			v.each &block
			self
		end

		def bytes v
			@data.concat v.b
			self
		end

		def string v
			var_bytes v.to_s
		end

		def var_bytes v
			if v.bytesize < 0xff
				u8 v.bytesize
			elsif v.bytesize < 0xffff
				u8 0xff
				u16 v.bytesize
			else
				u8 0xff
				u16 0xffff
				u32 v.bytesize
			end
			bytes v
		end

		def back_up_state
			(@stack ||= []).push State.new @data
		end

		State = Struct.new :data do
			def restore instance
				instance.instance_variable_set :@data, data
				Writer.instance_methods.each { instance.define_singleton_method _1, Writer.instance_method(_1) }
			end
		end
	end

	def read name = nil, &block
		define_method name ? :"read_#{name}" : :read do |data, *args|
			back_up_state if respond_to? :back_up_state
			Reader.instance_methods.each { define_singleton_method _1, Reader.instance_method(_1) } unless @stack&.last.is_a? Reader::State
			@data = data
			@pos = 0
			instance_exec *args, &block
			@stack&.pop&.restore self
			self
		end
	end

	def write name = nil, &block
		define_method name ? :"write_#{name}" : :write do |*args|
			back_up_state if respond_to? :back_up_state
			Writer.instance_methods.each { define_singleton_method _1, Writer.instance_method(_1) } unless @stack&.last.is_a? Writer::State
			@data = ''.b
			instance_exec *args, &block
			result = @data
			@stack&.pop&.restore self
			result
		end
	end
end

class Song
	extend Binary

	DIFF_NAMES = {
		1 => :easy,
		2 => :normal,
		8196 => :hard_phone,
		4100 => :hard_tablet,
		16 => :extra,
		8208 => :extra_phone,
		4112 => :extra_tablet,
	}.freeze
	DIFF_IDS = DIFF_NAMES.invert.freeze

	attr_accessor :title, :artist, :description, :categories, :tags
	attr_accessor :content_id, :secondary_id, :size_field
	attr_accessor :preview, :cover, :cover_blur
	attr_reader :charts, :musics, :metadata

	def initialize description = {}
		@description = description
		@charts = {}
		@musics = {}
		@metadata = {}
	end

	read :meta do
		@title = string
		@artist = string
		@flags = u8
		@version = string
		@categories = array { u8 }
		@tags = array { string }
		@content_id = u32
		@secondary_id = u32 if u8 != 0
		array { @charts[u32] = Chart.new u8 }
		@size_field = u32
		must_end
	end

	write :meta do
		string @title
		string @artist
		u8 @flags
		string @version
		array(@categories) { u8 _1 }
		array(@tags) { string _1 }
		u32 @content_id
		if @secondary_id
			u8 1
			u32 @secondary_id
		else
			u8 0
		end
		array @charts do |diff_id, chart|
			u32 diff_id
			u8 chart.diff
		end
		u32 @size_field
	end

	read :bmd do |public_key|
		raise 'not a BMD' unless u32 == 0x200
		signature = Signature.new.read Utils.rsa_decrypt bytes(512), public_key
		array { u32 } # diff ids
		array { [u8, u32] } # music sizes
		array { [u32, u32] } # variants
		read_container signature.decrypt bytes signature.payload_size
		# there are trailing bytes after here, seemingly trash
	end

	write :bmd do |private_key|
		u32 0x200
		signature = Signature.random
		payload = signature.encrypt write_container
		bytes Utils.rsa_encrypt signature.write, private_key
		array(@charts) { |diff_id, chart| u32 diff_id }
		array @musics do |variant_id, binary|
			u8 variant_id
			u32 binary.bytesize
		end
		array @charts.filter { _2.variant_id } do |diff_id, chart|
			u32 diff_id
			u32 chart.variant_id
		end
		bytes payload
	end

	read :container do
		array { [u32, u32, bytes(32)] }.each do |diff_id, length, key|
			@charts[diff_id].xml = Utils.aes_decrypt bytes(length), key
		end
		array { @charts[u32].tap { _1.variant_id, _1.version = u32, string } }
		music_headers = [u8, bytes(32)].then do |n, key|
			Array.new(n) { [u8, MusicHeader.new.read(Utils.aes_decrypt bytes(u16), key)] }.to_h
		end
		@metadata = music_headers.transform_values { string }
		@musics = music_headers.transform_values { _1.header + bytes(_1.body_size) }
		raise 'incorrect trailer' unless rest == ?\0
	end

	write :container do |music_header_length = 256|
		chart_keys = @charts.transform_values { RANDOM.random_bytes 32 }
		encrypted_charts = @charts.transform_values { [key = RANDOM.random_bytes(32), Utils.aes_encrypt(_1.xml, key)] }
		array encrypted_charts do |diff_id, (key, raw)|
			u32 diff_id
			u32 raw.bytesize
			bytes key
		end
		encrypted_charts.each { |diff_id, (key, raw)| bytes raw }
		array @charts.filter { _2.variant_id } do |diff_id, chart|
			u32 diff_id
			u32 chart.variant_id
			string chart.version
		end
		u8 @metadata.length
		key = RANDOM.random_bytes 32
		bytes key
		@musics.each do |variant_id, ogg|
			u8 variant_id
			payload = Utils.aes_encrypt MusicHeader.from_ogg(ogg, music_header_length).write, key
			u16 payload.bytesize
			bytes payload
		end
		@metadata.each { string _2 }
		@musics.each { bytes _2[music_header_length..] }
		bytes ?\0
	end

	def self.from_zip zip, entry_prefix, description, public_key
		new(description).instance_eval do
			id = File.basename entry_prefix
			read_meta Utils.zip_read! zip, File.join(entry_prefix, 'meta.dat')
			read_bmd Utils.zip_read!(zip, File.join(entry_prefix, "#{id}.bmd")), public_key
			@preview = Utils.zip_read zip, File.join(entry_prefix, "#{id}_p.ogg")
			@cover = Utils.zip_read zip, File.join(entry_prefix, "cover.png")
			@cover_blur = Utils.zip_read zip, File.join(entry_prefix, "cb.png")
			self
		end
	end

	def to_zip zip, entry_prefix, private_key
		id = File.basename entry_prefix
		Utils.zip_write! zip, File.join(entry_prefix, 'meta.dat'), write_meta
		Utils.zip_write! zip, File.join(entry_prefix, "#{id}.bmd"), write_bmd(private_key)
		Utils.zip_write! zip, File.join(entry_prefix, "#{id}_p.ogg"), @preview if @preview
		Utils.zip_write! zip, File.join(entry_prefix, "cover.png"), @cover if @cover
		Utils.zip_write! zip, File.join(entry_prefix, "cb.png"), @cover_blur if @cover_blur
	end

	def self.from_extracted dir
		Dir.chdir dir do
			meta = JSON.load_file 'meta.json', symbolize_names: true
			new(meta.fetch :description, {}).instance_eval do
				@title = meta.fetch :title, ''
				@artist = meta.fetch :artist, ''
				@flags = meta.fetch :flags, 0
				@version = meta.fetch :version, ''
				@categories = meta.fetch :categories, []
				@tags = meta.fetch :tags, []
				@content_id = meta.fetch :content_id, 0
				@secondary_id = meta[:secondary_id]
				meta.fetch(:charts, []).each do |diff_name, chart|
					@charts[DIFF_IDS.fetch(diff_name)] = Chart.new(chart.fetch :diff).tap do |c|
						c.xml = File.binread "#{diff_name}.xml"
						c.variant_id = chart[:variant_id]
						c.version = chart[:version]
					end
				end
				@size_field = meta.fetch :size_field, 0
				[0, *@charts.filter_map { _2.variant_id }].uniq.each do |variant_id|
					@musics[variant_id] = File.binread "music_#{variant_id}.ogg"
					@metadata[variant_id] = File.binread "metadata_#{variant_id}.xml"
				end
				@preview = File.binread 'preview.ogg' if File.file? 'preview.ogg'
				@cover = File.binread 'cover.png' if File.file? 'cover.png'
				@cover_blur = File.binread 'cover_blur.png' if File.file? 'cover_blur.png'
				self
			end
		end
	end

	def to_extracted dir
		FileUtils.mkdir_p dir
		Dir.chdir dir do
			File.write 'meta.json', JSON.pretty_generate(
				title: @title,
				artist: @artist,
				description: @description,
				flags: @flags,
				version: @version,
				categories: @categories,
				tags: @tags,
				content_id: @content_id,
				secondary_id: @secondary_id,
				charts: @charts.map { [DIFF_NAMES.fetch(_1), _2.to_h] }.to_h,
				size_field: @size_field,
			) + ?\n
			@charts.each { File.binwrite "#{DIFF_NAMES.fetch _1}.xml", _2.xml }
			@musics.each { File.binwrite "music_#{_1}.ogg", _2 }
			@metadata.each { File.binwrite "metadata_#{_1}.xml", _2 }
			File.binwrite 'preview.ogg', @preview if @preview
			File.binwrite 'cover.png', @cover if @cover
			File.binwrite 'cover_blur.png', @cover_blur if @cover_blur
		end
	end
end

class Chart
	attr_accessor :diff, :xml, :variant_id, :version

	def initialize diff
		@diff = diff
	end

	def to_h
		result = { diff: @diff }
		result.merge! variant_id: @variant_id, version: @version if @variant_id
		result
	end
end

class MusicHeader
	extend Binary

	attr_accessor :size, :header

	def body_size
		@size - @header.bytesize
	end

	def self.from_ogg ogg, length
		new.instance_eval do
			@size = ogg.bytesize
			@header = ogg[...length]
			self
		end
	end

	read do
		@size = u32
		@header = 'OggS'.b + rest
	end

	write do
		u32 @size
		bytes @header[4..]
	end
end

class Signature
	extend Binary

	SALT = (Utils.sha1('#77282_6654$MDD-PCL') * 2)[0, 32]
	HMAC_SUFFIX = '!!PHD_@SIG://_@BDL&'.b

	attr_accessor :seed, :hmac_prefix, :hmac, :payload_size, :iv

	def self.random
		new.instance_eval do
			@seed = RANDOM.random_bytes 32
			@hmac_prefix = RANDOM.random_bytes 16
			@iv = RANDOM.random_bytes 16
			self
		end
	end

	def key
		Utils.xor @seed, SALT
	end

	def hmac_from payload
		Utils.hmac @hmac_prefix + HMAC_SUFFIX, payload
	end

	def encrypt data
		Utils.aes_encrypt(data, key, @iv).tap do |payload|
			@hmac = hmac_from payload
			@payload_size = payload.bytesize
		end
	end

	def decrypt payload, check = true
		if check
			raise 'size mismatch' unless payload.bytesize == @payload_size
			raise 'hmac mismatch' unless hmac_from(payload) == @hmac
		end
		Utils.aes_decrypt payload, key, @iv
	end

	read do
		@seed = bytes 32
		@hmac_prefix = bytes 16
		@hmac = bytes 20
		@payload_size = u32
		@iv = bytes 16
	end

	write do
		bytes @seed
		bytes @hmac_prefix
		bytes @hmac
		u32 @payload_size
		bytes @iv
	end
end
