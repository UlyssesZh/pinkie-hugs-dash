#!/usr/bin/env ruby

require 'fileutils'
require 'optparse'
require 'rexml/document'
require 'tqdm'
require 'openssl'
require 'zip'

require_relative 'lib/utils'
require_relative 'lib/binary'

SO = 'lib/arm64-v8a/libleggieroapp_android.so'
BEGIN_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----'
END_PUBLIC_KEY = '-----END PUBLIC KEY-----'

def keygen private_key:, public_key:
	key = OpenSSL::PKey::RSA.generate 4096
	File.write private_key, key.to_pem
	File.chmod 0o600, private_key
	File.write public_key, key.public_key.to_pem
	puts "private key: #{private_key}"
	puts "public key:  #{public_key} (#{File.size(public_key)} bytes)"
end

def extract apk:, obb:, songs:
	apk = File.expand_path apk
	obb = File.expand_path obb
	out = File.expand_path songs
	FileUtils.rm_rf out if File.directory? out
	FileUtils.mkdir_p out

	public_key, descriptions = nil
	Zip::File.open apk do |zip|
		# deleted songs
		File.binwrite File.join(out, 'DeletedSongs.xml'), Utils.zip_read!(zip, 'assets/Songs/DeletedSongs.xml')
		# bundled songs
		bundled_songs = Utils.zip_read! zip, 'assets/Songs/BundledSongs.xml'
		ids = REXML::Document.new(bundled_songs).elements.to_enum(:each, 'Songs/Song').to_h { [_1.attributes['serial'].to_i, _1.attributes['id']] }
		File.binwrite File.join(out, 'BundledSongs.xml'), bundled_songs
		# public key
		public_key = Utils.zip_read!(zip, SO)[/#{BEGIN_PUBLIC_KEY}.*?#{END_PUBLIC_KEY}/m]
		# descriptions
		locales = REXML::Document.new(Utils.zip_read!(zip, 'assets/Locales/BundledLocales.xml')).elements.to_enum(:each, 'Locales/Locale').to_h do |e|
			key = e.attributes['value']
			[key.to_sym, Utils.zip_read!(zip, "assets/Locales/#{key}/string.#{key}.dat").lines(chomp: true).to_h { _1.split ?\t, 2 }]
		end
		descriptions = locales.each_with_object({}) do |(locale, strings), h|
			strings.each do |string_id, string|
				next unless serial = string_id[/^Song\.Desc\.(\d+)$/, 1]
				(h[ids[serial.to_i]] ||= {})[locale] = string.force_encoding 'UTF-8'
			end
		end
	end

	[[apk, 'assets/Songs'], [obb, 'Songs']].each_with_object Set.new do |(file, prefix), extracted_ids|
		Zip::File.open file do |zip|
			zip.entries.each do |entry|
				next unless id = entry.name[%r{^#{prefix}/([^/]+)/}, 1]
				next if id == 'Tutorial' || extracted_ids.include?(id)
				Song.from_zip(zip, "#{prefix}/#{id}", descriptions[id], public_key).to_extracted File.join out, id
				extracted_ids.add id
			end
		end
	end.tap { puts "extracted #{_1.size} songs to #{out}" }
end

def pack songs:, apk:, obb:, out_apk:, out_obb:, private_key:, ks: nil, ks_pass: '', key_pass: '', ks_key_alias: 'key0'
	dir = File.expand_path songs
	apk = File.expand_path apk
	obb = File.expand_path obb
	out_apk = File.expand_path out_apk
	out_obb = File.expand_path out_obb
	private_key = File.read File.expand_path private_key
	ks = File.expand_path ks if ks
	bundled_songs = File.read File.join dir, 'BundledSongs.xml'
	serials = REXML::Document.new(bundled_songs).elements.to_enum(:each, 'Songs/Song').to_h { [_1.attributes['id'], _1.attributes['serial'].to_i] }

	descriptions = {}
	Zip::OutputStream.open out_obb do |zip|
		serials.keys.with_progress.each do |id|
			song = Song.from_extracted File.join dir, id
			descriptions[id] = song.description
			song.to_zip zip, "Songs/#{id}", private_key
		end
	end
	puts "packed #{serials.size} songs to #{out_obb}"

	FileUtils.cp apk, out_apk
	Zip::File.open out_apk do |zip|
		# replace song list
		Utils.zip_write zip, 'assets/Songs/BundledSongs.xml', bundled_songs
		Utils.zip_write zip, 'assets/Songs/DeletedSongs.xml', File.binread(File.join dir, 'DeletedSongs.xml')
		# replace public key
		so = Utils.zip_read zip, SO
		start = so.index BEGIN_PUBLIC_KEY
		stop = so.index(END_PUBLIC_KEY, start) + END_PUBLIC_KEY.length
		pem = Utils.rsa_public_key(private_key).strip
		abort "public key too long: #{pem.length} bytes (max #{stop - start})" if pem.length > stop - start
		so[start...stop] = pem + ?\0 * (stop - start - pem.length)
		Utils.zip_write zip, SO, so
		# delete original songs
		zip.filter { _1.name[%r{^assets/Songs/([^/]+)/}, 1]&.!= 'Tutorial' }.each { zip.remove _1 }
		# replace descriptions
		locales = REXML::Document.new(Utils.zip_read! zip, 'assets/Locales/BundledLocales.xml').elements.to_enum(:each, 'Locales/Locale').to_h do |e|
			key = e.attributes['value']
			strings = Utils.zip_read!(zip, "assets/Locales/#{key}/string.#{key}.dat").force_encoding('UTF-8').lines(chomp: true).to_h { _1.split ?\t, 2 }
			[key.to_sym, strings.filter { |string_id, string| !string_id[/^Song\.Desc\.(\d+)$/] }]
		end
		descriptions.each { |id, description| locales.each { _2["Song.Desc.#{serials[id]}"] = description.fetch _1, '' } }
		locales.each { |locale, strings| Utils.zip_write zip, "assets/Locales/#{locale}/string.#{locale}.dat", strings.map { "#{_1}\t#{_2}\n" }.join }
	end
	puts "updated #{out_apk}"

	return unless ks
	zipalign = find_executable 'zipalign'
	apksigner = find_executable 'apksigner'
	if zipalign
		system zipalign, *%W[-f -P 16 4 #{out_apk} #{out_apk}.unsigned], exception: true
	else
		FileUtils.mv out_apk, "#{out_apk}.unsigned"
	end
	system apksigner, *%W[
		sign
		--ks #{ks}
		--ks-key-alias #{ks_key_alias}
		--ks-pass #{ks_pass}
		--key-pass #{key_pass}
		--out #{out_apk}
		#{out_apk}.unsigned
	], exception: true
	FileUtils.rm_f "#{out_apk}.unsigned"
	puts "signed #{out_apk}"
end

def lobby song:, blur_scale: 0.25, blur_radius: 1.65, preview_start: 30, preview_duration: 20, preview_fadeout: 2, no_blur: false, no_preview: false
	dir = File.expand_path song
	unless no_blur
		cover = File.join dir, 'cover.png'
		out = File.join dir, 'cover_blur.png'
		Vips::Image.new_from_file(cover).resize(blur_scale).gaussblur(blur_radius).write_to_file out
		puts "generated #{out}"
	end
	unless no_preview
		music = File.join dir, 'music_0.ogg'
		audio = Wavify::Audio.read music
		preview = audio.crop start: preview_start, duration: preview_duration
		out = File.join dir, 'preview.ogg'
		preview.fade_out(preview_fadeout).write out
		puts "generated #{out}"
	end
end

Zip.warn_invalid_date = false
Zip.write_zip64_support = false # ZIP64 not supported by zipalign

cmd = ARGV.shift
opts = {}
case cmd
when 'extract'
	OptionParser.new do |o|
		o.on '-h', '--help' do
			puts o
			exit
		end
		o.on '--apk PATH'
		o.on '--obb PATH'
		o.on '--songs PATH'
	end.parse! into: opts
	extract **opts

when 'pack'
	OptionParser.new do |o|
		o.on '-h', '--help' do
			puts o
			exit
		end
		o.on '--apk PATH'
		o.on '--obb PATH'
		o.on '--songs PATH'
		o.on '--out-apk PATH'
		o.on '--out-obb PATH'
		o.on '--private-key PATH'
		o.on '--ks PATH'
		o.on '--ks-pass PASS'
		o.on '--key-pass PASS'
		o.on '--ks-key-alias NAME'
		o.on '--seed N', Integer
	end.parse! into: opts
	require 'mkmf' if opts[:ks]
	if opts[:seed]
		require 'random/formatter'
		RANDOM = Random.new opts[:seed]
		opts.delete :seed
	else
		require 'securerandom'
		RANDOM = SecureRandom
	end
	pack **opts.transform_keys { _1.to_s.tr(?-, ?_).to_sym }

when 'keygen'
	OptionParser.new do |o|
		o.on '-h', '--help' do
			puts o
			exit
		end
		o.on '--private-key PATH'
		o.on '--public-key PATH'
	end.parse! into: opts
	keygen **opts.transform_keys { _1.to_s.tr(?-, ?_).to_sym }

when 'lobby'
	OptionParser.new do |o|
		o.on '-h', '--help' do
			puts o
			exit
		end
		o.on '--song PATH'
		o.on '--blur-scale FACTOR', Float
		o.on '--blur-radius RADIUS', Float
		o.on '--preview-start SECONDS', Float
		o.on '--preview-duration SECONDS', Float
		o.on '--preview-fadeout SECONDS', Float
		o.on '--no-blur'
		o.on '--no-preview'
        end.parse! into: opts
        require 'vips' unless opts[:'no-blur']
        require 'wavify' unless opts[:'no-preview']
        lobby **opts.transform_keys { _1.to_s.tr(?-, ?_).to_sym }

else
	abort "usage: #{__FILE__} extract|pack|keygen|lobby ..."
end
