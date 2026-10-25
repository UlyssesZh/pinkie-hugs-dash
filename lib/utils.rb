module Utils

	module_function

	def zip_read! zip, entry
		zip.get_entry(entry).get_input_stream.read
	end

	def zip_read zip, entry
		zip.find_entry(entry)&.get_input_stream&.read
	end

	def zip_write! zip, entry, data
		zip.put_next_entry entry
		zip.write data
	end

	def zip_write zip, entry, data
		zip.get_output_stream(entry) { _1.write data }
	end

	def xor a, b
		a.bytes.zip(b.bytes).map { _1 ^ _2 }.pack 'C*'
	end

	def md5 data
		OpenSSL::Digest::MD5.digest data
	end

	def sha1 data
		OpenSSL::Digest::SHA1.digest data
	end

	def hmac hmac_key, data
		OpenSSL::HMAC.digest 'SHA1', hmac_key, data
	end

	def aes_encrypt data, key, iv = md5(key)
		c = OpenSSL::Cipher.new 'aes-256-cbc'
		c.encrypt
		c.key = key
		c.iv = iv
		c.update(data) + c.final
	end

	def aes_decrypt data, key, iv = md5(key)
		c = OpenSSL::Cipher.new 'aes-256-cbc'
		c.decrypt
		c.key = key
		c.iv = iv
		c.update(data) + c.final
	end

	def rsa_decrypt data, public_key
		OpenSSL::PKey::RSA.new(public_key).public_decrypt data, OpenSSL::PKey::RSA::PKCS1_PADDING
	end

	def rsa_encrypt data, private_key
		OpenSSL::PKey::RSA.new(private_key).private_encrypt data, OpenSSL::PKey::RSA::PKCS1_PADDING
	end

	def rsa_public_key private_key
		OpenSSL::PKey::RSA.new(private_key).public_key.to_pem
	end

	module TimeReproducible
		Zip::DOSTime.singleton_class.prepend self
		def now
			at 0, in: 0
		end
	end
end
