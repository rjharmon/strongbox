module Strongbox
  # The Lock class encrypts and decrypts the protected attribute.  It 
  # automatically encrypts the data when set and decrypts it when the private
  # key password is provided.
  class Lock
      
    def initialize name, instance, options = {}
      @name              = name
      @instance          = instance
      
      @size = nil
      
      options = Strongbox.options.merge(options)
      
      @is_empty = true if @instance[@name].blank?
      
      @base64 = options[:base64]
      @public_key = options[:public_key] || options[:key_pair]
      @private_key = options[:private_key] || options[:key_pair]
      @padding = options[:padding]
      @symmetric = options[:symmetric]
      @symmetric_cipher = options[:symmetric_cipher]
      @symmetric_key = options[:symmetric_key] || "#{name}_key"
      @symmetric_iv = options[:symmetric_iv] || "#{name}_iv"
      @key_proc = options[:key_proc]
      @encrypt_iv = options[:encrypt_iv]
      if @symmetric == :only
        if @encrypt_iv
          raise ArgumentError, ":encrypt_iv should be set to false for :symmetric => :only encryption, since encrypting the iv requires a pubkey"
        end
        if @public_key
          raise ArgumentError, ":public_key, :private_key and :key_pair are not used with :symmetric => :only"
        end
        unless @key_proc
          raise ArgumentError, ":key_proc option is required.  This option specifies a proc or a symbol of a method on the instance, which will return a key used for the symmetric cypher."
        end
      else
        if @key_proc
          raise ArgumentError, ":key_proc is valid only when :symmetric => :only is specified, or when using encrypt_with_symmetric_key()"
        end
      end
    end
    
    def encrypt plaintext
      
      unless @public_key or @symmetric == :only
        raise StrongboxError.new("#{@instance.class} model does not have public key_file")
      end
      if !plaintext.blank?
        @is_empty = false
        @size = plaintext.size # For validations
        # Using a blank password in OpenSSL::PKey::RSA.new prevents reading
        # the private key if the file is a key pair
        public_key = get_rsa_key(@public_key,"")
        if @symmetric == :always or @symmetric == :only
          cipher = OpenSSL::Cipher::Cipher.new(@symmetric_cipher)
          cipher.encrypt
          
          cipher.key = symmetric_key = case @key_proc
          when Proc
            @key_proc.call( @instance )
          when Symbol
            @instance.send( @key_proc )
          else
            cipher.random_key
          end
          cipher.iv = symmetric_iv = cipher.random_iv

          ciphertext = cipher.update(plaintext)
          ciphertext << cipher.final
          unless @symmetric == :only
            encrypted_key = public_key.public_encrypt(symmetric_key,@padding)
          end
          if @encrypt_iv
            encrypted_iv = public_key.public_encrypt(symmetric_iv,@padding)
          end
          if @base64
            unless @symmetric == :only
              encrypted_key = Base64.encode64(encrypted_key)
            end
            encrypted_iv = Base64.encode64(encrypted_iv)
          end
          unless @symmetric == :only
            @instance[@symmetric_key] = encrypted_key
          end
          if @encrypt_iv
            @instance[@symmetric_iv] = encrypted_iv
          else
            @instance[@symmetric_iv] = symmetric_iv
          end
        else
          ciphertext = public_key.public_encrypt(plaintext,@padding)
        end
        ciphertext =  Base64.encode64(ciphertext) if @base64
        @instance[@name] = ciphertext
      else
        @size = 0
        @instance[@name] = ""
        @is_empty = true
      end
    end
    
    # Given the private key password decrypts the attribute.  Will raise
    # OpenSSL::PKey::RSAError if the password is wrong.
    
    def decrypt password = nil
      return "" if @is_empty
      # Given a private key and a nil password OpenSSL::PKey::RSA.new() will
      # *prompt* for a password, we default to an empty string to avoid that.
      ciphertext = @instance[@name]
      return nil if ciphertext.nil?
      return "" if ciphertext.empty?
      
      return "*encrypted*" if password.nil? and ! @key_proc
      unless @private_key or @symmetric == :only
        raise StrongboxError.new("#{@instance.class} model does not have private key_file")
      end
      
      if ciphertext
        ciphertext = Base64.decode64(ciphertext) if @base64
        private_key = get_rsa_key(@private_key,password)
        
        if @symmetric == :always || @symmetric == :only
          symmetric_key = case @key_proc
          when Proc
            @key_proc.call( @instance )
          when Symbol
            @instance.send( @key_proc )
          else
            @instance[@symmetric_key]
          end
          symmetric_iv = @instance[@symmetric_iv]
          
          if @base64
            if @symmetric == :always
              symmetric_key = Base64.decode64(symmetric_key)
            end
            symmetric_iv = Base64.decode64(symmetric_iv)
          end
          cipher = OpenSSL::Cipher::Cipher.new(@symmetric_cipher)
          cipher.decrypt
          cipher.key = if @symmetric == :only
            symmetric_key
          else
            private_key.private_decrypt(symmetric_key,@padding)
          end
          if @encrypt_iv
            cipher.iv = private_key.private_decrypt(symmetric_iv,@padding)
          else
            cipher.iv = symmetric_iv
          end
          
          plaintext = cipher.update(ciphertext)
          plaintext << cipher.final
        else
          plaintext = private_key.private_decrypt(ciphertext,@padding)
        end
      else
        nil
      end
    end
    
    def to_s
      decrypt
    end
    
    # Needed for validations
    def blank?
      @instance[@name].blank?
    end
    
    def nil?
      @instance[@name].nil?
    end
    
    def size
      @size
    end

private
    def get_rsa_key(key,password = '')
      return nil unless key
      return key if key.is_a?(OpenSSL::PKey::RSA)
      if key !~ /^-----BEGIN RSA/
        key = File.read(key)
      end
      return OpenSSL::PKey::RSA.new(key,password)
    end
  end
end
