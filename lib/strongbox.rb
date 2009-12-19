require 'openssl'
require 'base64'

require 'strongbox/lock'

module Strongbox

  VERSION = "0.3.0"

  RSA_PKCS1_PADDING	= OpenSSL::PKey::RSA::PKCS1_PADDING
  RSA_SSLV23_PADDING	= OpenSSL::PKey::RSA::SSLV23_PADDING
  RSA_NO_PADDING		= OpenSSL::PKey::RSA::NO_PADDING
  RSA_PKCS1_OAEP_PADDING	= OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
  
  class << self
    # Provides for setting the default options for Strongbox
    def options
      @options ||= {
        :base64 => false,
        :symmetric => :always,
        :padding => RSA_PKCS1_PADDING,
        :encrypt_iv => true,
        :symmetric_cipher => 'aes-256-cbc'
      }
    end
    
    def included base #:nodoc:
      base.extend ClassMethods
    end
  end

  class StrongboxError < StandardError #:nodoc:
  end
  
  module ClassMethods
    # +encrypt_with_public_key+ gives the class it is called on an attribute that
    # when assigned is automatically encrypted using a public key.  This allows the
    # unattended encryption of data, without exposing the information need to decrypt
    # it (as would be the case when using symmetric key encryption alone).  Small
    # amounts of data may be encrypted directly with the public key.  Larger data is
    # encrypted using symmetric encryption. The encrypted data is stored in the
    # database column of the same name as the attibute.  If symmetric encryption is
    # used (the default) additional column are need to store the generated password
    # and IV.
    def encrypt_with_public_key(name, options = {})
      strongbox_encryption( name, options )
    end

    def encrypt_with_symmetric_key( name, options = {})
      options.merge!( :symmetric => :only )
      strongbox_encryption( name, options )
    end

    def strongbox_encryption( name, options )
      include InstanceMethods

      class_inheritable_reader :lock_options
      write_inheritable_attribute(:lock_options, {}) if lock_options.nil?


      lock_options[name] = options.symbolize_keys.reverse_merge Strongbox.options
          
      define_method name do
        lock_for(name)
      end
      
      define_method "#{name}=" do | plaintext |
        lock_for(name).encrypt plaintext
      end
      
    end
  end
  
  module InstanceMethods
    def lock_for name
      @_locks ||= {}
      @_locks[name] ||= Lock.new(name, self, self.class.lock_options[name])
    end
  end
end

if Object.const_defined?("ActiveRecord")
  ActiveRecord::Base.send(:include, Strongbox)
end

