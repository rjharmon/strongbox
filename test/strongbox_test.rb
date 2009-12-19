# -*- coding: utf-8 -*-
require 'test/test_helper'

class StrongboxTest < Test::Unit::TestCase
  context 'A Class with a secured field' do
    setup do
      @password = 'boost facile'
      rebuild_model :key_pair => File.join(FIXTURES_DIR,'keypair.pem')
    end

    should 'not error when trying to also create a secure field' do
      assert_nothing_raised do
        Dummy.class_eval do
          encrypt_with_public_key :secret
        end
      end
    end
     
     context 'that is valid' do
       setup do
         @dummy = Dummy.new
         @dummy.secret = 'Shhhh'
         @dummy.in_the_clear = 'Hey you guys!'
       end
       
       should 'not change unencrypted fields' do
         assert_equal 'Hey you guys!', @dummy.in_the_clear
       end
       
       should 'return "*encrypted*" when locked'  do
         assert_equal '*encrypted*', @dummy.secret.decrypt
       end
       
       should 'return secret when unlocked'  do
         assert_equal 'Shhhh', @dummy.secret.decrypt(@password)
       end
       
       should 'generate and store symmetric encryption key and IV' do
         assert_not_nil @dummy.attributes['secret_key']
         assert_not_nil @dummy.attributes['secret_iv']
       end
       
       should 'raise on bad password' do
         assert_raises(OpenSSL::PKey::RSAError) do
           @dummy.secret.decrypt('letmein')
         end
       end

       context 'updating unencrypted fields' do
         setup do
           @dummy.in_the_clear = 'I see you...'
           @dummy.save
         end
         
         should 'not effect the secret' do
           assert_equal 'Shhhh', @dummy.secret.decrypt(@password)
         end
       end
       
       context 'updating the secret' do
         setup do
           @dummy.secret = @new_secret = 'Don\'t tell'
           @dummy.save
         end

         should 'update the secret' do
           assert_equal @new_secret, @dummy.secret.decrypt(@password)
         end
       end
           
       context 'with symmetric encryption disabled' do
         setup do
           rebuild_class(:key_pair => File.join(FIXTURES_DIR,'keypair.pem'),
                         :symmetric => :never)
           @dummy = Dummy.new
           @dummy.secret = 'Shhhh'
         end
         
         should 'return "*encrypted*" when locked'  do
           assert_equal '*encrypted*', @dummy.secret.decrypt
         end
         
         should 'return secret when unlocked'  do
           assert_equal 'Shhhh', @dummy.secret.decrypt(@password)
         end
         
         should 'not generate and store symmetric encryption key and IV' do
           assert_nil @dummy.attributes['secret_key']
           assert_nil @dummy.attributes['secret_iv']
         end

       end
       
       context 'with Base64 encoding enabled' do
         setup do
           rebuild_class(:key_pair => File.join(FIXTURES_DIR,'keypair.pem'),
                         :base64 => true)
           @dummy = Dummy.new
           @dummy.secret = 'Shhhh'
         end
       
         should 'Base64 encode the ciphertext' do
           # Base64 encoded text is limited to the charaters A–Z, a–z, and 0–9,
           # and is padded with 0 to 2 equal-signs
           assert_match /^[0-9A-Za-z+\/]+={0,2}$/, @dummy.attributes['secret']
           assert_match /^[0-9A-Za-z+\/]+={0,2}$/, @dummy.attributes['secret_key']
           assert_match /^[0-9A-Za-z+\/]+={0,2}$/, @dummy.attributes['secret_iv']
         end
         
         should 'encrypt the data'  do
           assert_not_equal @dummy.attributes['secret'], 'Shhhh'
           assert_equal '*encrypted*', @dummy.secret.decrypt
           assert_equal 'Shhhh', @dummy.secret.decrypt(@password)
         end
       end
     end
     
     context 'using blowfish cipher instead of AES' do
       setup do
         rebuild_class(:key_pair => File.join(FIXTURES_DIR,'keypair.pem'),
                       :symmetric_cipher => 'bf-cbc')
         @dummy = Dummy.new
         @dummy.secret = 'Shhhh'
       end
       
       should 'encrypt the data'  do
         assert_not_equal @dummy.attributes['secret'], 'Shhhh'
         assert_equal '*encrypted*', @dummy.secret.decrypt
         assert_equal 'Shhhh', @dummy.secret.decrypt(@password)
       end
     end
  end

  context 'when a public key is not provided' do
    setup do
      rebuild_class
      @dummy = Dummy.new
    end

    should 'raise on encrypt' do
      assert_raises(Strongbox::StrongboxError) do
        @dummy.secret = 'Shhhh'
      end
    end
  end
  
  context 'when a private key is not provided' do
     setup do
      @password = 'boost facile'
      rebuild_class(:public_key => File.join(FIXTURES_DIR,'keypair.pem'))
      @dummy = Dummy.new(:secret => 'Shhhh')
     end
      
    should 'raise on decrypt with a password' do
      assert_raises(Strongbox::StrongboxError) do
        @dummy.secret.decrypt(@password)
      end
    end
    
    should 'return "*encrypted*" when still locked' do
      assert_equal '*encrypted*', @dummy.secret.decrypt
    end
  end

  context "when an unencrypted public key is used" do
     setup do
      rebuild_class(:public_key => generate_key_pair.public_key)
      @dummy = Dummy.new(:secret => 'Shhhh')
     end

    should "encrypt the data"  do
      assert_not_equal @dummy.attributes['secret'], 'Shhhh'
      assert_equal '*encrypted*', @dummy.secret.decrypt
    end
  end

  context "when an unencrypted key pair is used" do
    setup do
      rebuild_class(:key_pair => generate_key_pair)
      @dummy = Dummy.new(:secret => 'Shhhh')
    end

    should "encrypt the data"  do
      assert_not_equal @dummy.attributes['secret'], 'Shhhh'
      assert_equal "Shhhh", @dummy.secret.decrypt('')
    end

    context "and we set the field to empty" do
      setup do
        @dummy.secret = "something"
        @dummy.secret = ""
      end
      should "clear the field" do
        assert_equal '', @dummy.secret.decrypt()
        assert_equal '', @dummy[:secret]
        assert_equal '', @dummy.secret.decrypt('')
      end
      should "unclear the field if we set it back to something" do
        @dummy.secret = "something"
        assert_equal '*encrypted*', @dummy.secret.decrypt()
        assert_equal 'something', @dummy.secret.decrypt('')
      end
    end
  end
  
  context 'with validations' do
    context 'using validates_presence_of' do
      setup do
        rebuild_class(:key_pair => File.join(FIXTURES_DIR,'keypair.pem'))
        Dummy.send(:validates_presence_of, :secret)
        @valid = Dummy.new(:secret => 'Shhhh')
        @invalid = Dummy.new(:secret => nil)
      end
      
      should 'not have an error on the secret when valid' do
        assert @valid.valid?
        assert_nil @valid.errors.on(:secret)
      end
      
      should 'have an error on the secret when invalid' do
        assert !@invalid.valid?
        assert @invalid.errors.on(:secret)
      end
      
      should 'be invalid on update if the field is changed to empty' do
        @valid.save
        @invalid = @valid.reload
        @invalid.secret = ""
        assert ! @invalid.valid?
      end
    end
    
    context 'using validates_length_of' do
      setup do
        rebuild_class(:key_pair => File.join(FIXTURES_DIR,'keypair.pem'))
        Dummy.send(:validates_length_of,
                   :secret,
                   :in => 5..10,
                   :allow_nil => true,
                   :allow_blank => true
                   )
        @valid = Dummy.new(:secret => 'Shhhh')
        @valid_nil = Dummy.new(:secret => nil)
        @valid_blank = Dummy.new(:secret => '')
        @invalid = Dummy.new(:secret => '1')
      end
      
      should 'not have an error on the secret when in range' do
        assert @valid.valid?
        assert_nil @valid.errors.on(:secret)
      end
      
      should 'not have an error on the secret when nil' do
        assert @valid_nil.valid?
        assert_nil @valid_nil.errors.on(:secret)
      end
      
      should 'not have an error on the secret when blank' do
        assert @valid_blank.valid?
        assert_nil @valid_blank.errors.on(:secret)
      end
      
      should 'have an error on the secret when invalid' do
        assert !@invalid.valid?
        assert @invalid.errors.on(:secret)
      end
    end
  end

  context 'A Class with two secured fields' do
    setup do
      @password = 'boost facile'
      key_pair = File.join(FIXTURES_DIR,'keypair.pem')
      Dummy.class_eval do
        encrypt_with_public_key :secret, :key_pair => key_pair
        encrypt_with_public_key :segreto, :key_pair => key_pair
      end
    end

    context 'that is valid' do
      setup do
        @dummy = Dummy.new
        @dummy.secret = 'I have a secret...'
        @dummy.segreto = 'Ho un segreto...'
      end
       
      should 'return "*encrypted*" when the record is locked'  do
        assert_equal '*encrypted*', @dummy.secret.decrypt
        assert_equal '*encrypted*', @dummy.segreto.decrypt
      end

       should 'return the secrets when unlocked'  do
         assert_equal 'I have a secret...', @dummy.secret.decrypt(@password)
         assert_equal 'Ho un segreto...', @dummy.segreto.decrypt(@password)
       end

    end
  end

  context 'A class without symmetric-only encryption field' do
    should "not allow key_proc" do
      assert_raises ArgumentError do
        Dummy.class_eval do
          def foobar
            'Fake symmetric key'
          end
          encrypt_with_public_key :secret, :key_proc => :foobar, :key_pair => File.join(FIXTURES_DIR,'keypair.pem')
        end
        Dummy.new.secret = "value"
      end      
    end
  end
  
  context 'A class with symmetric-only encryption field' do
    should "require key_proc" do
      assert_raises ArgumentError do
        Dummy.class_eval do
          encrypt_with_symmetric_key :secret
        end
        Dummy.new.secret = "value"
      end      
    end
    should "not allow :key_pair" do
      assert_raises ArgumentError do
        Dummy.class_eval do
          encrypt_with_symmetric_key :secret, :key_pair => true
        end
        Dummy.new.secret = "value"
      end      
    end
    should "not allow :private_key" do
      assert_raises ArgumentError do
        Dummy.class_eval do
          encrypt_with_symmetric_key :secret, :private_key => true
        end
        Dummy.new.secret = "value"
      end      
    end
    should "not allow :public_key" do
      assert_raises ArgumentError do
        Dummy.class_eval do
          encrypt_with_symmetric_key :secret, :public_key => true
        end
        Dummy.new.secret = "value"
      end      
    end
    should "require false :encrypt_iv" do
      assert_raises ArgumentError do
        Dummy.class_eval do
          encrypt_with_symmetric_key :secret, :encrypt_iv => true
        end
        Dummy.new.secret = "value"
      end      
    end
  
    context "after successful setup" do
      setup do
        Dummy.class_eval do
          def return_a_key
            'this is my symmetric key, in an over-simplified key-returning function'
          end
          encrypt_with_symmetric_key :secret, :key_proc => :return_a_key, :encrypt_iv => false
        end
        @dummy = Dummy.new
      end
      should "store the iv" do
        @dummy.secret = "some value"
        assert @dummy.secret_iv
      end
      should "decrypt the data" do
        expected = 'secret data'
        @dummy.secret = expected
        assert_equal expected, @dummy.secret.decrypt()
      end
    end
  end
end

