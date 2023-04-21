# frozen_string_literal: true

require "minitest/autorun"
require "sm2_crypto"
require "base64"
require "securerandom"

class SM2CryptoTest < Minitest::Test
  SM2_PRIVATE_KEY = ["7DF1CBE97D602CDF2CD5005A102E95EC0F3B50045EFBAEA2E8364B47C33C585A"].pack("H*")
  SM2_PUBLIC_KEY = ["0456B6D322DA7114E7989927DC276D627530A6377F209D7F02C23C5DBB27173F1099667FBC95BF50172F03F45E01A83E293B32664FB425801888C84ABB7677975F"].pack("H*")

  SM2_DATA = "abc1234XYZ@%& 你好，世界！"
  SM2_ENCRYPTED_DATA = "BFTtp/3xFw25H/JV9KQ4z8U9GMoIpfWSoyuPtn387bSxWbp8zcjoxURo5pqZb55VzSrAypcmM32WqKjJLJRqUaj/JTG+7IhRm9wFkAbqIQTbMkB89/6AWYIM8zL72mQUGS9s6vQS2dewYsbuYWZzH512ipRY743zh52lIyMof/ik"

  def test_encrypt_and_decrypt
    encrypted_data = SM2Crypto.encrypt(SM2_PUBLIC_KEY, SM2_DATA)
    decrypted_data = SM2Crypto.decrypt(SM2_PRIVATE_KEY, encrypted_data)
    assert_equal SM2_DATA, decrypted_data.force_encoding("UTF-8")

    decrypted_data2 = SM2Crypto.decrypt(SM2_PRIVATE_KEY, ::Base64.decode64(SM2_ENCRYPTED_DATA))
    assert_equal SM2_DATA.bytes, decrypted_data2.bytes
  end

  def test_option_cipher_mode
    encrypted_data = SM2Crypto.encrypt(SM2_PUBLIC_KEY, SM2_DATA, cipher_mode: 0)
    decrypted_data = SM2Crypto.decrypt(SM2_PRIVATE_KEY, encrypted_data, cipher_mode: 0)
    assert_equal SM2_DATA, decrypted_data.force_encoding("UTF-8")
  end

  def test_encrypt_and_decrypt_long_data
    msg = SecureRandom.alphanumeric(rand(1000..10_000))
    encrypted_data = SM2Crypto.encrypt(SM2_PUBLIC_KEY, msg)
    decrypted_data = SM2Crypto.decrypt(SM2_PRIVATE_KEY, encrypted_data)
    assert_equal msg, decrypted_data
  end

  def test_encrypt_and_decrypt_with_padding
    # public_key not start with "\x04"
    public_key = ["56B6D322DA7114E7989927DC276D627530A6377F209D7F02C23C5DBB27173F1099667FBC95BF50172F03F45E01A83E293B32664FB425801888C84ABB7677975F"].pack("H*")
    encrypted_data = SM2Crypto.encrypt(public_key, SM2_DATA)
    decrypted_data = SM2Crypto.decrypt(SM2_PRIVATE_KEY, encrypted_data)
    assert_equal SM2_DATA, decrypted_data.force_encoding("UTF-8")

    # encrypted_data not start with "\x04"
    decrypted_data2 = SM2Crypto.decrypt(SM2_PRIVATE_KEY, encrypted_data[1, encrypted_data.size - 1])
    assert_equal SM2_DATA, decrypted_data2.force_encoding("UTF-8")
  end

  def test_generate_keypairs
    keypair = OpenSSL::PKey::EC.generate("SM2")
    private_key = keypair.private_key.to_s(2)
    public_key = keypair.public_key.to_octet_string(:uncompressed)

    msg = SecureRandom.random_bytes(rand(10..100))
    encrypted_data = SM2Crypto.encrypt(public_key, msg)
    decrypted_data = SM2Crypto.decrypt(private_key, encrypted_data)
    assert_equal msg, decrypted_data
  end

  def test_base64
    private_key = Base64.decode64("1F2NPo0cF9grhuBNIvH+9vpAC/itfBZjuE2uIYhmaFE=\n")
    msg = "abc"
    encrypted_data = "BKpGCI/L1mrP0iFDbmB/ykCWWUnrC+5OuXa7/nyFi86yz33NhVvR+JrPml1fLVISFNsMennZNCMZ4uN4mzngBMhldVQJwszbmYys3d5fZ+EJ7ZJXz1uWRKwE7on574SbTCc5zw=="
    decrypted_data = SM2Crypto.decrypt(private_key, Base64.decode64(encrypted_data))
    assert_equal msg, decrypted_data
  end

  def test_get_publick_key
    public_key = SM2Crypto.get_public_key(SM2_PRIVATE_KEY)
    assert_equal SM2_PUBLIC_KEY, public_key

    keypair = OpenSSL::PKey::EC.generate("SM2")
    private_key = keypair.private_key.to_s(2)
    public_key = keypair.public_key.to_bn.to_s(2)
    assert_equal public_key, SM2Crypto.get_public_key(private_key)
  end

  def test_sign_and_verify
    msg = "abc"
    sign = SM2Crypto.sign(SM2_PRIVATE_KEY, msg)
    assert_equal true, SM2Crypto.verify(SM2_PUBLIC_KEY, msg, sign)

    cjk_msg = "abc1234XYZ@%& 你好，世界！#{SecureRandom.alphanumeric(rand(1000..10_000))}"
    sign2 = SM2Crypto.sign(SM2_PRIVATE_KEY, cjk_msg)
    assert_equal true, SM2Crypto.verify(SM2_PUBLIC_KEY, cjk_msg, sign2)
  end

  def test_sign_and_verify_with_hash
    msg = "abc"
    user_id = "313233343536373831323334353637AA"
    sign = SM2Crypto.sign(SM2_PRIVATE_KEY, msg, sm3_hash: true, user_id: user_id)
    assert_equal true, SM2Crypto.verify(SM2_PUBLIC_KEY, msg, sign, sm3_hash: true, user_id: user_id)

    cjk_msg = "abc1234XYZ@%& 你好，世界！#{SecureRandom.alphanumeric(rand(1000..10_000))}"
    sign2 = SM2Crypto.sign(SM2_PRIVATE_KEY, cjk_msg, sm3_hash: true)
    assert_equal true, SM2Crypto.verify(SM2_PUBLIC_KEY, cjk_msg, sign2, sm3_hash: true)
  end
end
