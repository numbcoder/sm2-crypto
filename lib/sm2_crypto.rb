# frozen_string_literal: true
require "openssl"

module SM2Crypto
  module_function

  # Key Derived Function
  #
  # @param key [String] key data
  # @param klen [Integer] export key length
  # @return [Array<Integer>] bytes array
  def kdf(key, klen)
    # hlen = 32 # 哈希函数 SM3 输出长度 32 字节
    n = (klen.to_f / 32).ceil # n = klen/hlen 向上取整

    (1..n).map do |ct|
      OpenSSL::Digest.digest("SM3", key + [ct].pack("N"))
    end.join.slice(0, klen).bytes
  end

  # Encrypt
  #
  # @param public_key [String] public key, format: binary string
  # @param data [String] data
  # @param cipher_mode [Integer] 0: C1C2C3, 1: C1C3C2, default: 1
  # @return [String] encrypted data, format: binary string
  def encrypt(public_key, data, cipher_mode: 1)
    data = data.unpack1("a*") unless data.ascii_only?
    public_key = "\x04#{public_key}" if public_key.size == 64 && public_key[0] != "\x04"

    point = OpenSSL::PKey::EC::Point.new(OpenSSL::PKey::EC::Group.new("SM2"), OpenSSL::BN.new(public_key, 2))
    random_key = OpenSSL::PKey::EC.generate("SM2")
    k = random_key.private_key
    c1 = random_key.public_key.to_bn.to_s(2)

    p = point.mul(k)
    p_bin_str = p.to_bn.to_s(2)
    x2 = p_bin_str[1, 32]
    y2 = p_bin_str[33, 32]

    t = kdf(x2 + y2, data.bytesize)
    while t[0, 8].uniq == [0] && t.uniq == [0] do
      t = kdf(x2 + y2, data.bytesize)
    end

    c2 = data.each_byte.map.with_index { |b, i| b ^ t[i] }.pack("C*")

    # c3 = hash(x2 || msg || y2)
    c3 = OpenSSL::Digest.digest("SM3", x2 + data + y2)

    cipher_mode == 0 ? c1 + c2 + c3 : c1 + c3 + c2
  end

  # Decrypt
  #
  # @param private_key [String] private key, format: binary string
  # @param data [String] data to be decrypted, format: binary string
  # @param cipher_mode [Integer] 0: C1C2C3, 1: C1C3C2, default: 1
  # @return [String] encrypted data, format: binary string
  def decrypt(private_key, data, cipher_mode: 1)
    data = "\x04#{data}" if data[0] != "\x04"

    c1 = data[0, 65]
    c2_size = data.bytesize - 97
    if cipher_mode == 0
      c2 = data[65, c2_size]
      c3 = data[65 + c2_size, 32]
    else
      c3 = data[65, 32]
      c2 = data[97, c2_size]
    end
    point = OpenSSL::PKey::EC::Point.new(OpenSSL::PKey::EC::Group.new("SM2"), OpenSSL::BN.new(c1, 2))
    pkey = OpenSSL::BN.new(private_key, 2)
    p = point.mul(pkey)
    p_bin_str = p.to_bn.to_s(2)
    x2 = p_bin_str[1, 32]
    y2 = p_bin_str[33, 32]

    t = kdf(x2 + y2, c2_size)
    raise ArgumentError, "KDF is 0" if t[0, 8].uniq == [0] && t.uniq == [0]

    msg = c2.each_byte.map.with_index { |b, i| b ^ t[i] }.pack("C*")

    digest = OpenSSL::Digest.digest("SM3", x2 + msg + y2)
    raise ArgumentError, "Digest no match" if c3 != digest

    msg
  end
end
