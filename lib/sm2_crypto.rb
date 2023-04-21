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
    c1 = random_key.public_key.to_octet_string(:uncompressed)

    p = point.mul(k)
    p_bin_str = p.to_octet_string(:uncompressed)
    x2 = p_bin_str[1, 32]
    y2 = p_bin_str[33, 32]

    t = kdf(x2 + y2, data.bytesize)
    t = kdf(x2 + y2, data.bytesize) while t[0, 8].uniq == [0] && t.uniq == [0]

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
    p_bin_str = p.to_octet_string(:uncompressed)
    x2 = p_bin_str[1, 32]
    y2 = p_bin_str[33, 32]

    t = kdf(x2 + y2, c2_size)
    raise ArgumentError, "KDF is 0" if t[0, 8].uniq == [0] && t.uniq == [0]

    msg = c2.each_byte.map.with_index { |b, i| b ^ t[i] }.pack("C*")

    digest = OpenSSL::Digest.digest("SM3", x2 + msg + y2)
    raise ArgumentError, "Digest no match" if c3 != digest

    msg
  end

  # get public key from private key
  #
  # @param private_key [String] private key, format: binary string
  # @return [String] public key, format: binary string
  def get_public_key(private_key)
    pkey = OpenSSL::BN.new(private_key, 2)
    group = OpenSSL::PKey::EC::Group.new("SM2")
    group.generator.mul(pkey).to_octet_string(:uncompressed)
  end

  # sign with private key
  #
  # @param private_key [String] private key, format: binary string
  # @param data [String]
  # @param sm3_hash [Boolean], option to sign with sm3 hash, default: false
  # @param user_id [String], format: hex string, default: "31323334353637383132333435363738"
  # @return [String] signature, format: hex string
  def sign(private_key, data, sm3_hash: false, user_id: "31323334353637383132333435363738")
    data = data.unpack1("a*") unless data.ascii_only?
    if sm3_hash
      public_key = get_public_key(private_key)
      data = OpenSSL::Digest.digest("SM3", za(public_key, user_id) + data)
    end

    n = OpenSSL::BN.new("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
    da = OpenSSL::BN.new(private_key, 2)
    e = OpenSSL::BN.new(data, 2)
    one = OpenSSL::BN.new(1)

    k = 0
    s = 0
    r = 0
    while s.zero?
      while r.zero? || r + k == n
        random_key = OpenSSL::PKey::EC.generate("SM2")
        k = random_key.private_key
        x1 = OpenSSL::BN.new(random_key.public_key.to_octet_string(:uncompressed)[1, 32], 2)
        # r = (e + x1) mod n
        r = (e + x1) % n
      end
      # s = ((1 + dA)^-1 * (k - r * dA)) mod n
      s = ((one + da).mod_inverse(n) * (k - (r * da))).to_i % n.to_i
    end

    r.to_s(16).rjust(64, "0") + s.to_s(16).rjust(64, "0")
  end

  # verify the signature with public_key
  #
  # @param public_key [String] public key, format: binary string
  # @param data [String]
  # @param signature [String], hex string
  # @param sm3_hash [Boolean], option to sign with sm3 hash, default: false
  # @param user_id [String], format: hex string, default: "31323334353637383132333435363738"
  # @return [Boolean] verify result
  def verify(public_key, data, signature, sm3_hash: false, user_id: "31323334353637383132333435363738")
    return false if signature.size != 128

    public_key = "\x04#{public_key}" if public_key.size == 64 && public_key[0] != "\x04"
    data = data.unpack1("a*") unless data.ascii_only?
    if sm3_hash
      data = OpenSSL::Digest.digest("SM3", za(public_key, user_id) + data)
    end
    r = OpenSSL::BN.new(signature[0, 64], 16)
    s = OpenSSL::BN.new(signature[64, 64], 16)
    n = OpenSSL::BN.new("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
    e = OpenSSL::BN.new(data, 2)

    # t = (r + s) mod n
    t = (r + s) % n
    return false if t.zero?

    point = OpenSSL::PKey::EC::Point.new(OpenSSL::PKey::EC::Group.new("SM2"), OpenSSL::BN.new(public_key, 2))

    # x1y1 = s * G + t * PA
    x1y1 = point.mul(t, s)
    x1 = OpenSSL::BN.new(x1y1.to_octet_string(:uncompressed)[1, 32], 2)

    # R = (e + x1) mod n
    r1 = (e + x1) % n

    r == r1
  end

  # ZA = H256(ENTLA || IDA || a || b || gx || gy || px || py)
  def za(public_key, user_id)
    ida = [user_id].pack("H*")
    entla = [ida.size * 8].pack("n")
    a = ["FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"].pack("H*")
    b = ["28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"].pack("H*")
    gxgy = OpenSSL::PKey::EC::Group.new("SM2").generator.to_octet_string(:uncompressed)[1, 64]
    public_key = public_key[1, 64] if public_key.size == 65

    OpenSSL::Digest.digest("SM3", entla + ida + a + b + gxgy + public_key)
  end
end
