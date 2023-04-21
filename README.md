# sm2-crypto

sm2-crypto is an implementation of the SM2 encryption and decryption algorithm in pure Ruby based on the OpenSSL SM2 elliptic curve cryptography standard.

## Installation
OpenSSL has added support for SM2/SM3/SM4 encryption algorithms since version [1.1.1](https://www.openssl.org/news/openssl-1.1.1-notes.html). However, Ruby does not wrap the C interface related to SM2 encryption and decryption in OpenSSL. This library is not a wrapper for the C interface, but an implementation of the SM2 encryption and decryption algorithm in pure Ruby, based on the `OpenSSL::PKey::EC` interface.

Before using, please make sure your Ruby's OpenSSL version is `1.1.1` or higher.

Check the OpenSSL version in Ruby:

```ruby
irb(main):001:0> require "openssl"
=> true
irb(main):002:0> OpenSSL::OPENSSL_VERSION
=> "OpenSSL 1.1.1k  25 Mar 2021"
```

Add this line to your Gemfile:

```ruby
gem "sm2-crypto"
```

Or install it yourself via command line:

```shell
$ gem install sm2-crypto
```

## Usage

### Encrypt and Decrypt

```ruby
require 'sm2_crypto'

# Generate key pair
keypair = OpenSSL::PKey::EC.generate("SM2")
private_key = keypair.private_key.to_s(2)
public_key = keypair.public_key.to_octet_string(:uncompressed)

# Encrypt data
message = "Hello, SM2 encryption!"
encrypted_data = SM2Crypto.encrypt(public_key, message)
puts "Encrypted message: #{encrypted_data}"

# Decrypt data
decrypted_message = SM2Crypto.decrypt(private_key, encrypted_data)
puts "Decrypted message: #{decrypted_message}"
```

### Sign and Verify

```ruby
message = "Hello, SM2 signature!"
# get signatrue
sign = SM2Crypto.sign(private_key, message)
# verify signatrue
SM2Crypto.verify(public_key, message, sign)

user_id = "31323334353637383132333435363738" # user_id should be a hex string
# sign with hash and user_id
sign = SM2Crypto.sign(private_key, message, sm3_hash: true, user_id: user_id)
# verify with hash and user_id
SM2Crypto.verify(public_key, message, sign, sm3_hash: true, user_id: user_id)
```

### Get Public Key from Private Key

```ruby
public_key = SM2Crypto.get_public_key(private_key)
```

## Contributing

Contributions to the project are welcome. Please fork the repository, create a feature branch, and submit a pull request. Be sure to add tests and update documentation as needed.

For bug reports and feature requests, please open an issue on the [GitHub repository](https://github.com/numbcoder/sm2-crypto/issues).

## License

sm2-crypto is released under the [MIT License](https://opensource.org/licenses/MIT).
