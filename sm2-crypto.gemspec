# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "sm2-crypto"
  spec.version = "0.2.2"
  spec.authors = ["Seekr"]
  spec.email = ["wzhao23@gmail.com"]

  spec.summary = "An SM2 cryptographic algorithm encryption and decryption library for Ruby"
  spec.description = "sm2-crypto is an implementation of the SM2 encryption and decryption algorithm in pure Ruby based on the OpenSSL"
  spec.homepage = "https://github.com/numbcoder/sm2-crypto"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.7.0"

  spec.metadata["rubygems_mfa_required"] = "true"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
end
