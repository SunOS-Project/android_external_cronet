// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ANONYMOUS_TOKENS_CPP_CRYPTO_RSA_BLINDER_H_
#define ANONYMOUS_TOKENS_CPP_CRYPTO_RSA_BLINDER_H_

#include <stdint.h>

#include <memory>
#include <optional>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "anonymous_tokens/cpp/crypto/blinder.h"
#include "anonymous_tokens/cpp/crypto/crypto_utils.h"


namespace anonymous_tokens {

// RsaBlinder `blinds` input messages, and then unblinds them after they are
// signed.
class RsaBlinder : public Blinder {
 public:
  // Passing of public_metadata is optional. If it is set to any value including
  // an empty string, RsaBlinder will assume that partially blind RSA signature
  // protocol is being executed.
  //
  // If public metadata is passed and the boolean "use_rsa_public_exponent" is
  // set to false, the rsa_public_exponent is not used in any computations in
  // the protocol.
  //
  // Setting "use_rsa_public_exponent" to true is deprecated. All new users
  // should set it to false.
  static absl::StatusOr<std::unique_ptr<RsaBlinder>> New(
      absl::string_view rsa_modulus, absl::string_view rsa_public_exponent,
      const EVP_MD* signature_hash_function, const EVP_MD* mgf1_hash_function,
      int salt_length, bool use_rsa_public_exponent,
      std::optional<absl::string_view> public_metadata = std::nullopt);

  // Blind `message` using n and e derived from an RSA public key and the public
  // metadata if applicable.
  //
  // Before blinding, the `message` will first be hashed and then encoded with
  // the EMSA-PSS operation.
  absl::StatusOr<std::string> Blind(absl::string_view message) override;

  // Unblinds `blind_signature`.
  //
  // Callers should run Verify on the returned signature before using it /
  // passing it on.
  absl::StatusOr<std::string> Unblind(
      absl::string_view blind_signature) override;

  // Verifies an `unblinded` signature against the same `message' that was
  // passed to Blind.
  absl::Status Verify(absl::string_view signature, absl::string_view message);

 private:
  // Use `New` to construct
  RsaBlinder(int salt_length, std::optional<absl::string_view> public_metadata,
             const EVP_MD* sig_hash, const EVP_MD* mgf1_hash,
             bssl::UniquePtr<RSA> rsa_public_key, bssl::UniquePtr<BIGNUM> r,
             bssl::UniquePtr<BIGNUM> r_inv_mont,
             bssl::UniquePtr<BN_MONT_CTX> mont_n);

  const int salt_length_;
  std::optional<std::string> public_metadata_;
  const EVP_MD* sig_hash_;   // Owned by BoringSSL.
  const EVP_MD* mgf1_hash_;  // Owned by BoringSSL.

  // If public metadata was passed to RsaBlinder::New, rsa_public_key_ will
  // will be initialized using RSA_new_public_key_large_e method.
  const bssl::UniquePtr<RSA> rsa_public_key_;

  const bssl::UniquePtr<BIGNUM> r_;
  // r^-1 mod n in the Montgomery domain
  const bssl::UniquePtr<BIGNUM> r_inv_mont_;
  const bssl::UniquePtr<BN_MONT_CTX> mont_n_;

  BlinderState blinder_state_;
};

}  // namespace anonymous_tokens


#endif  // ANONYMOUS_TOKENS_CPP_CRYPTO_RSA_BLINDER_H_
