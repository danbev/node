#include "node_security_spi.h"
#include "env.h"
#include "openssl/bio.h"

// TODO(danbev) Remove the dependency to V8 from node_crypto_bio.h if possible
#include "node_crypto_bio.h"

#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif  // !OPENSSL_NO_ENGINE
#include <openssl/err.h>
#include <openssl/evp.h>
// TODO(shigeki) Remove this after upgrading to 1.1.1
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>

#include <functional>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include "util.h"
#include "v8.h"

namespace node {
namespace security {

// Forcibly clear OpenSSL's error stack on return. This stops stale errors
// from popping up later in the lifecycle of crypto operations where they
// would cause spurious failures. It's a rather blunt method, though.
// ERR_clear_error() isn't necessarily cheap either.
struct ClearErrorOnReturn {
  ~ClearErrorOnReturn() { ERR_clear_error(); }
};

// Pop errors from OpenSSL's error stack that were added
// between when this was constructed and destructed.
struct MarkPopErrorOnReturn {
  MarkPopErrorOnReturn() { ERR_set_mark(); }
  ~MarkPopErrorOnReturn() { ERR_pop_to_mark(); }
};

// Define smart pointers for the most commonly used OpenSSL types:
using X509Pointer = DeleteFnPtr<X509, X509_free>;
using BIOPointer = DeleteFnPtr<BIO, BIO_free_all>;
using SSLCtxPointer = DeleteFnPtr<SSL_CTX, SSL_CTX_free>;
using SSLSessionPointer = DeleteFnPtr<SSL_SESSION, SSL_SESSION_free>;
using SSLPointer = DeleteFnPtr<SSL, SSL_free>;
using EVPKeyPointer = DeleteFnPtr<EVP_PKEY, EVP_PKEY_free>;
using EVPKeyCtxPointer = DeleteFnPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using EVPMDPointer = DeleteFnPtr<EVP_MD_CTX, EVP_MD_CTX_free>;
using RSAPointer = DeleteFnPtr<RSA, RSA_free>;
using ECPointer = DeleteFnPtr<EC_KEY, EC_KEY_free>;
using BignumPointer = DeleteFnPtr<BIGNUM, BN_free>;
using NetscapeSPKIPointer = DeleteFnPtr<NETSCAPE_SPKI, NETSCAPE_SPKI_free>;
using ECGroupPointer = DeleteFnPtr<EC_GROUP, EC_GROUP_free>;
using ECPointPointer = DeleteFnPtr<EC_POINT, EC_POINT_free>;
using ECKeyPointer = DeleteFnPtr<EC_KEY, EC_KEY_free>;
using DHPointer = DeleteFnPtr<DH, DH_free>;

struct StackOfX509Deleter {
  void operator()(STACK_OF(X509)* p) const { sk_X509_pop_free(p, X509_free); }
};
using StackOfX509 = std::unique_ptr<STACK_OF(X509), StackOfX509Deleter>;
using ContextStatus = SecurityProvider::Context::ContextStatus;
using TicketKeyCallbackResult = SecurityProvider::TicketKeyCallbackResult;
using TicketKey = SecurityProvider::TicketKey;
using Hash = SecurityProvider::Hash;

// Ensure that OpenSSL has enough entropy (at least 256 bits) for its PRNG.
// The entropy pool starts out empty and needs to fill up before the PRNG
// can be used securely.  Once the pool is filled, it never dries up again;
// its contents is stirred and reused when necessary.
//
// OpenSSL normally fills the pool automatically but not when someone starts
// generating random numbers before the pool is full: in that case OpenSSL
// keeps lowering the entropy estimate to thwart attackers trying to guess
// the initial state of the PRNG.
//
// When that happens, we will have to wait until enough entropy is available.
// That should normally never take longer than a few milliseconds.
//
// OpenSSL draws from /dev/random and /dev/urandom.  While /dev/random may
// block pending "true" randomness, /dev/urandom is a CSPRNG that doesn't
// block under normal circumstances.
//
// The only time when /dev/urandom may conceivably block is right after boot,
// when the whole system is still low on entropy.  That's not something we can
// do anything about.
void SecurityProvider::CheckEntropy() {
  for (;;) {
    int status = RAND_status();
    CHECK_GE(status, 0);  // Cannot fail.
    if (status != 0)
      break;

    // Give up, RAND_poll() not supported.
    if (RAND_poll() == 0)
      break;
  }
}

bool SecurityProvider::EntropySource(unsigned char* buffer, size_t length) {
  // Ensure that OpenSSL's PRNG is properly seeded.
  SecurityProvider::CheckEntropy();
  // RAND_bytes() can return 0 to indicate that the entropy data is not truly
  // random. That's okay, it's still better than V8's stock source of entropy,
  // which is /dev/urandom on UNIX platforms and the current time on Windows.
  return RAND_bytes(buffer, length) != -1;
}

void SecurityProvider::Init() {
#ifdef NODE_FIPS_MODE
  // In the case of FIPS builds we should make sure
  // the random source is properly initialized first.
  OPENSSL_init();
#endif  // NODE_FIPS_MODE
  // V8 on Windows doesn't have a good source of entropy. Seed it from
  // OpenSSL's pool.
  v8::V8::SetEntropySource(EntropySource);
}

void SecurityProvider::InitProviderOnce() {
  SSL_load_error_strings();
  OPENSSL_no_config();

  // --openssl-config=...
  if (!node::per_process_opts->openssl_config.empty()) {
    OPENSSL_load_builtin_modules();
#ifndef OPENSSL_NO_ENGINE
    ENGINE_load_builtin_engines();
#endif
    ERR_clear_error();
    CONF_modules_load_file(
        node::per_process_opts->openssl_config.c_str(),
        nullptr,
        CONF_MFLAGS_DEFAULT_SECTION);
    int err = ERR_get_error();
    if (0 != err) {
      fprintf(stderr,
              "openssl config failed: %s\n",
              ERR_error_string(err, nullptr));
      CHECK_NE(err, 0);
    }
  }

  SSL_library_init();
  OpenSSL_add_all_algorithms();

#ifdef NODE_FIPS_MODE
  /* Override FIPS settings in cnf file, if needed. */
  unsigned long err = 0;  // NOLINT(runtime/int)
  if (node::per_process_opts->enable_fips_crypto ||
      node::per_process_opts->force_fips_crypto) {
    if (0 == FIPS_mode() && !FIPS_mode_set(1)) {
      err = ERR_get_error();
    }
  }
  if (0 != err) {
    fprintf(stderr,
            "openssl fips failed: %s\n",
            ERR_error_string(err, nullptr));
    UNREACHABLE();
  }
#endif  // NODE_FIPS_MODE


  // Turn off compression. Saves memory and protects against CRIME attacks.
  // No-op with OPENSSL_NO_COMP builds of OpenSSL.
  sk_SSL_COMP_zero(SSL_COMP_get_compression_methods());

#ifndef OPENSSL_NO_ENGINE
  ERR_load_ENGINE_strings();
  ENGINE_load_builtin_engines();
#endif  // !OPENSSL_NO_ENGINE

  node::crypto::NodeBIO::GetMethod();
}

std::string SecurityProvider::GetProviderName() {
  return "openssl";
}

constexpr int search(const char* s, int n, int c) {
  return *s == c ? n : search(s + 1, n + 1, c);
}

std::string SecurityProvider::GetVersion() {
  // sample openssl version string format
  // for reference: "OpenSSL 1.1.0i 14 Aug 2018"
  char buf[128];
  const int start = search(OPENSSL_VERSION_TEXT, 0, ' ') + 1;
  const int end = search(OPENSSL_VERSION_TEXT + start, start, ' ');
  const int len = end - start;
  snprintf(buf, sizeof(buf), "%.*s", len, &OPENSSL_VERSION_TEXT[start]);
  return std::string(buf);
}

void SecurityProvider::UseCaExtraCerts(std::string certs) {
  node::crypto::UseExtraCaCerts(certs);
}

static void get_hashes(const EVP_MD* md,
                       const char* from,
                       const char* to,
                       void* arg) {
  static_cast<std::vector<std::string>*>(arg)->push_back(from);
}

std::vector<std::string> SecurityProvider::GetHashes() {
  std::vector<std::string> hashes;
  EVP_MD_do_all_sorted(get_hashes, &hashes);
  return hashes;
}

static void get_ciphers(const EVP_CIPHER* c,
                        const char* from,
                        const char* to,
                        void* arg) {
  static_cast<std::vector<std::string>*>(arg)->push_back(from);
}

std::vector<std::string> SecurityProvider::GetCiphers() {
  std::vector<std::string> ciphers;
  EVP_CIPHER_do_all_sorted(get_ciphers, &ciphers);
  return ciphers;
}

std::vector<std::string> SecurityProvider::GetTLSCiphers() {
  SSLCtxPointer ctx(SSL_CTX_new(TLS_method()));
  CHECK(ctx);

  SSLPointer ssl(SSL_new(ctx.get()));
  CHECK(ssl);

  STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(ssl.get());
  int n = sk_SSL_CIPHER_num(ciphers);
  std::vector<std::string> tls_ciphers(n);
  for (int i = 0; i < n; ++i) {
    const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
    tls_ciphers[i] = SSL_CIPHER_get_name(cipher);
  }
  return tls_ciphers;
}

std::vector<std::string> SecurityProvider::GetCurves() {
  const size_t num_curves = EC_get_builtin_curves(nullptr, 0);
  std::vector<std::string> curves(num_curves);
  std::vector<EC_builtin_curve> builtin_curves(num_curves);
  if (EC_get_builtin_curves(builtin_curves.data(), num_curves)) {
    for (const EC_builtin_curve& c : builtin_curves) {
      curves.push_back(OBJ_nid2sn(c.nid));
    }
  }
  return curves;
}

std::vector<std::string> SecurityProvider::GetErrors() {
  std::vector<std::string> errors;
  while (auto err = ERR_get_error()) {
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    errors.push_back(buf);
  }
  return errors;
}

uint32_t SecurityProvider::GetError() {
  return ERR_get_error();  // NOLINT(runtime/int)
}

std::string SecurityProvider::GetErrorStr() {
  unsigned long err = ERR_get_error();  // NOLINT(runtime/int)
  const char* str = ERR_reason_error_string(err);
  return std::string(str);
}

std::string SecurityProvider::GetErrorStr(uint32_t id) {
  const char* str = ERR_reason_error_string(id);
  return std::string(str);
}

bool SecurityProvider::VerifySpkac(const char* data, unsigned int len) {
  NetscapeSPKIPointer spki(NETSCAPE_SPKI_b64_decode(data, len));
  if (!spki)
    return false;

  EVPKeyPointer pkey(X509_PUBKEY_get(spki->spkac->pubkey));
  if (!pkey)
    return false;

  return NETSCAPE_SPKI_verify(spki.get(), pkey.get()) > 0;
}

char* SecurityProvider::ExportPublicKey(const char* data,
                                        int len,
                                        size_t* size) {
  char* buf = nullptr;

  BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!bio)
    return nullptr;

  NetscapeSPKIPointer spki(NETSCAPE_SPKI_b64_decode(data, len));
  if (!spki)
    return nullptr;

  EVPKeyPointer pkey(NETSCAPE_SPKI_get_pubkey(spki.get()));
  if (!pkey)
    return nullptr;

  if (PEM_write_bio_PUBKEY(bio.get(), pkey.get()) <= 0)
    return nullptr;

  BUF_MEM* ptr;
  BIO_get_mem_ptr(bio.get(), &ptr);

  *size = ptr->length;
  buf = node::Malloc(*size);
  memcpy(buf, ptr->data, *size);

  return buf;
}

unsigned char* SecurityProvider::ExportChallenge(const char* data, int len) {
  NetscapeSPKIPointer sp(NETSCAPE_SPKI_b64_decode(data, len));
  if (!sp)
    return nullptr;

  unsigned char* buf = nullptr;
  ASN1_STRING_to_UTF8(&buf, sp->spkac->challenge);

  return buf;
}

SecurityProvider::Status SecurityProvider::RandomBytes(size_t size,
                                                       unsigned char* data) {
  return (1 == RAND_bytes(data, size)) ? Status::ok : Status::error;
}

SecurityProvider::PBKDF2::PBKDF2(std::vector<char> pass,
                                 std::vector<char> salt,
                                 uint32_t iteration_count,
                                 std::string digest_name,
                                 unsigned char* keybuf,
                                 size_t keybuf_size) : pass_(pass),
                                 salt_(salt),
                                 iteration_count_(iteration_count),
                                 digest_name_(digest_name),
                                 keybuf_(keybuf), keybuf_size_(keybuf_size) {
  digest_ = const_cast<EVP_MD*>(EVP_get_digestbyname(digest_name_.c_str()));
}

bool SecurityProvider::PBKDF2::HasDigest() {
  return digest_ != nullptr;
}

bool SecurityProvider::PBKDF2::Generate() {
  auto salt_data = reinterpret_cast<const unsigned char*>(salt_.data());
  const EVP_MD* digest = static_cast<const EVP_MD*>(digest_);
  return PKCS5_PBKDF2_HMAC(pass_.data(), pass_.size(),
                           salt_data, salt_.size(),
                           iteration_count_, digest,
                           keybuf_size_, keybuf_);
}

void SecurityProvider::PBKDF2::Cleanup() {
  OPENSSL_cleanse(pass_.data(), pass_.size());
  OPENSSL_cleanse(salt_.data(), salt_.size());
  pass_.clear();
  salt_.clear();
}

std::unordered_map<std::string, double> SecurityProvider::Constants() {
  std::unordered_map<std::string, double> constants {
    {STRINGIFY_(OPENSSL_EC_NAMED_CURVE), OPENSSL_EC_NAMED_CURVE},
    {STRINGIFY_(OPENSSL_EC_EXPLICIT_CURVE), OPENSSL_EC_EXPLICIT_CURVE},
    {STRINGIFY(PK_ENCODING_PKCS1), PK_ENCODING_PKCS1},
    {STRINGIFY(PK_ENCODING_PKCS8), PK_ENCODING_PKCS8},
    {STRINGIFY(PK_ENCODING_SPKI), PK_ENCODING_SPKI},
    {STRINGIFY(PK_ENCODING_SEC1), PK_ENCODING_SEC1},
    {STRINGIFY(PK_FORMAT_DER), PK_FORMAT_DER},
    {STRINGIFY(PK_FORMAT_PEM), PK_FORMAT_PEM}
  };
  return constants;
}

bool SecurityProvider::TimingSafeEquals(const void* a,
                                        const void* b,
                                        size_t len) {
  return CRYPTO_memcmp(a, b, len) == 0;
}

enum ParsePublicKeyResult {
  kParsePublicOk,
  kParsePublicNotRecognized,
  kParsePublicFailed
};

static int PasswordCallback(char* buf, int size, int rwflag, void* u) {
  if (u) {
    size_t buflen = static_cast<size_t>(size);
    size_t len = strlen(static_cast<const char*>(u));
    len = len > buflen ? buflen : len;
    memcpy(buf, u, len);
    return len;
  }

  return 0;
}

static ParsePublicKeyResult TryParsePublicKey(
    EVPKeyPointer* pkey,
    const BIOPointer& bp,
    const char* name,
    // NOLINTNEXTLINE(runtime/int)
    std::function<EVP_PKEY*(const unsigned char** p, long l)> parse) {
  unsigned char* der_data;
  long der_len;  // NOLINT(runtime/int)

  // This skips surrounding data and decodes PEM to DER.
  {
    MarkPopErrorOnReturn mark_pop_error_on_return;
    if (PEM_bytes_read_bio(&der_data, &der_len, nullptr, name,
                           bp.get(), nullptr, nullptr) != 1)
      return kParsePublicNotRecognized;
  }

  // OpenSSL might modify the pointer, so we need to make a copy before parsing.
  const unsigned char* p = der_data;
  pkey->reset(parse(&p, der_len));
  OPENSSL_clear_free(der_data, der_len);

  return *pkey ? kParsePublicOk : kParsePublicFailed;
}

static ParsePublicKeyResult ParsePublicKey(EVPKeyPointer* pkey,
                                           const char* key_pem,
                                           int key_pem_len) {
  BIOPointer bp(BIO_new_mem_buf(const_cast<char*>(key_pem),
                                        key_pem_len));
  if (!bp)
    return kParsePublicFailed;

  ParsePublicKeyResult ret;

  // Try PKCS#8 first.
  ret = TryParsePublicKey(pkey, bp, "PUBLIC KEY",
      [](const unsigned char** p, long l) {  // NOLINT(runtime/int)
        return d2i_PUBKEY(nullptr, p, l);
      });
  if (ret != kParsePublicNotRecognized)
    return ret;

  // Maybe it is PKCS#1.
  CHECK(BIO_reset(bp.get()));
  ret = TryParsePublicKey(pkey, bp, "RSA PUBLIC KEY",
      [](const unsigned char** p, long l) {  // NOLINT(runtime/int)
        return d2i_PublicKey(EVP_PKEY_RSA, nullptr, p, l);
      });
  if (ret != kParsePublicNotRecognized)
    return ret;

  // X.509 fallback.
  CHECK(BIO_reset(bp.get()));
  return TryParsePublicKey(pkey, bp, "CERTIFICATE",
      [](const unsigned char** p, long l) {  // NOLINT(runtime/int)
        X509Pointer x509(d2i_X509(nullptr, p, l));
        return x509 ? X509_get_pubkey(x509.get()) : nullptr;
      });
}

bool SecurityProvider::KeyCipher::PrivateEncrypt(const char* key_pem,
                                                 int key_pem_len,
                                                 const char* passphrase,
                                                 int padding,
                                                 const unsigned char* data,
                                                 int len,
                                                 unsigned char** out,
                                                 size_t* out_len) {
  EVPKeyPointer pkey;
  BIOPointer bp(BIO_new_mem_buf(const_cast<char*>(key_pem),
                                        key_pem_len));
  if (bp == nullptr)
    return false;

  pkey.reset(PEM_read_bio_PrivateKey(bp.get(),
                                     nullptr,
                                     PasswordCallback,
                                     const_cast<char*>(passphrase)));
  if (pkey == nullptr)
    return false;

  EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
  if (!ctx)
    return false;
  if (EVP_PKEY_sign_init(ctx.get()) <= 0)
    return false;
  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), padding) <= 0)
    return false;

  if (EVP_PKEY_sign(ctx.get(), nullptr, out_len, data, len) <= 0)
    return false;

  *out = Malloc<unsigned char>(*out_len);

  if (EVP_PKEY_sign(ctx.get(), *out, out_len, data, len) <= 0)
    return false;

  return true;
}

bool SecurityProvider::KeyCipher::PrivateDecrypt(const char* key_pem,
                             int key_pem_len,
                             const char* passphrase,
                             int padding,
                             const unsigned char* data,
                             int len,
                             unsigned char** out,
                             size_t* out_len) {
  EVPKeyPointer pkey;
  BIOPointer bp(BIO_new_mem_buf(const_cast<char*>(key_pem),
                                        key_pem_len));
  if (bp == nullptr)
    return false;

  pkey.reset(PEM_read_bio_PrivateKey(bp.get(),
                                     nullptr,
                                     PasswordCallback,
                                     const_cast<char*>(passphrase)));
  if (pkey == nullptr)
    return false;

  EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
  if (!ctx)
    return false;
  if (EVP_PKEY_decrypt_init(ctx.get()) <= 0)
    return false;
  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), padding) <= 0)
    return false;

  if (EVP_PKEY_decrypt(ctx.get(), nullptr, out_len, data, len) <= 0)
    return false;

  *out = Malloc<unsigned char>(*out_len);

  if (EVP_PKEY_decrypt(ctx.get(), *out, out_len, data, len) <= 0)
    return false;

  return true;
}

bool SecurityProvider::KeyCipher::PublicEncrypt(const char* key_pem,
                             int key_pem_len,
                             const char* passphrase,
                             int padding,
                             const unsigned char* data,
                             int len,
                             unsigned char** out,
                             size_t* out_len) {
  EVPKeyPointer pkey;

  // Check if this is a PKCS#8 or RSA public key before trying as X.509 and
  // private key.
  ParsePublicKeyResult pkeyres = ParsePublicKey(&pkey, key_pem, key_pem_len);
  if (pkeyres == kParsePublicFailed)
    return false;

  if (pkey == nullptr) {
    // Private key fallback.
    BIOPointer bp(BIO_new_mem_buf(const_cast<char*>(key_pem),
                                          key_pem_len));
    if (bp == nullptr)
      return false;
    pkey.reset(PEM_read_bio_PrivateKey(bp.get(),
                                       nullptr,
                                       PasswordCallback,
                                       const_cast<char*>(passphrase)));
    if (pkey == nullptr)
      return false;
  }

  EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
  if (!ctx)
    return false;
  if (EVP_PKEY_encrypt_init(ctx.get()) <= 0)
    return false;
  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), padding) <= 0)
    return false;

  if (EVP_PKEY_encrypt(ctx.get(), nullptr, out_len, data, len) <= 0)
    return false;

  *out = Malloc<unsigned char>(*out_len);

  if (EVP_PKEY_encrypt(ctx.get(), *out, out_len, data, len) <= 0)
    return false;

  return true;
}

bool SecurityProvider::KeyCipher::PublicDecrypt(const char* key_pem,
                             int key_pem_len,
                             const char* passphrase,
                             int padding,
                             const unsigned char* data,
                             int len,
                             unsigned char** out,
                             size_t* out_len) {
  EVPKeyPointer pkey;

  // Check if this is a PKCS#8 or RSA public key before trying as X.509 and
  // private key.
  ParsePublicKeyResult pkeyres = ParsePublicKey(&pkey, key_pem, key_pem_len);
  if (pkeyres == kParsePublicFailed)
    return false;

  if (pkey == nullptr) {
    // Private key fallback.
    BIOPointer bp(BIO_new_mem_buf(const_cast<char*>(key_pem),
                                          key_pem_len));
    if (bp == nullptr)
      return false;
    pkey.reset(PEM_read_bio_PrivateKey(bp.get(),
                                       nullptr,
                                       PasswordCallback,
                                       const_cast<char*>(passphrase)));
    if (pkey == nullptr)
      return false;
  }

  EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
  if (!ctx)
    return false;
  if (EVP_PKEY_verify_recover_init(ctx.get()) <= 0)
    return false;
  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), padding) <= 0)
    return false;

  if (EVP_PKEY_verify_recover(ctx.get(), nullptr, out_len, data, len) <= 0)
    return false;

  *out = Malloc<unsigned char>(*out_len);

  if (EVP_PKEY_verify_recover(ctx.get(), *out, out_len, data, len) <= 0)
    return false;

  return true;
}


class KeyPairGenerationConfig {
 public:
  virtual EVPKeyCtxPointer Setup() = 0;
  virtual bool Configure(const EVPKeyCtxPointer& ctx) {
    return true;
  }
  virtual ~KeyPairGenerationConfig() {}
};

class RSAKeyPairGenerationConfig : public KeyPairGenerationConfig {
 public:
  RSAKeyPairGenerationConfig(unsigned int modulus_bits, unsigned int exponent)
    : modulus_bits_(modulus_bits), exponent_(exponent) {}

  EVPKeyCtxPointer Setup() override {
    return EVPKeyCtxPointer(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  }

  bool Configure(const EVPKeyCtxPointer& ctx) override {
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), modulus_bits_) <= 0)
      return false;

    // 0x10001 is the default RSA exponent.
    if (exponent_ != 0x10001) {
      BignumPointer bn(BN_new());
      CHECK_NOT_NULL(bn.get());
      CHECK(BN_set_word(bn.get(), exponent_));
      if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx.get(), bn.get()) <= 0)
        return false;
    }

    return true;
  }

 private:
  const unsigned int modulus_bits_;
  const unsigned int exponent_;
};

class DSAKeyPairGenerationConfig : public KeyPairGenerationConfig {
 public:
  DSAKeyPairGenerationConfig(unsigned int modulus_bits, int divisor_bits)
    : modulus_bits_(modulus_bits), divisor_bits_(divisor_bits) {}

    EVPKeyCtxPointer Setup() override {
      EVPKeyCtxPointer param_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_DSA,
                                                             nullptr));
    if (!param_ctx)
      return nullptr;

    if (EVP_PKEY_paramgen_init(param_ctx.get()) <= 0)
      return nullptr;

    if (EVP_PKEY_CTX_set_dsa_paramgen_bits(param_ctx.get(), modulus_bits_) <= 0)
      return nullptr;

    if (divisor_bits_ != -1) {
      if (EVP_PKEY_CTX_ctrl(param_ctx.get(), EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                            EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, divisor_bits_,
                            nullptr) <= 0) {
        return nullptr;
      }
    }

    EVP_PKEY* params = nullptr;
    if (EVP_PKEY_paramgen(param_ctx.get(), &params) <= 0)
      return nullptr;
    param_ctx.reset();

    EVPKeyCtxPointer key_ctx(EVP_PKEY_CTX_new(params, nullptr));
    EVP_PKEY_free(params);
    return key_ctx;
  }

 private:
  const unsigned int modulus_bits_;
  const int divisor_bits_;
};

class ECKeyPairGenerationConfig : public KeyPairGenerationConfig {
 public:
  ECKeyPairGenerationConfig(int curve_nid, int param_encoding)
    : curve_nid_(curve_nid), param_encoding_(param_encoding) {}

  EVPKeyCtxPointer Setup() override {
    EVPKeyCtxPointer param_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC,
                                                           nullptr));
    if (!param_ctx)
      return nullptr;

    if (EVP_PKEY_paramgen_init(param_ctx.get()) <= 0)
      return nullptr;

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx.get(),
                                               curve_nid_) <= 0)
      return nullptr;

    if (EVP_PKEY_CTX_set_ec_param_enc(param_ctx.get(), param_encoding_) <= 0)
      return nullptr;

    EVP_PKEY* params = nullptr;
    if (EVP_PKEY_paramgen(param_ctx.get(), &params) <= 0)
      return nullptr;
    param_ctx.reset();

    EVPKeyCtxPointer key_ctx(EVP_PKEY_CTX_new(params, nullptr));
    EVP_PKEY_free(params);
    return key_ctx;
  }

 private:
  const int curve_nid_;
  const int param_encoding_;
};

typedef security::KeyPairEncodingConfig PublicKeyEncodingConfig;

struct PrivateKeyEncodingConfig : public security::KeyPairEncodingConfig {
  const EVP_CIPHER* cipher_;
  // This char* will be passed to OPENSSL_clear_free.
  std::shared_ptr<char> passphrase_;
  unsigned int passphrase_length_;
};

bool SecurityProvider::KeyPairGenerator::LoadCipher() {
  if (!cipher_name_.empty()) {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(cipher_name_.c_str());
    cipher_ = static_cast<void*>(const_cast<EVP_CIPHER*>(cipher));
    return cipher_ != nullptr;
  }
  // Setting this to nullptr will indicate to OpenSSL that no encryption of
  // the private key should be done.
  cipher_ = nullptr;
  return true;
}

bool SecurityProvider::KeyPairGenerator::HasKey() const {
  return pkey_ != nullptr;
}

bool Generate(KeyPairGenerationConfig* config, void** out) {
  // Make sure that the CSPRNG is properly seeded so the results are secure.
  SecurityProvider::CheckEntropy();

  // Create the key generation context.
  EVPKeyCtxPointer ctx = config->Setup();
  if (!ctx)
    return false;

  // Initialize key generation.
  if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
    return false;

  // Configure key generation.
  if (!config->Configure(ctx))
    return false;

  // Generate the key.
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &pkey) != 1)
    return false;
  *out = pkey;
  return true;
}

bool SecurityProvider::KeyPairGeneratorRSA::Generate() {
  std::unique_ptr<KeyPairGenerationConfig> config =
      std::make_unique<RSAKeyPairGenerationConfig>(modulus_bits_, exponent_);
  return ::node::security::Generate(config.get(), &pkey_);
}

bool SecurityProvider::KeyPairGeneratorDSA::Generate() {
  std::unique_ptr<KeyPairGenerationConfig> config =
      std::make_unique<DSAKeyPairGenerationConfig>(modulus_bits_,
                                                   divisor_bits_);
  return ::node::security::Generate(config.get(), &pkey_);
}

bool SecurityProvider::KeyPairGeneratorEC::Generate() {
  CHECK(param_encoding_ == OPENSSL_EC_NAMED_CURVE ||
        param_encoding_ == OPENSSL_EC_EXPLICIT_CURVE);
  std::unique_ptr<KeyPairGenerationConfig> config =
      std::make_unique<ECKeyPairGenerationConfig>(curve_id_,
                                                  param_encoding_);
  return ::node::security::Generate(config.get(), &pkey_);
}

bool SecurityProvider::KeyPairGeneratorEC::LoadCurve() {
  const char* curve_name = curve_name_.c_str();
  curve_id_ = EC_curve_nist2nid(curve_name);
  if (curve_id_ == NID_undef)
    curve_id_ = OBJ_sn2nid(curve_name);
  // TODO(tniessen): Should we also support OBJ_ln2nid? (Other APIs don't.)
  return curve_id_ != NID_undef;
}

bool SecurityProvider::KeyPairGenerator::EncodeKeys(Key* public_key,
                                                    Key* private_key) const {
  //  EVP_PKEY* pkey = pkey_.get();
  EVP_PKEY* pkey = static_cast<EVP_PKEY*>(pkey_);
  BIOPointer bio(BIO_new(BIO_s_mem()));
  CHECK(bio);

  // Encode the public key.
  if (pub_encoding_ == security::PK_ENCODING_PKCS1) {
    // PKCS#1 is only valid for RSA keys.
    CHECK_EQ(EVP_PKEY_id(pkey), EVP_PKEY_RSA);
    RSAPointer rsa(EVP_PKEY_get1_RSA(pkey));
    if (pub_format_ == security::PK_FORMAT_PEM) {
      // Encode PKCS#1 as PEM.
      if (PEM_write_bio_RSAPublicKey(bio.get(), rsa.get()) != 1)
        return false;
    } else {
      // Encode PKCS#1 as DER.
      CHECK_EQ(pub_format_, security::PK_FORMAT_DER);
      if (i2d_RSAPublicKey_bio(bio.get(), rsa.get()) != 1)
        return false;
    }
  } else {
    CHECK_EQ(pub_encoding_, security::PK_ENCODING_SPKI);
    if (pub_format_ == security::PK_FORMAT_PEM) {
      // Encode SPKI as PEM.
      if (PEM_write_bio_PUBKEY(bio.get(), pkey) != 1)
        return false;
    } else {
      // Encode SPKI as DER.
      CHECK_EQ(pub_format_, security::PK_FORMAT_DER);
      if (i2d_PUBKEY_bio(bio.get(), pkey) != 1)
      return false;
    }
  }

  BUF_MEM* bptr;
  BIO_get_mem_ptr(bio.get(), &bptr);
  public_key->data_ = bptr->data;
  public_key->length_ = bptr->length;

  // Release and pass ownership to public_key out parameter
  USE(bio.release());
  bio.reset(BIO_new(BIO_s_mem()));

  // Now do the same for the private key (which is a bit more difficult).
  if (pri_encoding_ == security::PK_ENCODING_PKCS1) {
    // PKCS#1 is only permitted for RSA keys.
    CHECK_EQ(EVP_PKEY_id(pkey), EVP_PKEY_RSA);

    RSAPointer rsa(EVP_PKEY_get1_RSA(pkey));
    if (pri_format_ == security::PK_FORMAT_PEM) {
      // Encode PKCS#1 as PEM.
      char* pass = const_cast<char*>(passphrase_.c_str());
      if (PEM_write_bio_RSAPrivateKey(
              bio.get(), rsa.get(),
              static_cast<EVP_CIPHER*>(cipher_),
              reinterpret_cast<unsigned char*>(pass),
              passphrase_.length(),
              nullptr, nullptr) != 1)
        return false;
    } else {
      // Encode PKCS#1 as DER. This does not permit encryption.
      CHECK_EQ(pri_format_, security::PK_FORMAT_DER);
      CHECK_NULL(cipher_);
      if (i2d_RSAPrivateKey_bio(bio.get(), rsa.get()) != 1)
        return false;
    }
  } else if (pri_encoding_ == security::PK_ENCODING_PKCS8) {
    if (pri_format_ == security::PK_FORMAT_PEM) {
      // Encode PKCS#8 as PEM.
      if (PEM_write_bio_PKCS8PrivateKey(
              bio.get(), pkey,
              static_cast<EVP_CIPHER*>(cipher_),
              const_cast<char*>(passphrase_.c_str()),
              passphrase_.length(),
              nullptr, nullptr) != 1)
        return false;
    } else {
      // Encode PKCS#8 as DER.
      CHECK_EQ(pri_format_, security::PK_FORMAT_DER);
      if (i2d_PKCS8PrivateKey_bio(
              bio.get(), pkey,
              static_cast<EVP_CIPHER*>(cipher_),
              const_cast<char*>(passphrase_.c_str()),
              passphrase_.length(),
              nullptr, nullptr) != 1)
        return false;
    }
  } else {
    CHECK_EQ(pri_encoding_, security::PK_ENCODING_SEC1);

    // SEC1 is only permitted for EC keys.
    CHECK_EQ(EVP_PKEY_id(pkey), EVP_PKEY_EC);

    ECKeyPointer ec_key(EVP_PKEY_get1_EC_KEY(pkey));
    if (pri_format_ == security::PK_FORMAT_PEM) {
      // Encode SEC1 as PEM.
      const char* pass = passphrase_.c_str();
      if (PEM_write_bio_ECPrivateKey(
              bio.get(), ec_key.get(),
              static_cast<EVP_CIPHER*>(cipher_),
              reinterpret_cast<unsigned char*>(const_cast<char*>(pass)),
              passphrase_.length(),
              nullptr, nullptr) != 1)
        return false;
    } else {
      // Encode SEC1 as DER. This does not permit encryption.
      CHECK_EQ(pri_format_, security::PK_FORMAT_DER);
      CHECK_NULL(cipher_);
      if (i2d_ECPrivateKey_bio(bio.get(), ec_key.get()) != 1)
        return false;
    }
  }

  BIO_get_mem_ptr(bio.get(), &bptr);
  private_key->data_ = bptr->data;
  private_key->length_ = bptr->length;
  // Release and pass ownership to public_key out parameter
  USE(bio.release());
  return true;
}

#ifdef NODE_FIPS_MODE
bool SecurityProvider::HasFipsSupport() {
  return FIPS_mode();
}

bool SecurityProvider::SetFipsSupport(bool enable) {
  const bool enabled = FIPS_mode();
  return enabled == enable ? true : FIPS_mode_set(enable);
}
#endif /* NODE_FIPS_MODE */

static X509_STORE* root_cert_store;

class SecurityProvider::Context::ContextImpl {
 public:
  ContextImpl() {}
  ~ContextImpl() {}
  ContextStatus Init(int min_version, int max_version,
                     std::string method_name);
  void AddRootCerts();
  ContextStatus SetCert(Cert* cert, Environment* env);
  ContextStatus SetKey(Key* key_data,
                       std::string passphrase,
                       bool has_passphrase,
                       Environment* env);
  ContextStatus AddCACert(Cert* cert, Environment* env);
  ContextStatus SetCiphers(std::string ciphers);
  ContextStatus AddCRL(Data* crl_data, Environment* env);
  ContextStatus SetECDHCurve(std::string curve);
  ContextStatus SetDHParam(Data* dh_data, Environment* env);
  ContextStatus SetOptions(int64_t val);
  ContextStatus SetSessionContextId(const unsigned char* id,
                                    unsigned int length);
  ContextStatus SetSessionTimeout(uint32_t timeout);
  ContextStatus LoadPKCS12(Data* s, std::vector<char> pass, Environment* env);
  ContextStatus SetClientCertEngine(std::string engine_id);
  ContextStatus GetCertificate(Cert* cert);
  ContextStatus GetIssuerCertificate(Cert* cert);
  ContextStatus SetTicketKey(TicketKey* key);
  TicketKey* GetTicketKey();
  ContextStatus EnableTicketCallback(OnTicketKeyCallback callback);
  ContextStatus SetEngine(std::string name, uint32_t flags);
  static int TicketKeyCallback(SSL* ssl,
                        unsigned char* name,
                        unsigned char* iv,
                        EVP_CIPHER_CTX* ectx,
                        HMAC_CTX* hctx,
                        int enc);
  static int TicketCompatibilityCallback(SSL* ssl,
                                         unsigned char* name,
                                         unsigned char* iv,
                                         EVP_CIPHER_CTX* ectx,
                                         HMAC_CTX* hctx,
                                         int enc);

 private:
  SSLCtxPointer ctx_;
  X509Pointer cert_;
  X509Pointer issuer_;
  TicketKey ticket_key_;
  OnTicketKeyCallback on_ticketkey_callback_;
};

class SecurityProvider::Hash::HashImpl {
 public:
  HashImpl() : mdctx_(nullptr) {}
  ~HashImpl() {}

  Status Init(const char* hash_type);
  Status Update(const char* data, int len);
  Status Digest(const char* data, int len);
  Status Digest(unsigned char* data, unsigned int* len);

 private:
  EVPMDPointer mdctx_;
};

SecurityProvider::Hash::Hash(Environment* env) :
    hash_impl_(std::make_unique<HashImpl>()), env_(env) {}
SecurityProvider::Hash::~Hash() {}

Hash::Status SecurityProvider::Hash::HashImpl::Init(const char* hash_type) {
  const EVP_MD* md = EVP_get_digestbyname(hash_type);
  if (md == nullptr)
    return Status::DigestNotFound;

  mdctx_.reset(EVP_MD_CTX_new());
  if (!mdctx_ || EVP_DigestInit_ex(mdctx_.get(), md, nullptr) <= 0) {
    mdctx_.reset();
    return Status::DigestInitError;
  }
  return Status::Ok;
}

Hash::Status SecurityProvider::Hash::HashImpl::Update(const char* data,
                                                      int len) {
  if (!mdctx_)
    return Status::HashNotAvailable;

  EVP_DigestUpdate(mdctx_.get(), data, len);
  return Status::Ok;
}

Hash::Status SecurityProvider::Hash::HashImpl::Digest(unsigned char* out,
                                                      unsigned int* len) {
  unsigned char md_value[EVP_MAX_MD_SIZE];
  EVP_DigestFinal_ex(mdctx_.get(), md_value, len);
  out = md_value;
  return Status::Ok;
}

Hash::Status SecurityProvider::Hash::Hash::Init(const char* hash_type) {
  return hash_impl_->Init(hash_type);
}

Hash::Status SecurityProvider::Hash::Hash::Update(const char* data, int len) {
  return hash_impl_->Update(data, len);
}

Hash::Status SecurityProvider::Hash::Hash::Digest(unsigned char* data,
                                                  unsigned int* len) {
  return hash_impl_->Digest(data, len);
}

SecurityProvider::Context::Context(Environment* env)
  : context_impl_(std::make_unique<ContextImpl>()), env_(env) {}

SecurityProvider::Context::~Context() {
}

int SecurityProvider::Context::ContextImpl::TicketCompatibilityCallback(
    SSL* ssl, unsigned char* name, unsigned char* iv, EVP_CIPHER_CTX* ectx,
    HMAC_CTX* hctx, int enc) {
  Context* context = static_cast<Context*>(
      SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
  ContextImpl* ctx = context->context_impl_.get();

  if (enc) {
    memcpy(name,
           ctx->ticket_key_.ticket_key_name_,
           sizeof(ctx->ticket_key_.ticket_key_name_));
    if (RAND_bytes(iv, 16) <= 0 ||
        EVP_EncryptInit_ex(ectx, EVP_aes_128_cbc(), nullptr,
                           ctx->ticket_key_.ticket_key_aes_, iv) <= 0 ||
        HMAC_Init_ex(hctx,
                     ctx->ticket_key_.ticket_key_hmac_,
                     sizeof(ctx->ticket_key_.ticket_key_hmac_),
                     EVP_sha256(), nullptr) <= 0) {
      return -1;
    }
    return 1;
  }

  if (memcmp(name,
             ctx->ticket_key_.ticket_key_name_,
             sizeof(ctx->ticket_key_.ticket_key_name_)) != 0) {
    // The ticket key name does not match. Discard the ticket.
    return 0;
  }

  if (EVP_DecryptInit_ex(ectx,
                         EVP_aes_128_cbc(),
                         nullptr, ctx->ticket_key_.ticket_key_aes_,
                         iv) <= 0 ||
      HMAC_Init_ex(hctx,
                   ctx->ticket_key_.ticket_key_hmac_,
                   sizeof(ctx->ticket_key_.ticket_key_hmac_),
                   EVP_sha256(), nullptr) <= 0) {
    return -1;
  }
  return 1;
}

ContextStatus SecurityProvider::Context::ContextImpl::Init(int min_version,
    int max_version, std::string method_name) {
  const SSL_METHOD* method = TLS_method();
  if (!method_name.empty()) {
    const char* ssl_method = method_name.c_str();
    // Note that SSLv2 and SSLv3 are disallowed but SSLv23_method and friends
    // are still accepted.  They are OpenSSL's way of saying that all known
    // protocols are supported unless explicitly disabled (which we do below
    // for SSLv2 and SSLv3.)
    if (strcmp(ssl_method, "SSLv2_method") == 0) {
      return ContextStatus::MethodDisabled;
    } else if (strcmp(ssl_method, "SSLv2_server_method") == 0) {
      return ContextStatus::MethodDisabled;
    } else if (strcmp(ssl_method, "SSLv2_client_method") == 0) {
      return ContextStatus::MethodDisabled;
    } else if (strcmp(ssl_method, "SSLv3_method") == 0) {
      return ContextStatus::MethodDisabled;
    } else if (strcmp(ssl_method, "SSLv3_server_method") == 0) {
      return ContextStatus::MethodDisabled;
    } else if (strcmp(ssl_method, "SSLv3_client_method") == 0) {
      return ContextStatus::MethodDisabled;
    } else if (strcmp(ssl_method, "SSLv23_method") == 0) {
      // noop
    } else if (strcmp(ssl_method, "SSLv23_server_method") == 0) {
      method = TLS_server_method();
    } else if (strcmp(ssl_method, "SSLv23_client_method") == 0) {
      method = TLS_client_method();
    } else if (strcmp(ssl_method, "TLS_method") == 0) {
      min_version = 0;
      max_version = 0;
    } else if (strcmp(ssl_method, "TLS_server_method") == 0) {
      min_version = 0;
      max_version = 0;
      method = TLS_server_method();
    } else if (strcmp(ssl_method, "TLS_client_method") == 0) {
      min_version = 0;
      max_version = 0;
      method = TLS_client_method();
    } else if (strcmp(ssl_method, "TLSv1_method") == 0) {
      min_version = TLS1_VERSION;
      max_version = TLS1_VERSION;
    } else if (strcmp(ssl_method, "TLSv1_server_method") == 0) {
      min_version = TLS1_VERSION;
      max_version = TLS1_VERSION;
      method = TLS_server_method();
    } else if (strcmp(ssl_method, "TLSv1_client_method") == 0) {
      min_version = TLS1_VERSION;
      max_version = TLS1_VERSION;
      method = TLS_client_method();
    } else if (strcmp(ssl_method, "TLSv1_1_method") == 0) {
      min_version = TLS1_1_VERSION;
      max_version = TLS1_1_VERSION;
    } else if (strcmp(ssl_method, "TLSv1_1_server_method") == 0) {
      min_version = TLS1_1_VERSION;
      max_version = TLS1_1_VERSION;
      method = TLS_server_method();
    } else if (strcmp(ssl_method, "TLSv1_1_client_method") == 0) {
      min_version = TLS1_1_VERSION;
      max_version = TLS1_1_VERSION;
      method = TLS_client_method();
    } else if (strcmp(ssl_method, "TLSv1_2_method") == 0) {
      min_version = TLS1_2_VERSION;
      max_version = TLS1_2_VERSION;
    } else if (strcmp(ssl_method, "TLSv1_2_server_method") == 0) {
      min_version = TLS1_2_VERSION;
      max_version = TLS1_2_VERSION;
      method = TLS_server_method();
    } else if (strcmp(ssl_method, "TLSv1_2_client_method") == 0) {
      min_version = TLS1_2_VERSION;
      max_version = TLS1_2_VERSION;
      method = TLS_client_method();
    } else {
      return ContextStatus::UnknownMethod;
    }
  }
  ctx_.reset(SSL_CTX_new(method));

  SSL_CTX_set_app_data(ctx_.get(), this);

  // Disable SSLv2 in the case when method == TLS_method() and the
  // cipher list contains SSLv2 ciphers (not the default, should be rare.)
  // The bundled OpenSSL doesn't have SSLv2 support but the system OpenSSL may.
  // SSLv3 is disabled because it's susceptible to downgrade attacks (POODLE.)
  SSL_CTX_set_options(ctx_.get(), SSL_OP_NO_SSLv2);
  SSL_CTX_set_options(ctx_.get(), SSL_OP_NO_SSLv3);

  // Enable automatic cert chaining. This is enabled by default in OpenSSL, but
  // disabled by default in BoringSSL. Enable it explicitly to make the
  // behavior match when Node is built with BoringSSL.
  SSL_CTX_clear_mode(ctx_.get(), SSL_MODE_NO_AUTO_CHAIN);

  // SSL session cache configuration
  SSL_CTX_set_session_cache_mode(ctx_.get(),
                                 SSL_SESS_CACHE_SERVER |
                                 SSL_SESS_CACHE_NO_INTERNAL |
                                 SSL_SESS_CACHE_NO_AUTO_CLEAR);

  SSL_CTX_set_min_proto_version(ctx_.get(), min_version);
  SSL_CTX_set_max_proto_version(ctx_.get(), max_version);

  // OpenSSL 1.1.0 changed the ticket key size, but the OpenSSL 1.0.x size was
  // exposed in the public API. To retain compatibility, install a callback
  // which restores the old algorithm.
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  if (RAND_bytes(ticket_key_.ticket_key_name_,
                 sizeof(ticket_key_.ticket_key_name_)) <= 0 ||
      RAND_bytes(ticket_key_.ticket_key_hmac_,
                 sizeof(ticket_key_.ticket_key_hmac_)) <= 0 ||
      RAND_bytes(ticket_key_.ticket_key_aes_,
                 sizeof(ticket_key_.ticket_key_aes_)) <= 0) {
    return ContextStatus::TicketKeyError;
  }
  SSL_CTX_set_tlsext_ticket_key_cb(ctx_.get(), TicketCompatibilityCallback);
#endif

  return ContextStatus::Ok;
}

static const char* const root_certs[] = {
#include "node_root_certs.h"  // NOLINT(build/include_order)
};

static const char system_cert_path[] = NODE_OPENSSL_SYSTEM_CERT_PATH;

//
// This callback is used to avoid the default passphrase callback in OpenSSL
// which will typically prompt for the passphrase. The prompting is designed
// for the OpenSSL CLI, but works poorly for Node.js because it involves
// synchronous interaction with the controlling terminal, something we never
// want, and use this function to avoid it.
static int NoPasswordCallback(char* buf, int size, int rwflag, void* u) {
  return 0;
}

static X509_STORE* NewRootCertStore() {
  static std::vector<X509*> root_certs_vector;
  static Mutex root_certs_vector_mutex;
  Mutex::ScopedLock lock(root_certs_vector_mutex);

  if (root_certs_vector.empty()) {
    for (size_t i = 0; i < arraysize(root_certs); i++) {
      X509* x509 =
          PEM_read_bio_X509(crypto::NodeBIO::NewFixed(root_certs[i],
                                              strlen(root_certs[i])).get(),
                            nullptr,   // no re-use of X509 structure
                            NoPasswordCallback,
                            nullptr);  // no callback data

      // Parse errors from the built-in roots are fatal.
      CHECK_NOT_NULL(x509);

      root_certs_vector.push_back(x509);
    }
  }

  X509_STORE* store = X509_STORE_new();
  if (*system_cert_path != '\0') {
    X509_STORE_load_locations(store, system_cert_path, nullptr);
  }
  if (per_process_opts->ssl_openssl_cert_store) {
    X509_STORE_set_default_paths(store);
  } else {
    for (X509* cert : root_certs_vector) {
      X509_up_ref(cert);
      X509_STORE_add_cert(store, cert);
    }
  }

  return store;
}

int SSL_CTX_get_issuer(SSL_CTX* ctx, X509* cert, X509** issuer) {
  X509_STORE* store = SSL_CTX_get_cert_store(ctx);
  DeleteFnPtr<X509_STORE_CTX, X509_STORE_CTX_free> store_ctx(
      X509_STORE_CTX_new());
  return store_ctx.get() != nullptr &&
         X509_STORE_CTX_init(store_ctx.get(), store, nullptr, nullptr) == 1 &&
         X509_STORE_CTX_get1_issuer(issuer, store_ctx.get(), cert) == 1;
}

int SSL_CTX_use_certificate_chain(SSL_CTX* ctx,
                                  X509Pointer&& x,
                                  STACK_OF(X509)* extra_certs,
                                  X509Pointer* cert,
                                  X509Pointer* issuer_) {
  CHECK(!*issuer_);
  CHECK(!*cert);
  X509* issuer = nullptr;

  int ret = SSL_CTX_use_certificate(ctx, x.get());

  if (ret) {
    // If we could set up our certificate, now proceed to
    // the CA certificates.
    SSL_CTX_clear_extra_chain_certs(ctx);

    for (int i = 0; i < sk_X509_num(extra_certs); i++) {
      X509* ca = sk_X509_value(extra_certs, i);

      // NOTE: Increments reference count on `ca`
      if (!SSL_CTX_add1_chain_cert(ctx, ca)) {
        ret = 0;
        issuer = nullptr;
        break;
      }
      // Note that we must not free r if it was successfully
      // added to the chain (while we must free the main
      // certificate, since its reference count is increased
      // by SSL_CTX_use_certificate).

      // Find issuer
      if (issuer != nullptr || X509_check_issued(ca, x.get()) != X509_V_OK)
        continue;

      issuer = ca;
    }
  }

  // Try getting issuer from a cert store
  if (ret) {
    if (issuer == nullptr) {
      ret = SSL_CTX_get_issuer(ctx, x.get(), &issuer);
      ret = ret < 0 ? 0 : 1;
      // NOTE: get_cert_store doesn't increment reference count,
      // no need to free `store`
    } else {
      // Increment issuer reference count
      issuer = X509_dup(issuer);
      if (issuer == nullptr) {
        ret = 0;
      }
    }
  }

  issuer_->reset(issuer);

  if (ret && x != nullptr) {
    cert->reset(X509_dup(x.get()));
    if (!*cert)
      ret = 0;
  }
  return ret;
}

int SSL_CTX_use_certificate_chain(SSL_CTX* ctx,
                                  BIOPointer&& in,
                                  X509Pointer* cert,
                                  X509Pointer* issuer) {
  // Just to ensure that `ERR_peek_last_error` below will return only errors
  // that we are interested in
  ERR_clear_error();

  X509Pointer x(
      PEM_read_bio_X509_AUX(in.get(), nullptr, NoPasswordCallback, nullptr));

  if (!x)
    return 0;

  unsigned long err = 0;  // NOLINT(runtime/int)

  StackOfX509 extra_certs(sk_X509_new_null());
  if (!extra_certs)
    return 0;

  while (X509Pointer extra {PEM_read_bio_X509(in.get(),
                                    nullptr,
                                    NoPasswordCallback,
                                    nullptr)}) {
    if (sk_X509_push(extra_certs.get(), extra.get())) {
      extra.release();
      continue;
    }

    return 0;
  }

  // When the while loop ends, it's usually just EOF.
  err = ERR_peek_last_error();
  if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
      ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
    ERR_clear_error();
  } else {
    // some real error
    return 0;
  }

  return SSL_CTX_use_certificate_chain(ctx,
                                       std::move(x),
                                       extra_certs.get(),
                                       cert,
                                       issuer);
}


void SecurityProvider::Context::ContextImpl::AddRootCerts() {
  if (root_cert_store == nullptr) {
    root_cert_store = NewRootCertStore();
  }

  X509_STORE_up_ref(root_cert_store);
  SSL_CTX_set_cert_store(ctx_.get(), root_cert_store);
}

ContextStatus SecurityProvider::Context::Init(int min_version,
                                              int max_version,
                                              std::string method_name) {
  return context_impl_->Init(min_version, max_version, method_name);
}

ContextStatus SecurityProvider::Context::ContextImpl::SetCert(Cert* cert,
    Environment* env) {
  BIOPointer bio(crypto::NodeBIO::NewFixed(cert->data_,
                                                   cert->length_,
                                                   env));
  if (!bio)
    return ContextStatus::CertSourceError;

  cert_.reset();
  issuer_.reset();

  int rv = SSL_CTX_use_certificate_chain(ctx_.get(),
                                         std::move(bio),
                                         &cert_,
                                         &issuer_);

  if (!rv) {
    return ContextStatus::CertError;
  }
  return ContextStatus::Ok;
}

ContextStatus SecurityProvider::Context::ContextImpl::SetKey(Key* key_data,
    std::string passphrase, bool has_passphrase, Environment* env) {
  ClearErrorOnReturn clear_error_on_return;
  BIOPointer bio(crypto::NodeBIO::NewFixed(key_data->data_,
                                                   key_data->length_,
                                                   env));
  if (!bio)
    return ContextStatus::PrivateKeySourceError;

    void* ps = has_passphrase ?
      static_cast<void*>(const_cast<char*>(passphrase.c_str())) : nullptr;
    EVPKeyPointer key(
      PEM_read_bio_PrivateKey(bio.get(),
                              nullptr,
                              PasswordCallback,
                              ps));

  if (!key) {
    return ContextStatus::PrivateKeyReadError;
    /*
    unsigned long err = ERR_get_error();  // NOLINT(runtime/int)
    if (!err) {
      return env->ThrowError("PEM_read_bio_PrivateKey");
    }
    return ThrowCryptoError(env, err);
    */
  }

  int rv = SSL_CTX_use_PrivateKey(ctx_.get(), key.get());

  if (!rv) {
    return ContextStatus::PrivateKeyUsageError;
    /*
    unsigned long err = ERR_get_error();  // NOLINT(runtime/int)
    if (!err)
      return env->ThrowError("SSL_CTX_use_PrivateKey");
    return ThrowCryptoError(env, err);
    */
  }

  return ContextStatus::Ok;
}

ContextStatus SecurityProvider::Context::ContextImpl::SetCiphers(
    std::string ciphers) {
  ClearErrorOnReturn clear_error_on_return;

  if (!SSL_CTX_set_cipher_list(ctx_.get(), ciphers.c_str())) {
    return ContextStatus::SetCiphersError;
    /*
    unsigned long err = ERR_get_error();  // NOLINT(runtime/int)
    if (!err) {
      return env->ThrowError("Failed to set ciphers");
    }
    return ThrowCryptoError(env, err);
    */
  }
  return ContextStatus::Ok;
}

ContextStatus SecurityProvider::Context::ContextImpl::AddCACert(Cert* cert_data,
    Environment* env) {
  ClearErrorOnReturn clear_error_on_return;

  BIOPointer bio(crypto::NodeBIO::NewFixed(cert_data->data_,
                                                   cert_data->length_,
                                                   env));
  if (!bio)
    return ContextStatus::CACertSourceError;

  X509_STORE* cert_store = SSL_CTX_get_cert_store(ctx_.get());
  while (X509* x509 = PEM_read_bio_X509(
      bio.get(), nullptr, NoPasswordCallback, nullptr)) {
    if (cert_store == root_cert_store) {
      cert_store = NewRootCertStore();
      SSL_CTX_set_cert_store(ctx_.get(), cert_store);
    }
    X509_STORE_add_cert(cert_store, x509);
    SSL_CTX_add_client_CA(ctx_.get(), x509);
    X509_free(x509);
  }

  return ContextStatus::Ok;
}

ContextStatus SecurityProvider::Context::ContextImpl::AddCRL(Data* crl_data,
    Environment* env) {
  ClearErrorOnReturn clear_error_on_return;
  BIOPointer bio(crypto::NodeBIO::NewFixed(crl_data->data_,
                                                   crl_data->length_,
                                                   env));
  if (!bio)
    return ContextStatus::CRLSourceError;

  DeleteFnPtr<X509_CRL, X509_CRL_free> crl(
      PEM_read_bio_X509_CRL(bio.get(), nullptr, NoPasswordCallback, nullptr));

  if (!crl)
    return ContextStatus::CRLParseError;

  X509_STORE* cert_store = SSL_CTX_get_cert_store(ctx_.get());
  if (cert_store == root_cert_store) {
    cert_store = NewRootCertStore();
    SSL_CTX_set_cert_store(ctx_.get(), cert_store);
  }

  X509_STORE_add_crl(cert_store, crl.get());
  X509_STORE_set_flags(cert_store,
                       X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

  return ContextStatus::Ok;
}

ContextStatus SecurityProvider::Context::ContextImpl::SetECDHCurve(
    std::string curve) {

  if (!SSL_CTX_set1_curves_list(ctx_.get(), curve.c_str()))
    return ContextStatus::ECDHSetError;
    //  return env->ThrowError("Failed to set ECDH curve");

  return ContextStatus::Ok;
}

ContextStatus SecurityProvider::Context::ContextImpl::SetDHParam(
    Data* dh_data, Environment* env) {
  ClearErrorOnReturn clear_error_on_return;
  DHPointer dh;
  {
    BIOPointer bio(crypto::NodeBIO::NewFixed(dh_data->data_,
                                                    dh_data->length_,
                                                    env));
    if (!bio)
      return ContextStatus::DHSourceError;

    dh.reset(PEM_read_bio_DHparams(bio.get(), nullptr, nullptr, nullptr));
  }

  // Invalid dhparam is silently discarded and DHE is no longer used.
  if (!dh)
    return ContextStatus::Ok;

  const BIGNUM* p;
  DH_get0_pqg(dh.get(), &p, nullptr, nullptr);
  const int size = BN_num_bits(p);
  if (size < 1024) {
    return ContextStatus::DH_PARAM_INVALID_LESS_THAN_1024;
    /*
    return THROW_ERR_INVALID_ARG_VALUE(
        env, "DH parameter is less than 1024 bits");
        */
  } else if (size < 2048) {
    return ContextStatus::DH_PARAM_INVALID_LESS_THAN_2048;
    /*
    args.GetReturnValue().Set(FIXED_ONE_BYTE_STRING(
        env->isolate(), "DH parameter is less than 2048 bits"));
        */
  }

  SSL_CTX_set_options(ctx_.get(), SSL_OP_SINGLE_DH_USE);
  int r = SSL_CTX_set_tmp_dh(ctx_.get(), dh.get());

  if (!r)
    return ContextStatus::DH_PARAM_SET_ERROR;
    //  return env->ThrowTypeError("Error setting temp DH parameter");

  return ContextStatus::Ok;
}

ContextStatus SecurityProvider::Context::ContextImpl::SetOptions(int64_t val) {
  SSL_CTX_set_options(ctx_.get(),
                      static_cast<long>(val));  // NOLINT(runtime/int)
  return ContextStatus::Ok;
}

ContextStatus SecurityProvider::Context::ContextImpl::SetSessionContextId(
    const unsigned char* id, unsigned int length) {
  int r = SSL_CTX_set_session_id_context(ctx_.get(), id, length);
  if (r != 1)
    return ContextStatus::SESSION_CONTEXT_ID_SET_ERROR;

  return ContextStatus::Ok;
  /*
  BUF_MEM* mem;
  Local<String> message;

  BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!bio) {
    message = FIXED_ONE_BYTE_STRING(args.GetIsolate(),
                                    "SSL_CTX_set_session_id_context error");
  } else {
    ERR_print_errors(bio.get());
    BIO_get_mem_ptr(bio.get(), &mem);
    message = OneByteString(args.GetIsolate(), mem->data, mem->length);
  }

  args.GetIsolate()->ThrowException(Exception::TypeError(message));

  return ContextStatus::Ok;
  */
}

ContextStatus SecurityProvider::Context::ContextImpl::SetSessionTimeout(
    uint32_t timeout) {
  SSL_CTX_set_timeout(ctx_.get(), timeout);
  return ContextStatus::Ok;
}

ContextStatus SecurityProvider::Context::ContextImpl::LoadPKCS12(
    Data* s, std::vector<char> pass, Environment* env) {
  bool ret = false;
  ClearErrorOnReturn clear_error_on_return;
  BIOPointer in(crypto::NodeBIO::NewFixed(s->data_,
                                                   s->length_,
                                                   env));
  if (!in) {
    return ContextStatus::PKCS12_SOURCE_ERROR;
    //  return env->ThrowError("Unable to load BIO");
  }

  issuer_.reset();
  cert_.reset();

  X509_STORE* cert_store = SSL_CTX_get_cert_store(ctx_.get());

  DeleteFnPtr<PKCS12, PKCS12_free> p12;
  EVPKeyPointer pkey;
  X509Pointer cert;
  StackOfX509 extra_certs;

  PKCS12* p12_ptr = nullptr;
  EVP_PKEY* pkey_ptr = nullptr;
  X509* cert_ptr = nullptr;
  STACK_OF(X509)* extra_certs_ptr = nullptr;
  if (d2i_PKCS12_bio(in.get(), &p12_ptr) &&
      (p12.reset(p12_ptr), true) &&  // Move ownership to the smart pointer.
      PKCS12_parse(p12.get(), pass.data(),
                   &pkey_ptr,
                   &cert_ptr,
                   &extra_certs_ptr) &&
      (pkey.reset(pkey_ptr), cert.reset(cert_ptr),
       extra_certs.reset(extra_certs_ptr), true) &&  // Move ownership.
      SSL_CTX_use_certificate_chain(ctx_.get(),
                                    std::move(cert),
                                    extra_certs.get(),
                                    &cert_,
                                    &issuer_) &&
      SSL_CTX_use_PrivateKey(ctx_.get(), pkey.get())) {
    // Add CA certs too
    for (int i = 0; i < sk_X509_num(extra_certs.get()); i++) {
      X509* ca = sk_X509_value(extra_certs.get(), i);

      if (cert_store == root_cert_store) {
        cert_store = NewRootCertStore();
        SSL_CTX_set_cert_store(ctx_.get(), cert_store);
      }
      X509_STORE_add_cert(cert_store, ca);
      SSL_CTX_add_client_CA(ctx_.get(), ca);
    }
    ret = true;
  }

  if (!ret) {
    return ContextStatus::PKCS12_LOAD_ERROR;
    /*
    unsigned long err = ERR_get_error();  // NOLINT(runtime/int)
    const char* str = ERR_reason_error_string(err);
    return env->ThrowError(str);
    */
  }

  return ContextStatus::Ok;
}
//
// Loads OpenSSL engine by engine id and returns it. The loaded engine
// gets a reference so remember the corresponding call to ENGINE_free.
#ifndef OPENSSL_NO_ENGINE
static ENGINE* LoadEngineById(const char* engine_id) {
  MarkPopErrorOnReturn mark_pop_error_on_return;

  ENGINE* engine = ENGINE_by_id(engine_id);

  if (engine == nullptr) {
    // Engine not found, try loading dynamically.
    engine = ENGINE_by_id("dynamic");
    if (engine != nullptr) {
      if (!ENGINE_ctrl_cmd_string(engine, "SO_PATH", engine_id, 0) ||
          !ENGINE_ctrl_cmd_string(engine, "LOAD", nullptr, 0)) {
        ENGINE_free(engine);
        engine = nullptr;
      }
    }
  }

  /*
  if (engine == nullptr) {
    int err = ERR_get_error();
    if (err != 0) {
      ERR_error_string_n(err, *errmsg, sizeof(*errmsg));
    } else {
      snprintf(*errmsg, sizeof(*errmsg),
               "Engine \"%s\" was not found", engine_id);
    }
  }
  */

  return engine;
}

// Helper for the smart pointer.
void ENGINE_free_fn(ENGINE* engine) { ENGINE_free(engine); }

ContextStatus SecurityProvider::Context::ContextImpl::SetClientCertEngine(
    std::string engine_id) {
  MarkPopErrorOnReturn mark_pop_error_on_return;

  DeleteFnPtr<ENGINE, ENGINE_free_fn> engine(
      LoadEngineById(engine_id.c_str()));

  if (!engine)
    return ContextStatus::CLIENT_ENGINE_LOAD_ERROR;
    //  return env->ThrowError(errmsg);

  // Note that this takes another reference to `engine`.
  int r = SSL_CTX_set_client_cert_engine(ctx_.get(), engine.get());
  if (r == 0)
    return ContextStatus::CLIENT_ENGINE_SET_ERROR;
    //  return ThrowCryptoError(env, ERR_get_error());

  return ContextStatus::Ok;
}
#endif  // !OPENSSL_NO_ENGINE

inline void* BufferMalloc(size_t length) {
  return per_process_opts->zero_fill_all_buffers ?
      node::UncheckedCalloc(length) :
      node::UncheckedMalloc(length);
}

ContextStatus Copy(X509* cert, SecurityProvider::Cert* out) {
  // i2d means convert from internal OpenSSL c struct to der format.
  int size = i2d_X509(cert, nullptr);
  void* data = BufferMalloc(size);
  if (data == nullptr) {
    return ContextStatus::MALLOC_ERROR;
  }

  unsigned char* serialized = reinterpret_cast<unsigned char*>(data);
  i2d_X509(cert, &serialized);
  out->data_ = reinterpret_cast<const char*>(serialized);
  out->length_ = size;
  return ContextStatus::Ok;
}

ContextStatus SecurityProvider::Context::ContextImpl::GetCertificate(
    SecurityProvider::Cert* out) {
  return Copy(cert_.get(), out);
}

ContextStatus SecurityProvider::Context::ContextImpl::GetIssuerCertificate(
    Cert* out) {
  return Copy(issuer_.get(), out);
}

ContextStatus SecurityProvider::Context::ContextImpl::SetTicketKey(
    TicketKey* key) {

  return ContextStatus::Ok;
}

TicketKey* SecurityProvider::Context::ContextImpl::GetTicketKey() {
  return &ticket_key_;
}

int SecurityProvider::Context::ContextImpl::TicketKeyCallback(SSL* ssl,
                      unsigned char* name,
                      unsigned char* iv,
                      EVP_CIPHER_CTX* ectx,
                      HMAC_CTX* hctx,
                      int enc) {
  Context* context = static_cast<Context*>(
      SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
  ContextImpl* ctx = context->context_impl_.get();

  TicketKeyCallbackResult on_callback_result =
    ctx->on_ticketkey_callback_(name, iv, enc != 0);
  if (on_callback_result.result < 0) {
    return on_callback_result.result;
  }

  HMAC_Init_ex(hctx,
               on_callback_result.hmac,
               on_callback_result.hmac_length,
               EVP_sha256(),
               nullptr);

  const unsigned char* aes_key =
      reinterpret_cast<unsigned char*>(on_callback_result.aes);
  if (enc) {
    EVP_EncryptInit_ex(ectx,
                       EVP_aes_128_cbc(),
                       nullptr,
                       aes_key,
                       iv);
  } else {
    EVP_DecryptInit_ex(ectx,
                       EVP_aes_128_cbc(),
                       nullptr,
                       aes_key,
                       iv);
  }

  return on_callback_result.result;
}

ContextStatus SecurityProvider::Context::ContextImpl::EnableTicketCallback(
    OnTicketKeyCallback on_ticketkey_callback) {
  on_ticketkey_callback_ = on_ticketkey_callback;
  SSL_CTX_set_app_data(ctx_.get(), this);
  SSL_CTX_set_tlsext_ticket_key_cb(ctx_.get(), TicketKeyCallback);
  return ContextStatus::Ok;
}

ContextStatus SecurityProvider::Context::ContextImpl::SetEngine(
    std::string name, uint32_t flags) {
  ClearErrorOnReturn clear_error_on_return;

  // Load engine.
  DeleteFnPtr<ENGINE, ENGINE_free_fn> engine(
      LoadEngineById(name.c_str()));
  if (!engine)
    return ContextStatus::ENGINE_LOAD_ERROR;

  int r = ENGINE_set_default(engine.get(), flags);
  ENGINE_free(engine.get());
  if (r == 0)
    return ContextStatus::ENGINE_SET_ERROR;
  return ContextStatus::Ok;
}

void SecurityProvider::Context::AddRootCerts() {
  return context_impl_->AddRootCerts();
}

ContextStatus SecurityProvider::Context::SetCert(Cert* cert) {
  return context_impl_->SetCert(cert, env_);
}

ContextStatus SecurityProvider::Context::SetKey(Key* key_data,
                                                std::string passphrase,
                                                bool has_passphrase) {
  return context_impl_->SetKey(key_data, passphrase, has_passphrase, env_);
}

ContextStatus SecurityProvider::Context::SetCiphers(std::string ciphers) {
  return context_impl_->SetCiphers(ciphers);
}

ContextStatus SecurityProvider::Context::AddCACert(Cert* cert_data) {
  return context_impl_->AddCACert(cert_data, env_);
}

ContextStatus SecurityProvider::Context::AddCRL(Data* crl_data) {
  return context_impl_->AddCRL(crl_data, env_);
}

ContextStatus SecurityProvider::Context::SetECDHCurve(std::string curve) {
  return context_impl_->SetECDHCurve(curve);
}

ContextStatus SecurityProvider::Context::SetDHParam(Data* dh_data) {
  return context_impl_->SetDHParam(dh_data, env_);
}

ContextStatus SecurityProvider::Context::SetOptions(int64_t val) {
  return context_impl_->SetOptions(val);
}

ContextStatus SecurityProvider::Context::SetSessionContextId(
    const unsigned char* id, unsigned int length) {
  return context_impl_->SetSessionContextId(id, length);
}

ContextStatus SecurityProvider::Context::SetSessionTimeout(uint32_t timeout) {
  return context_impl_->SetSessionTimeout(timeout);
}

ContextStatus SecurityProvider::Context::LoadPKCS12(Data* s,
                                                    std::vector<char> pass) {
  return context_impl_->LoadPKCS12(s, pass, env_);
}

ContextStatus SecurityProvider::Context::SetClientCertEngine(
    std::string engine_id) {
#ifndef OPENSSL_NO_ENGINE
  return context_impl_->SetClientCertEngine(engine_id);
#else
  return ContextStatus:Ok;
#endif
}

ContextStatus SecurityProvider::Context::GetCertificate(Cert* cert) {
  return context_impl_->GetCertificate(cert);
}

ContextStatus SecurityProvider::Context::GetIssuerCertificate(Cert* cert) {
  return context_impl_->GetIssuerCertificate(cert);
}

ContextStatus SecurityProvider::Context::SetTicketKey(TicketKey* key) {
  return context_impl_->SetTicketKey(key);
}

TicketKey* SecurityProvider::Context::GetTicketKey() {
  return context_impl_->GetTicketKey();
}

ContextStatus SecurityProvider::Context::EnableTicketCallback(
    OnTicketKeyCallback callback) {
  return context_impl_->EnableTicketCallback(callback);
}

ContextStatus SecurityProvider::Context::SetEngine(std::string name,
                                                   uint32_t flags) {
  return context_impl_->SetEngine(name, flags);
}

}  // namespace security

}  // namespace node
