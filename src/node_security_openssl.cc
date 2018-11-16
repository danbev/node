#include "node_security_spi.h"
#if HAVE_OPENSSL
#include "node_crypto.h"
#include "node_crypto_bio.h"
#endif
#include "v8.h"
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include "util.h"

namespace node {
namespace security {

void SecurityProvider::Init() {
#ifdef NODE_FIPS_MODE
  // In the case of FIPS builds we should make sure
  // the random source is properly initialized first.
  OPENSSL_init();
#endif  // NODE_FIPS_MODE
  // V8 on Windows doesn't have a good source of entropy. Seed it from
  // OpenSSL's pool.
  v8::V8::SetEntropySource(node::crypto::EntropySource);
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
  crypto::SSLCtxPointer ctx(SSL_CTX_new(TLS_method()));
  CHECK(ctx);

  crypto::SSLPointer ssl(SSL_new(ctx.get()));
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

bool SecurityProvider::VerifySpkac(const char* data, unsigned int len) {
  node::crypto::NetscapeSPKIPointer spki(NETSCAPE_SPKI_b64_decode(data, len));
  if (!spki)
    return false;

  node::crypto::EVPKeyPointer pkey(X509_PUBKEY_get(spki->spkac->pubkey));
  if (!pkey)
    return false;

  return NETSCAPE_SPKI_verify(spki.get(), pkey.get()) > 0;
}

char* SecurityProvider::ExportPublicKey(const char* data,
                                        int len,
                                        size_t* size) {
  char* buf = nullptr;

  node::crypto::BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!bio)
    return nullptr;

  node::crypto::NetscapeSPKIPointer spki(NETSCAPE_SPKI_b64_decode(data, len));
  if (!spki)
    return nullptr;

  node::crypto::EVPKeyPointer pkey(NETSCAPE_SPKI_get_pubkey(spki.get()));
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
  node::crypto::NetscapeSPKIPointer sp(NETSCAPE_SPKI_b64_decode(data, len));
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

// Pop errors from OpenSSL's error stack that were added
// between when this was constructed and destructed.
struct MarkPopErrorOnReturn {
  MarkPopErrorOnReturn() { ERR_set_mark(); }
  ~MarkPopErrorOnReturn() { ERR_pop_to_mark(); }
};

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
    crypto::EVPKeyPointer* pkey,
    const crypto::BIOPointer& bp,
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

static ParsePublicKeyResult ParsePublicKey(crypto::EVPKeyPointer* pkey,
                                           const char* key_pem,
                                           int key_pem_len) {
  crypto::BIOPointer bp(BIO_new_mem_buf(const_cast<char*>(key_pem),
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
        crypto::X509Pointer x509(d2i_X509(nullptr, p, l));
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
  crypto::EVPKeyPointer pkey;
  crypto::BIOPointer bp(BIO_new_mem_buf(const_cast<char*>(key_pem),
                                        key_pem_len));
  if (bp == nullptr)
    return false;

  pkey.reset(PEM_read_bio_PrivateKey(bp.get(),
                                     nullptr,
                                     PasswordCallback,
                                     const_cast<char*>(passphrase)));
  if (pkey == nullptr)
    return false;

  crypto::EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
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
  crypto::EVPKeyPointer pkey;
  crypto::BIOPointer bp(BIO_new_mem_buf(const_cast<char*>(key_pem),
                                        key_pem_len));
  if (bp == nullptr)
    return false;

  pkey.reset(PEM_read_bio_PrivateKey(bp.get(),
                                     nullptr,
                                     PasswordCallback,
                                     const_cast<char*>(passphrase)));
  if (pkey == nullptr)
    return false;

  crypto::EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
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
  crypto::EVPKeyPointer pkey;

  // Check if this is a PKCS#8 or RSA public key before trying as X.509 and
  // private key.
  ParsePublicKeyResult pkeyres = ParsePublicKey(&pkey, key_pem, key_pem_len);
  if (pkeyres == kParsePublicFailed)
    return false;

  if (pkey == nullptr) {
    // Private key fallback.
    crypto::BIOPointer bp(BIO_new_mem_buf(const_cast<char*>(key_pem),
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

  crypto::EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
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
  crypto::EVPKeyPointer pkey;

  // Check if this is a PKCS#8 or RSA public key before trying as X.509 and
  // private key.
  ParsePublicKeyResult pkeyres = ParsePublicKey(&pkey, key_pem, key_pem_len);
  if (pkeyres == kParsePublicFailed)
    return false;

  if (pkey == nullptr) {
    // Private key fallback.
    crypto::BIOPointer bp(BIO_new_mem_buf(const_cast<char*>(key_pem),
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

  crypto::EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
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

inline void CheckEntropy() {
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

class KeyPairGenerationConfig {
 public:
  virtual crypto::EVPKeyCtxPointer Setup() = 0;
  virtual bool Configure(const crypto::EVPKeyCtxPointer& ctx) {
    return true;
  }
  virtual ~KeyPairGenerationConfig() {}
};

class RSAKeyPairGenerationConfig : public KeyPairGenerationConfig {
 public:
  RSAKeyPairGenerationConfig(unsigned int modulus_bits, unsigned int exponent)
    : modulus_bits_(modulus_bits), exponent_(exponent) {}

  crypto::EVPKeyCtxPointer Setup() override {
    return crypto::EVPKeyCtxPointer(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  }

  bool Configure(const crypto::EVPKeyCtxPointer& ctx) override {
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), modulus_bits_) <= 0)
      return false;

    // 0x10001 is the default RSA exponent.
    if (exponent_ != 0x10001) {
      crypto::BignumPointer bn(BN_new());
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

    crypto::EVPKeyCtxPointer Setup() override {
      crypto::EVPKeyCtxPointer param_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_DSA,
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

    crypto::EVPKeyCtxPointer key_ctx(EVP_PKEY_CTX_new(params, nullptr));
    EVP_PKEY_free(params);
    return key_ctx;
  }

 private:
  const unsigned int modulus_bits_;
  const int divisor_bits_;
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
  CheckEntropy();

  // Create the key generation context.
  crypto::EVPKeyCtxPointer ctx = config->Setup();
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

bool SecurityProvider::KeyPairGenerator::EncodeKeys(Key* public_key,
                                                    Key* private_key) const {
  //  EVP_PKEY* pkey = pkey_.get();
  EVP_PKEY* pkey = static_cast<EVP_PKEY*>(pkey_);
  crypto::BIOPointer bio(BIO_new(BIO_s_mem()));
  CHECK(bio);

  // Encode the public key.
  if (pub_encoding_ == security::PK_ENCODING_PKCS1) {
    // PKCS#1 is only valid for RSA keys.
    CHECK_EQ(EVP_PKEY_id(pkey), EVP_PKEY_RSA);
    crypto::RSAPointer rsa(EVP_PKEY_get1_RSA(pkey));
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

    crypto::RSAPointer rsa(EVP_PKEY_get1_RSA(pkey));
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

    crypto::ECKeyPointer ec_key(EVP_PKEY_get1_EC_KEY(pkey));
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

}  // namespace security

}  // namespace node
