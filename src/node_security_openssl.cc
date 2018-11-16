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

}  // namespace security

}  // namespace node
