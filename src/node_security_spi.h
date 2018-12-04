#ifndef SRC_NODE_SECURITY_SPI_H_
#define SRC_NODE_SECURITY_SPI_H_

#include "env.h"
#include <string>
#include <vector>
#include <unordered_map>

namespace node {
namespace security {

#ifndef SECURITY_SPI_VERSION
#ifdef SECURITY_SPI_EXPERIMENTAL
#define SECURITY_SPI_VERSION 2147483647
#else
// The baseline version for Security SPI
#define SECURITY_SPI_VERSION 1
#endif
#endif

enum PKEncodingType {
  // RSAPublicKey / RSAPrivateKey according to PKCS#1.
  PK_ENCODING_PKCS1,
  // PrivateKeyInfo or EncryptedPrivateKeyInfo according to PKCS#8.
  PK_ENCODING_PKCS8,
  // SubjectPublicKeyInfo according to X.509.
  PK_ENCODING_SPKI,
  // ECPrivateKey according to SEC1.
  PK_ENCODING_SEC1
};

enum PKFormatType {
  PK_FORMAT_DER,
  PK_FORMAT_PEM
};

struct KeyPairEncodingConfig {
  PKEncodingType type_;
  PKFormatType format_;
};

class SecurityProvider {
 public:
  enum class Status { ok, error };

  class PBKDF2 {
   public:
    PBKDF2(std::vector<char> pass,
           std::vector<char> salt,
           uint32_t iteration_count,
           std::string digest_name,
           unsigned char* keybuf,
           size_t keybuf_size);
    virtual ~PBKDF2() {}
    virtual bool Generate();
    virtual bool HasDigest();
    virtual void Cleanup();
    SecurityProvider::Status Status() { return status_; }
   private:
    std::vector<char> pass_;
    std::vector<char> salt_;
    uint32_t iteration_count_;
    std::string digest_name_;
    unsigned char* keybuf_;
    size_t keybuf_size_;
    SecurityProvider::Status status_;
    void* digest_;
  };

  class KeyCipher {
   public:
    using CipherFunction = bool (*) (const char*,
                                     int,
                                     const char*,
                                     int,
                                     const unsigned char*,
                                     int,
                                     unsigned char**,
                                     size_t*);

    static bool PublicEncrypt(const char* key_pem,
                              int key_pem_len,
                              const char* passphrase,
                              int padding,
                              const unsigned char* data,
                              int len,
                              unsigned char** out,
                              size_t* out_len);

    static bool PublicDecrypt(const char* key_pem,
                              int key_pem_len,
                              const char* passphrase,
                              int padding,
                              const unsigned char* data,
                              int len,
                              unsigned char** out,
                              size_t* out_len);

    static bool PrivateEncrypt(const char* key_pem,
                              int key_pem_len,
                              const char* passphrase,
                              int padding,
                              const unsigned char* data,
                              int len,
                              unsigned char** out,
                              size_t* out_len);

    static bool PrivateDecrypt(const char* key_pem,
                               int key_pem_len,
                               const char* passphrase,
                               int padding,
                               const unsigned char* data,
                               int len,
                               unsigned char** out,
                               size_t* out_len);
  };

  class Data {
   public:
     const char* data_;
     size_t length_;
  };

  class Key {
   public:
     const char* data_;
     size_t length_;
  };

  class Cert {
   public:
     const char* data_;
     size_t length_;
  };

  class KeyPairGenerator {
   public:
    KeyPairGenerator(PKEncodingType pub_encoding,
                     PKFormatType pub_format,
                     PKEncodingType pri_encoding,
                     PKFormatType pri_format,
                     std::string cipher_name,
                     std::string passphrase) : pub_encoding_(pub_encoding),
                                               pub_format_(pub_format),
                                               pri_encoding_(pri_encoding),
                                               pri_format_(pri_format),
                                               cipher_name_(cipher_name),
                                               passphrase_(passphrase) {}
    virtual ~KeyPairGenerator() {}
    bool LoadCipher();
    bool HasKey() const;
    bool EncodeKeys(Key* public_key, Key* private_key) const;
    virtual bool Generate() = 0;
    PKFormatType PublicKeyFormat() { return pub_format_; }
    PKFormatType PrivateKeyFormat() { return pri_format_; }
    PKEncodingType PublicKeyEncoding() { return pub_encoding_; }
    PKEncodingType PrivateKeyEncoding() { return pri_encoding_; }
    SecurityProvider::Status Status() { return status_; }

   protected:
    PKEncodingType pub_encoding_;
    PKFormatType pub_format_;
    PKEncodingType pri_encoding_;
    PKFormatType pri_format_;
    std::string cipher_name_;
    std::string passphrase_;
    void* pkey_;
    void* cipher_;
    SecurityProvider::Status status_;
  };

  class KeyPairGeneratorRSA : public KeyPairGenerator {
   public:
    KeyPairGeneratorRSA(const uint32_t modulus_bits,
                        const uint32_t exponent,
                        PKEncodingType pub_encoding,
                        PKFormatType pub_format,
                        PKEncodingType pri_encoding,
                        PKFormatType pri_format,
                        std::string cipher_name,
                        std::string passphrase) :
        KeyPairGenerator(pub_encoding, pub_format, pri_encoding, pri_format,
                         cipher_name, passphrase), modulus_bits_(modulus_bits),
                         exponent_(exponent) {}
    ~KeyPairGeneratorRSA() = default;
    bool Generate();
   private:
    const uint32_t modulus_bits_;
    const uint32_t exponent_;
  };

  class KeyPairGeneratorDSA : public KeyPairGenerator {
   public:
    KeyPairGeneratorDSA(const uint32_t modulus_bits,
                        const uint32_t divisor_bits,
                        PKEncodingType pub_encoding,
                        PKFormatType pub_format,
                        PKEncodingType pri_encoding,
                        PKFormatType pri_format,
                        std::string cipher_name,
                        std::string passphrase) :
        KeyPairGenerator(pub_encoding, pub_format, pri_encoding, pri_format,
                         cipher_name, passphrase), modulus_bits_(modulus_bits),
                         divisor_bits_(divisor_bits) {}
    ~KeyPairGeneratorDSA() = default;
    bool Generate();
   private:
    const uint32_t modulus_bits_;
    const uint32_t divisor_bits_;
  };

  class KeyPairGeneratorEC : public KeyPairGenerator {
   public:
    KeyPairGeneratorEC(std::string curve_name,
                       uint32_t param_encoding,
                       PKEncodingType pub_encoding,
                       PKFormatType pub_format,
                       PKEncodingType pri_encoding,
                       PKFormatType pri_format,
                       std::string cipher_name,
                       std::string passphrase) :
        KeyPairGenerator(pub_encoding, pub_format, pri_encoding, pri_format,
                         cipher_name, passphrase), curve_name_(curve_name),
                         param_encoding_(param_encoding) {}
    ~KeyPairGeneratorEC() = default;
    bool Generate();
    bool LoadCurve();
   private:
    std::string curve_name_;
    uint32_t curve_id_;
    uint32_t param_encoding_;
  };

  class TicketKey {
   public:
     unsigned char ticket_key_name_[16];
     unsigned char ticket_key_aes_[16];
     unsigned char ticket_key_hmac_[16];
  };

  class TicketKeyCallbackResult {
   public:
     unsigned char* name;
     unsigned char* iv;
     unsigned char* aes;
     uint32_t aes_length;
     unsigned char* hmac;
     uint32_t hmac_length;
     int result;
  };

  typedef std::function<TicketKeyCallbackResult(unsigned char* name,
                             unsigned char* iv,
                             bool b)> OnTicketKeyCallback;

  class Context {
   public:
    enum class ContextStatus {
      Ok,
      MethodDisabled,
      UnknownMethod,
      TicketKeyError,
      CertSourceError,
      CertError,
      PrivateKeySourceError,
      PrivateKeyReadError,
      PrivateKeyUsageError,
      SetCiphersError,
      CACertSourceError,
      CRLSourceError,
      CRLParseError,
      ECDHSetError,
      DHSourceError,
      DH_PARAM_INVALID_LESS_THAN_1024,
      DH_PARAM_INVALID_LESS_THAN_2048,
      DH_PARAM_SET_ERROR,
      SESSION_CONTEXT_ID_SET_ERROR,
      PKCS12_SOURCE_ERROR,
      PKCS12_LOAD_ERROR,
      CLIENT_ENGINE_SET_ERROR,
      CLIENT_ENGINE_LOAD_ERROR,
      ENGINE_SET_ERROR,
      ENGINE_LOAD_ERROR,
      MALLOC_ERROR
    };
    explicit Context(Environment* env);
    ~Context();
    ContextStatus Init(int min_version, int max_version,
                       std::string method_name);
    void AddRootCerts();
    ContextStatus SetCert(Cert* cert_data);
    ContextStatus SetKey(Key* key_data,
                         std::string passphrase,
                         bool has_passphrase);
    ContextStatus SetCiphers(std::string ciphers);
    ContextStatus AddCACert(Cert* cert_data);
    ContextStatus AddCRL(Data* crl_data);
    ContextStatus SetECDHCurve(std::string curve);
    ContextStatus SetDHParam(Data* dh_data);
    ContextStatus SetOptions(int64_t val);
    ContextStatus SetSessionContextId(const unsigned char* id,
                                      unsigned int length);
    ContextStatus SetSessionTimeout(uint32_t timeout);
    ContextStatus LoadPKCS12(Data* something, std::vector<char> pass);
    ContextStatus SetClientCertEngine(std::string engine_id);
    ContextStatus GetCertificate(Cert* cert);
    ContextStatus GetIssuerCertificate(Cert* cert);
    ContextStatus SetTicketKey(TicketKey* key);
    TicketKey* GetTicketKey();
    ContextStatus EnableTicketCallback(OnTicketKeyCallback callback);
    ContextStatus SetEngine(std::string name, uint32_t flags);
    Environment* GetEnv() { return env_; }
    const Context operator=(const Context&) = delete;
    Context(const Context&) = delete;

   private:
     class ContextImpl;
     std::unique_ptr<ContextImpl> context_impl_;
     Environment* env_;
  };

  class Hash {
   public:
    enum class Status {
      Ok,
      DigestNotFound,
      DigestInitError,
      HashNotAvailable
    };
    explicit Hash(Environment* env);
    ~Hash();
    Status Init(const char* hash_type);
    Status Update(const char* data, int len);
    Status Digest(unsigned char* data, unsigned int* len);

   private:
     class HashImpl;
     std::unique_ptr<HashImpl> hash_impl_;
     Environment* env_;
  };

  class SignBase {
   public:
    enum class Status {
      SignOk,
      SignUnknownDigest,
      SignInit,
      SignNotInitialised,
      SignUpdate,
      SignPrivateKey,
      SignPublicKey
    };
    SignBase();
    ~SignBase();
    Status Init(const char* sign_type);
    Status Update(const char* data, int len);

   protected:
     class SignBaseImpl;
     std::unique_ptr<SignBaseImpl> base_impl_;
  };

  class Sign : public SignBase {
   public:
    struct SignResult {
      Status status_;
      MallocedBuffer<unsigned char> signature_;

      explicit SignResult(
          Status status,
          MallocedBuffer<unsigned char>&& sig = MallocedBuffer<unsigned char>())
        : status_(status), signature_(std::move(sig)) {}
    };
    Sign();
    ~Sign();
    SignResult SignFinal(const char* key_pem,
                         int key_pem_len,
                         const char* passphrase,
                         int padding,
                         int saltlen);
  };

  class Verify : public SignBase {
   public:
    Verify();
    ~Verify();
    Status VerifyFinal(const char* key_pem,
                       int key_pem_len,
                       const char* sig,
                       int siglen,
                       int padding,
                       int saltlen,
                       bool* verify_result);
  };

  static void Init();
  static void InitProviderOnce();
  static std::string GetProviderName();
  static std::string GetVersion();
  static void UseCaExtraCerts(std::string certs);
  static std::vector<std::string> GetHashes();
  static std::vector<std::string> GetCiphers();
  static std::vector<std::string> GetTLSCiphers();
  static std::vector<std::string> GetCurves();
  static std::vector<std::string> GetErrors();
  static std::string GetErrorStr();
  static std::string GetErrorStr(uint32_t id);
  static uint32_t GetError();
  static Status RandomBytes(size_t size, unsigned char* data);
  static bool VerifySpkac(const char* data, unsigned int len);
  static char* ExportPublicKey(const char* data, int len, size_t* size);
  static unsigned char* ExportChallenge(const char* data, int len);
  static std::unordered_map<std::string, double> Constants();
  static bool TimingSafeEquals(const void* a, const void* b, size_t len);
#ifdef NODE_FIPS_MODE
  static bool HasFipsSupport();
  static Status SetFipsSupport(bool enable);
#endif /* NODE_FIPS_MODE */
  static void CheckEntropy();
  static bool EntropySource(unsigned char* buffer, size_t length);
};


}  // namespace security

}  // namespace node

#endif  // SRC_NODE_SECURITY_SPI_H_
