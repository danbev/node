#ifndef SRC_NODE_SECURITY_SPI_H_
#define SRC_NODE_SECURITY_SPI_H_

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

  class Key {
   public:
    char* data_;
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
