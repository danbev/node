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
    KeyPairGenerator(const uint32_t modulus_bits,
                     const uint32_t exponent,
                     PKEncodingType pub_encoding,
                     PKFormatType pub_format,
                     PKEncodingType pri_encoding,
                     PKFormatType pri_format,
                     std::string cipher_name,
                     std::string passphrase);
    virtual ~KeyPairGenerator() {}
    virtual bool LoadCipher() = 0;
    virtual bool HasKey() = 0;
    virtual bool Generate() = 0;
    virtual bool EncodeKeys(Key* public_key, Key* private_key) = 0;
    PKFormatType PublicKeyFormat() { return pub_format_; }
    PKFormatType PrivateKeyFormat() { return pri_format_; }
    PKEncodingType PublicKeyEncoding() { return pub_encoding_; }
    PKEncodingType PrivateKeyEncoding() { return pri_encoding_; }
    SecurityProvider::Status Status() { return status_; }

   protected:
    const uint32_t modulus_bits_;
    const uint32_t exponent_;
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
                        std::string passphrase);
    ~KeyPairGeneratorRSA() = default;
    bool LoadCipher();
    bool Generate();
    bool HasKey();
    bool EncodeKeys(Key* public_key, Key* private_key);
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
  static Status RandomBytes(size_t size, unsigned char* data);
  static bool VerifySpkac(const char* data, unsigned int len);
  static char* ExportPublicKey(const char* data, int len, size_t* size);
  static unsigned char* ExportChallenge(const char* data, int len);
  static std::unordered_map<std::string, double> Constants();
  static bool TimingSafeEquals(const void* a, const void* b, size_t len);
};


}  // namespace security

}  // namespace node

#endif  // SRC_NODE_SECURITY_SPI_H_
