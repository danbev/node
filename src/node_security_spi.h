#ifndef SRC_NODE_SECURITY_SPI_H_
#define SRC_NODE_SECURITY_SPI_H_

#include <string>
#include <vector>

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

  static void Init();
  static void InitProviderOnce();
  static std::string GetProviderName();
  static std::string GetVersion();
  static void UseCaExtraCerts(std::string certs);
  static std::vector<std::string> GetHashes();
  static std::vector<std::string> GetCiphers();
  static std::vector<std::string> GetCurves();
  static std::vector<std::string> GetErrors();
  static Status RandomBytes(size_t size, unsigned char* data);
  static bool VerifySpkac(const char* data, unsigned int len);
  static char* ExportPublicKey(const char* data, int len, size_t* size);
  static unsigned char* ExportChallenge(const char* data, int len);
};


}  // namespace security

}  // namespace node

#endif  // SRC_NODE_SECURITY_SPI_H_
