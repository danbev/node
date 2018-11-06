#ifndef SRC_NODE_SECURITY_SPI_H_
#define SRC_NODE_SECURITY_SPI_H_

#include <string>

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
