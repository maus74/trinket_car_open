#ifndef HW2_CRYPTO_H
#define HW2_CRYPTO_H

#include <string>
#include <vector>
#include <openssl/pem.h>

namespace CHATING {
    /**
     * Reading the key file into a special structure
     * @param keyPath - path to public key file
     * @return pointer to EVP_PKEY or nullptr. Remember to use EVP_PKEY_free.
     */
    EVP_PKEY *readPublicKey(const char *keyPath);
    /**
     * Reading the key file into a special structure
     * @param keyPath - path to public key file
     * @return pointer to EVP_PKEY or nullptr. Remember to use EVP_PKEY_free.
     */
    EVP_PKEY *readPrivateKey(const char *keyPath);
    /**
     * Generates a signature for a message.
     * @param message
     * @param signature Remember to use OPENSSL_free.
     * @param signatureLen
     * @param privateRSA
     */
    void signMessage(std::vector<unsigned char> &message, unsigned char **signature, size_t *signatureLen, EVP_PKEY *privateRSA);
    /**
     * Verify the message signature.
     * @param message
     * @param signature
     * @param signatureLen
     * @param publicRSA
     * @return whether the signature is correct
     */
    bool verifyMessage(std::vector<unsigned char> &message, const unsigned char *signature, size_t signatureLen, EVP_PKEY *publicRSA);

}

#endif