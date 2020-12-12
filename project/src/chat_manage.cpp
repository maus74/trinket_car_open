#include <stdexcept>
#include <cstring>
#include <openssl/rand.h>
#include <iostream>
#include "chat_manage.h"
#include "crypto.h"


namespace CHATING {
    const char *TRINKET_HELLO = "Hi car, give me permissions";
    size_t CHALLENGE_VALUE_SIZE = 25;

    Trinket::Trinket(const char *pathToPrivateKey) : _isWaitChallenge(false), _privateKeyPath(pathToPrivateKey) {
        std::cout << "The trinket uses a private key: " + std::string(_privateKeyPath) << std::endl;
    }

    std::string Trinket::generateHandshake() {
        _isWaitChallenge = true;
        return std::string(TRINKET_HELLO);
    }

    std::string Trinket::processChallenge(const std::string &challengeValue) {
        // if the hacker sent TRINKET_HELLO to the machine (and not the trinket), the trinket should not respond
        if (!_isWaitChallenge) {
            throw std::runtime_error("The challenge was not expected");
        }
        auto *privateKey = readPrivateKey(_privateKeyPath);

        std::vector<unsigned char> challengeData(challengeValue.length(), '\0');
        memcpy(challengeData.data(), challengeValue.data(), challengeData.size());
        unsigned char *signature = nullptr;
        size_t signatureLen = 0;

        signMessage(challengeData, &signature, &signatureLen, privateKey);
        std::string signatureString(reinterpret_cast<const char *>(signature), signatureLen);

        EVP_PKEY_free(privateKey);  // TODO: memory leak if a signMessage throws an exception
        OPENSSL_free(signature);
        return signatureString;
    }

    Car::Car(const char *pathToPublicKey) :
            _publicKey(pathToPublicKey), _challengeValue(CHALLENGE_VALUE_SIZE, '\0') {
        std::cout << "The car uses a public key: " + std::string(_publicKey) << std::endl;
    }

    std::string Car::processHandshake(const std::string &trinketHello) {
        if (trinketHello != TRINKET_HELLO) {
            throw std::runtime_error("wrong trinket hello");
        }

        /* OpenSSL is configured to automatically seed the CSPRNG
         * on first use using the operating systems's random generator. */
        int rc = RAND_bytes(_challengeValue.data(), _challengeValue.size());
        if (rc != 1) {
            throw std::runtime_error("RAND_bytes error");
        }

        return std::string(reinterpret_cast<const char *>(_challengeValue.data()), _challengeValue.size());
    }

    bool Car::verifySign(const std::string &challengeResponse) {
        auto *publicKey = readPublicKey(_publicKey);
        auto isSignatureValid = verifyMessage(_challengeValue,
                                              reinterpret_cast<const unsigned char *>(challengeResponse.data()),
                                              challengeResponse.size(), publicKey);
        EVP_PKEY_free(publicKey);
        return isSignatureValid;
    }
}