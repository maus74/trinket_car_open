#ifndef HW2_CHAT_MANAGE_H
#define HW2_CHAT_MANAGE_H

#include <string>
#include <vector>

namespace CHATING {
    class Trinket {
    public:
        /**
         * @param pathToPrivateKey - path to trinket private key file
         */
        explicit Trinket(const char *pathToPrivateKey);

        /**
         * Make "open door" request
         * @return "open door" string
         */
        std::string generateHandshake();

        /**
         * Trinket makes a signature for the received challenge value
         * @return only the signature
         */
        std::string processChallenge(const std::string &challengeValue);

    private:
        bool _isWaitChallenge;
        const char *_privateKeyPath;
    };


    class Car {
    public:
        /**
         * @param pathToPublicKey - path to trinket public key file
         */
        explicit Car(const char *pathToPublicKey);

        /**
         * The car starts the challenge: generate a random value that the trinket must sign
         * @return a random value for the trinket challenge
         */
        std::string processHandshake(const std::string &trinketHello);

        /**
         * Checking that the challenge value signature made by a true trinket
         * @return is the challenge successful
         */
        bool verifySign(const std::string &challengeResponse);

    private:
        const char * _publicKey;
        std::vector<unsigned char> _challengeValue;
    };


}

#endif
