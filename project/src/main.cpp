#include <iostream>
#include "chat_manage.h"

const char *PUBLIC_KEY_PATH = "./project/keys/rsa.public";
const char *PRIVATE_KEY_PATH = "./project/keys/rsa.private";

int main() {
    CHATING::Trinket trinket(PRIVATE_KEY_PATH);
    CHATING::Car car(PUBLIC_KEY_PATH);
    try {

        auto publicMessage = trinket.generateHandshake();  // The trinket begins handshake
        std::cout << "Trinket => Car: " << publicMessage << std::endl;

        publicMessage = car.processHandshake(publicMessage);  /* Part of the car handshake - a random value is generated for the signature */
        std::cout << "Car => Trinket: " << publicMessage << std::endl;

        publicMessage = trinket.processChallenge(publicMessage);  // The trinket signs the challenge value
        std::cout << "Trinket => Car: " << publicMessage << std::endl;

        auto isDoorOpen = car.verifySign(publicMessage);  // The car checks that the signature is correct
        std::cout << "Car: " << (isDoorOpen ? "doors open" : "doors remain closed") << std::endl;

    } catch (std::runtime_error &error) {
        std::cout << error.what() << std::endl;
        return 1;
    } catch (...) {
        std::cout << "some error.." << std::endl;
        return 1;
    }
    return 0;
}
