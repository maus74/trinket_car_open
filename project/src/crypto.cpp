#include <stdexcept>
#include <openssl/err.h>
#include <iostream>
#include "crypto.h"

namespace CHATING {

    const char *HASH_NAME = "SHA256";

    EVP_PKEY *readPublicKey(const char *keyPath) {

        FILE *fp = fopen(keyPath, "r");
        if (!fp) {
            throw std::runtime_error("Can't open public key file: " + std::string(keyPath));
        }

        BIO *bio = BIO_new(BIO_s_file()); // OpenSSL's answer to the C library's FILE *
        if (!bio) {
            fclose(fp);
            throw std::runtime_error("BIO is nullptr");
        }

        BIO_set_fp(bio, fp, BIO_NOCLOSE);
        EVP_PKEY *publicRSA = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);

        BIO_free(bio);
        fclose(fp);

        if (!publicRSA) {
            throw std::runtime_error("Can't read pubkey from bio");
        }
        return publicRSA;
    }

    EVP_PKEY *readPrivateKey(const char *keyPath) {

        FILE *fp = fopen(keyPath, "r");
        if (!fp) {
            throw std::runtime_error("Can't open private key file: " + std::string(keyPath));
        }

        EVP_PKEY *privateRSA = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        if (!privateRSA) {
            throw std::runtime_error("Can't read private key");
        }
        return privateRSA;
    }

    void signMessage(std::vector<unsigned char> &message, unsigned char **signature, size_t *signatureLen,
                     EVP_PKEY *privateRSA) {

        if (!signature || !signatureLen || !privateRSA) {
            throw std::runtime_error("Invalid arguments");
        }

        *signatureLen = 0;
        *signature = nullptr;

        EVP_MD_CTX *ctx = EVP_MD_CTX_create(); // create environment
        if (!ctx) {
            throw std::runtime_error("EVP_MD_CTX_create error");
        }

        const EVP_MD *md = EVP_get_digestbyname(HASH_NAME); // use type of SHA
        if (!md) {
            EVP_MD_CTX_destroy(ctx);
            throw std::runtime_error("EVP_get_digestbyname error");
        }

        int rc = EVP_DigestInit_ex(ctx, md, nullptr); // will typically be supplied by a function such as EVP_sha1(). If impl is NULL then the default implementation of digest type is used.
        if (rc != 1) {
            EVP_MD_CTX_destroy(ctx);
            throw std::runtime_error("EVP_DigestInit_ex error");
        }

        rc = EVP_DigestSignInit(ctx, nullptr, md, nullptr, privateRSA); // select type of algo
        if (rc != 1) {
            EVP_MD_CTX_destroy(ctx);
            throw std::runtime_error("EVP_DigestSignInit error");
        }

        rc = EVP_DigestSignUpdate(ctx, message.data(), message.size()); // submit to message
        if (rc != 1) {
            EVP_MD_CTX_destroy(ctx);
            throw std::runtime_error("EVP_DigestSignUpdate error");
        }

        size_t req = 0;
        rc = EVP_DigestSignFinal(ctx, nullptr, &req); // need for signature
        if (rc != 1) {
            EVP_MD_CTX_destroy(ctx);
            throw std::runtime_error("EVP_DigestSignFinal error");
        }

        *signature = reinterpret_cast<unsigned char *>(OPENSSL_malloc(req));
        if (!*signature) {
            EVP_MD_CTX_destroy(ctx);
            throw std::runtime_error("OPENSSL_malloc error");
        }

        *signatureLen = req;
        rc = EVP_DigestSignFinal(ctx, *signature, signatureLen);
        if (rc != 1 || *signatureLen != req) {
            EVP_MD_CTX_destroy(ctx);
            throw std::runtime_error("EVP_DigestSignFinal error");
        }
        EVP_MD_CTX_destroy(ctx);

    }

    bool verifyMessage(std::vector<unsigned char> &message, const unsigned char *signature, size_t signatureLen,
                       EVP_PKEY *publicRSA) {

        if (!signature || !signatureLen || !publicRSA) {
            throw std::runtime_error("Invalid arguments");
        }

        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        if (!ctx) {
            throw std::runtime_error("EVP_MD_CTX_create error");
        }

        const EVP_MD *md = EVP_get_digestbyname(HASH_NAME);
        if (!md) {
            EVP_MD_CTX_destroy(ctx);
            throw std::runtime_error("EVP_get_digestbyname error");
        }

        int rc = EVP_DigestInit_ex(ctx, md, nullptr);
        if (rc != 1) {
            EVP_MD_CTX_destroy(ctx);
            throw std::runtime_error("EVP_DigestInit_ex error");
        }

        rc = EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, publicRSA);
        if (rc != 1) {
            EVP_MD_CTX_destroy(ctx);
            throw std::runtime_error("EVP_DigestVerifyInit error");
        }

        rc = EVP_DigestVerifyUpdate(ctx, message.data(), message.size());
        if (rc != 1) {
            EVP_MD_CTX_destroy(ctx);
            throw std::runtime_error("EVP_DigestVerifyUpdate error");
        }

        rc = EVP_DigestVerifyFinal(ctx, signature, signatureLen);
        if (!(rc == 1 || rc == 0)) {
            EVP_MD_CTX_destroy(ctx);
            throw std::runtime_error("EVP_DigestVerifyFinal error: "
                                     + std::string(ERR_reason_error_string(ERR_peek_last_error())));
        }
        EVP_MD_CTX_destroy(ctx);
        return rc != 0;

    }
}
