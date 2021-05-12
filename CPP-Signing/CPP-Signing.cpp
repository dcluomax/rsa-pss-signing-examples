#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <assert.h>

std::string privateKey = "-----BEGIN RSA PRIVATE KEY-----" "\n"
"MIIEpQIBAAKCAQEAnsxe6HMLAqzdRe/aAkTecba5L8uUnWC0xu3j1XyMW2U+wzYo" "\n"
"OVF5dmC6HTNp6wK7y7K0PLqRtYf3ofIBpAHPFC6hTRZepXQeNjwUvWiLI75wcB3F" "\n"
"bELTzqBXMTptk3vRaO1okgeiDpMQLJzYL5mat879d0UrUDSHMtTLm7fE9wjEGyze" "\n"
"LP+t9VxLPEpLlATdGdaaFyoUIIwYN/BFBB9SNa9VCMTjHSG6h31qj7RmTtDzCGuj" "\n"
"f668JyvHiNZv7jAs1OeynNw42/OS4WBD1NBxLHqsJxpNqkwhTEE1yYzdw24uIw43" "\n"
"C2gfuvScOGoAvAd3E8by95UBwYVP4p5C0UX6swIDAQABAoIBAQCZ9uEWU2SbhWtN" "\n"
"Ac7IYGmkq1tGAgbnx/m+3qwGM6oKe1GtB/dcC6jOo94PrefGGnJmf6/NKb9Y2Km6" "\n"
"dOAuWiqjEMsH6OZ/WORqBTq+onw1fdGaguMFoo2mS0P+0P2o/2X8bCL1Yz03EFOg" "\n"
"Tbo1/KJMEP8kAwaJz0Q+fp+jLTxlnq0Q1VPo0wEjZlj3fDSNxMRNO6Se3d6Zx27o" "\n"
"9S1grmp/NmUI0+Qby2McflQPaB0UalAisrOZZPAyqOSq13T+OGn5GsfWHI8O3L6q" "\n"
"zkXjzNBY4VHitkR4t0BULPopExtZIKZgsC4AkWVI3YJaQFIMxo9fVhOI4ftSTJVp" "\n"
"tHGqE1xRAoGBAM+C6MI0EazN213d1Ix0BsFzTbTnWmYtKHcIEBlgAhndRDjcdTmd" "\n"
"0pfLAa7L0Pbe0Eqfi8Yg+ysfyqXkzxD/8LV0vtnpeoO6VjC5i1fBbM7SR4MrOh5/" "\n"
"Olybt/IukEijKeUsxbdW2BM+v9zVBc8g3nkAEvSl6jF+XLsq9HrS0bYVAoGBAMPn" "\n"
"gOa+K2dvyG3wDqP8o2kiDQaAzg3SfVa/ri/8Fqoa3tEs7YpIfrA4o1e6+dd51dpz" "\n"
"pOnmMmlxcjNDj9w4dhzTVz8sqfz1q0jnma3vS8yNMrjOE0oLbZbYA3L56KubIUbF" "\n"
"5QpTivT4zGl+mXIWT5y9pkSJpVE/jp/T6fiajyenAoGAH63XhNZYIG5o3+KesTaB" "\n"
"VYUZxtVO6qxYMhvMAWOzzmkGIjwdtUcPwFagkiPRae7IE6xZtUyRq5q14C+XIPxB" "\n"
"riH9hNzs9DE9OUEKMcJ4rvZRLogp3kAEE+E96r4LDtvB6Je2M3ARmpaIydjHg0B8" "\n"
"VjKZsjmmEBo/Y9+B5UJL+6UCgYEAmCRljk3ohYdhwEesBx1Ah3ijZwaHgGKVZtas" "\n"
"X6XGsEr3+rmKrVdJ1G/YI10ZhYegVuxzChf11L//MeLpidzrlc1oN67nQYZFhPQg" "\n"
"/N0YH/8UgkPA5UNk075lR1jgos1ylXVBQLjK9R94GQHyB5FeONtsklPX6PaUPHom" "\n"
"fiUCwocCgYEAmkpKIExrP6kWl9ZbR/G+YYxIFzB2IQjP1oIQ6WwRpiv/PmvlDwGt" "\n"
"evCTfzAE+QH+3erp4soAFeXtJ+4ZE7OGkKyDz45ef3uKjXFjnBiv0vH2/frAYdcs" "\n"
"WGk4W/AbbFW+ovlny4IbyMG64LkIiGFCNTs6EkUVGZqR3gF8KXCpmQ4=" "\n"
"-----END RSA PRIVATE KEY-----\n\0";

std::string publicKey = "-----BEGIN PUBLIC KEY-----" "\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnsxe6HMLAqzdRe/aAkTe" "\n"
"cba5L8uUnWC0xu3j1XyMW2U+wzYoOVF5dmC6HTNp6wK7y7K0PLqRtYf3ofIBpAHP" "\n"
"FC6hTRZepXQeNjwUvWiLI75wcB3FbELTzqBXMTptk3vRaO1okgeiDpMQLJzYL5ma" "\n"
"t879d0UrUDSHMtTLm7fE9wjEGyzeLP+t9VxLPEpLlATdGdaaFyoUIIwYN/BFBB9S" "\n"
"Na9VCMTjHSG6h31qj7RmTtDzCGujf668JyvHiNZv7jAs1OeynNw42/OS4WBD1NBx" "\n"
"LHqsJxpNqkwhTEE1yYzdw24uIw43C2gfuvScOGoAvAd3E8by95UBwYVP4p5C0UX6" "\n"
"swIDAQAB" "\n"
"-----END PUBLIC KEY-----\n\0";

RSA* createPrivateRSA(std::string key) {
    RSA* rsa = NULL;
    const char* c_string = key.c_str();
    BIO* keybio = BIO_new_mem_buf((void*)c_string, -1);
    if (keybio == NULL) {
        return 0;
    }
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    return rsa;
}

RSA* createPublicRSA(std::string key) {
    RSA* rsa = NULL;
    BIO* keybio;
    const char* c_string = key.c_str();
    keybio = BIO_new_mem_buf((void*)c_string, -1);
    if (keybio == NULL) {
        return 0;
    }
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    return rsa;
}

bool RSASign(RSA* rsa,
    const unsigned char* Msg,
    size_t MsgLen,
    unsigned char** EncMsg,
    size_t* MsgLenEnc) {
    EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
    EVP_PKEY* priKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);

    EVP_PKEY_CTX* keygen_ctx = nullptr;

    if (EVP_DigestSignInit(m_RSASignCtx, &keygen_ctx, EVP_sha256(), NULL, priKey) <= 0) {
        return false;
    }

    EVP_PKEY_CTX_set_rsa_padding(keygen_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(keygen_ctx, RSA_PSS_SALTLEN_AUTO);

    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <= 0) {
        return false;
    }
    *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
    if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
        return false;
    }

    EVP_MD_CTX_free(m_RSASignCtx);
    return true;
}

bool RSAVerifySignature(RSA* rsa,
    unsigned char* MsgHash,
    size_t MsgHashLen,
    const char* Msg,
    size_t MsgLen,
    bool* Authentic) {
    *Authentic = false;
    int r = 0;
    EVP_PKEY* pubKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

    EVP_PKEY_CTX* keygen_ctx = nullptr;
  
    if (EVP_DigestVerifyInit(m_RSAVerifyCtx, &keygen_ctx, EVP_sha256(), NULL, pubKey) <= 0) {
        return false;
    }

    r = EVP_PKEY_CTX_set_rsa_padding(keygen_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(keygen_ctx, RSA_PSS_SALTLEN_AUTO);


    if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
    if (AuthStatus == 1) {
        *Authentic = true;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return true;
    }
    else if (AuthStatus == 0) {
        *Authentic = false;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return true;
    }
    else {
        *Authentic = false;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return false;
    }
}

void Base64Encode(const unsigned char* buffer,
    size_t length,
    char** base64Text) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);
    *base64Text = (*bufferPtr).data;
    (*base64Text)[(*bufferPtr).length] = '\0';
}

size_t calcDecodeLength(const char* b64input) {
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len - 1] == '=') //last char is =
        padding = 1;
    return (len * 3) / 4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
    BIO* bio, * b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}

char* signMessage(std::string privateKey, std::string plainText) {
    RSA* privateRSA = createPrivateRSA(privateKey);
    unsigned char* encMessage;
    char* base64Text;
    size_t encMessageLength;
    RSASign(privateRSA, (unsigned char*)plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
    Base64Encode(encMessage, encMessageLength, &base64Text);
    free(encMessage);
    return base64Text;
}

bool verifySignature(std::string publicKey, std::string plainText, char* signatureBase64) {
    RSA* publicRSA = createPublicRSA(publicKey);
    unsigned char* encMessage;
    size_t encMessageLength;
    bool authentic;
    Base64Decode(signatureBase64, &encMessage, &encMessageLength);
    bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
    return result & authentic;
}

int main() {
    std::string plainText = "My secret message.";
    char* signature = signMessage(privateKey, plainText);
    //std::string sigSampleStr = "jRqRBfeE2dX3UKihcHPUAeb3zMHl7YfNJsGZiyjKdX3ONZLRJSdjGZ81Tzx3+W6n" "\n"
    //    "awoxdNSOUr5hRSm7RAJ2mu26ShICx0SfRe0+DIWOjUUUSZ+uNbiyBcJzcF26Kt4J" "\n"
    //    "Gio3kjm2YTwg3Z+CadwFJ+zv8K95bJl3Xrg4UvbGroa7KQwVtl1DuUyXn/zTjQfD" "\n"
    //    "bFqEB3O9JcywaUHtqj+3DlScy6A0IPgTRI7yZS+efgEJ7B+5Qgt7TAf3Bsf/Vfv0" "\n"
    //    "doyIlaUfgxBwXVonuKCNNEos85O0C+5aEYwzWmyiKBkoq9k+thkWQF31bubso7Q/" "\n"
    //    "qQRsGb5/54Lwf7L+pyTIlw==" "\0";
    //char* sigSample = new char[sigSampleStr.size() + 1];
    //memcpy(sigSample, sigSampleStr.c_str(), sigSampleStr.size() + 1);
    bool authentic = verifySignature(publicKey, plainText, signature);
    std::cout << signature << std::endl;
    if (authentic) {
        std::cout << "Authentic" << std::endl;
    }
    else {
        std::cout << "Not Authentic" << std::endl;
    }
}