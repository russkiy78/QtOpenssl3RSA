#include "qtopenssl3rsa.h"



QtOpenssl3RSA::QtOpenssl3RSA(int keyLength, int encryptedKeyLen, const EVP_CIPHER* evpCipherType)
{
    this->keyLength = keyLength;
    this->encryptedKeyLen = encryptedKeyLen;
    this->evpCipherType = evpCipherType;
}


/*private*/
QByteArray QtOpenssl3RSA::generateRandom(const int len)
{
    QByteArray iv = QByteArray(len, 0);
    for(int i=0; i<len; ++i) {
        iv[i] = static_cast<char>(QRandomGenerator::system()->bounded(255));
    }
    return iv;
}

/*public*/

bool QtOpenssl3RSA::encode(QByteArray &plainText, QByteArray &encryptedText)
{
    if (!pkey)
        return false;


    int plainTextLen = plainText.size();

    unsigned char* charPlainText = reinterpret_cast<unsigned char*>(plainText.data());

    // init new
    unsigned char* charCipherText = reinterpret_cast<unsigned char*>(OPENSSL_malloc(plainText.size()*2));

    EVP_ENCODE_CTX *ctx;
    int cipherTextLen = 0;
    int len;
    int result = true;

    ctx = EVP_ENCODE_CTX_new();
    EVP_EncodeInit(ctx);


    if(EVP_EncodeUpdate(ctx, charCipherText, &len, charPlainText, plainTextLen) != 1)
        result = false;
    else
        cipherTextLen = len;

    if (result) {
        EVP_EncodeFinal(ctx, charCipherText + len, &len);
        cipherTextLen += len;
    }


    if (result) {
        encryptedText = QByteArray(reinterpret_cast<char*>(charCipherText),cipherTextLen);
    }

    // clear all
    OPENSSL_free(charCipherText);
    EVP_ENCODE_CTX_free(ctx);

    return result;

}

bool QtOpenssl3RSA::decode(QByteArray &plainText, QByteArray &encryptedText)
{
    if (!pkey)
        return false;


    int cipherTextLen = encryptedText.size();
    unsigned char* charCipherText = reinterpret_cast<unsigned char*>(encryptedText.data());

    // init new
    unsigned char* charPlainText = reinterpret_cast<unsigned char*>(OPENSSL_malloc(cipherTextLen + 1));

    EVP_ENCODE_CTX *ctx;
    int plainTextLen = 0;
    int len;

    ctx = EVP_ENCODE_CTX_new();
    EVP_DecodeInit(ctx);

    EVP_DecodeUpdate(ctx, charPlainText, &len, charCipherText, cipherTextLen);
    plainTextLen = len;

    EVP_DecodeFinal(ctx, charPlainText + len, &len);
    plainTextLen += len;

    plainText = QByteArray(reinterpret_cast<char*>(charPlainText),plainTextLen);


    // clear all
    OPENSSL_free(charPlainText);
    EVP_ENCODE_CTX_free(ctx);

    return true;

}

bool QtOpenssl3RSA::encodeSealRSA(QByteArray &plainText, QByteArray ivLine,  QByteArray &encryptedKey, QByteArray &encryptedText){

    if (!pkey)
        return false;

    // add random padding
    QByteArray padding = generateRandom(16);
    plainText = padding + plainText;

    int plainTextLen = plainText.size();

    unsigned char* charPlainText = reinterpret_cast<unsigned char*>(plainText.data());
    unsigned char* charIV = reinterpret_cast<unsigned char*>(ivLine.data());

    // init new
    unsigned char* charCipherText = reinterpret_cast<unsigned char*>(OPENSSL_malloc(plainText.size()*2));
    unsigned char* charEncryptedKey = reinterpret_cast<unsigned char*>(OPENSSL_malloc(keyLength +1));

    EVP_CIPHER_CTX *ctx;
    int cipherTextLen;
    int len;
    int result = true;

    ctx = EVP_CIPHER_CTX_new();

    if (EVP_SealInit(ctx, evpCipherType, &charEncryptedKey, &encryptedKeyLen, charIV, &pkey, 1) != 1)
        result = false;

    if (result) {
        if(EVP_SealUpdate(ctx, charCipherText, &len, charPlainText, plainTextLen) != 1)
            result = false;
        else
            cipherTextLen = len;
    }

    if (result) {
        if(EVP_SealFinal(ctx, charCipherText + len, &len) != 1)
            result = false;
        else
            cipherTextLen += len;
    }

    if (result) {
        encryptedKey = QByteArray(reinterpret_cast<char*>(charEncryptedKey),keyLength);
        encryptedText = QByteArray(reinterpret_cast<char*>(charCipherText),cipherTextLen);
    }

    // clear all
    OPENSSL_free(charEncryptedKey);
    OPENSSL_free(charCipherText);
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

bool QtOpenssl3RSA::decodeSealRSA(QByteArray &plainText, QByteArray &ivLine,  QByteArray &encryptedKey, QByteArray &encryptedText) {

    if (!pkey)
        return false;

    int cipherTextLen = encryptedText.size();

    unsigned char* charCipherText = reinterpret_cast<unsigned char*>(encryptedText.data());
    unsigned char* charIV = reinterpret_cast<unsigned char*>(ivLine.data());
    unsigned char* charEncryptedKey = reinterpret_cast<unsigned char*>(encryptedKey.data());

    // init new
    unsigned char* charPlainText = reinterpret_cast<unsigned char*>(OPENSSL_malloc(encryptedText.size()+1));


    EVP_CIPHER_CTX *ctx;
    int len;
    int plainTextLen = 0;
    int result = true;

    ctx = EVP_CIPHER_CTX_new(); 

    if (EVP_OpenInit(ctx, evpCipherType, charEncryptedKey, encryptedKeyLen, charIV, pkey) != 1)
        result = false;

    if (result){
        if(EVP_OpenUpdate(ctx, charPlainText, &len, charCipherText, cipherTextLen) != 1)
            result = false;
        else
            plainTextLen = len;
    }

    if (result){
        if(EVP_OpenFinal(ctx, charPlainText + len, &len) != 1)
            result = false;
        else
            plainTextLen += len;
    }

    plainText = QByteArray(reinterpret_cast<char*>(charPlainText),plainTextLen);

    //remove padding
    plainText.remove(0,16);

    OPENSSL_free(charPlainText);
    EVP_CIPHER_CTX_free(ctx);

    return result;

}

bool QtOpenssl3RSA::createRSAKeypar(const int keyLength)
{
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        return false;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        return false;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keyLength) <= 0)
        return false;

    /* Generate key */
    if (EVP_PKEY_generate(ctx, &pkey) <= 0)
        return false;

    EVP_PKEY_CTX_free(ctx);

    return true;

}

bool QtOpenssl3RSA::savePrivateKeyAsPEM(QString fileName){

    if (!pkey)
        return false;

    BIO* pOut = BIO_new_file( fileName.toStdString().c_str(), "wb");

    if (!pOut)
        return false;

    if( !PEM_write_bio_PrivateKey(pOut, pkey, NULL, NULL, 0, NULL, NULL))
        return false;

    BIO_free_all( pOut );
    return true;
}

bool QtOpenssl3RSA::savePublicKeyAsPEM(QString fileName)
{

    if (!pkey)
        return false;

    BIO* pOut = BIO_new_file( fileName.toStdString().c_str(), "wb");

    if (!pOut)
        return false;

    if( !PEM_write_bio_PUBKEY(pOut, pkey))
        return false;

    BIO_free_all( pOut );
    return true;

}

bool QtOpenssl3RSA::savePrivateKeyAsArray(QByteArray &privateKey)
{
    if (!pkey)
        return false;

    static char recv_buffer[2048];
    BIO *mem = BIO_new(BIO_s_mem());

    if (!mem)
        return false;

    if( !PEM_write_bio_PrivateKey( mem, pkey, NULL, NULL, 0, NULL, NULL))
        return false;

    BIO_read(mem, recv_buffer, 2048);

    privateKey = QByteArray(recv_buffer);

    BIO_free_all( mem );
    return true;
}

bool QtOpenssl3RSA::savePublicKeyAsArray(QByteArray &publicKey)
{
    if (!pkey)
        return false;

    BIO *mem = BIO_new(BIO_s_mem());
    static char recv_buffer[4096];

    if (!mem)
        return false;

    if( !PEM_write_bio_PUBKEY(mem, pkey))
        return false;

    BIO_read(mem, recv_buffer, 4096);

    publicKey = QByteArray(recv_buffer);

    BIO_free_all( mem );
    return true;

}

bool QtOpenssl3RSA::loadPrivateKeyFromPEM(QString fileName)
{
    BIO* pOut = BIO_new_file( fileName.toStdString().c_str(), "rb");

    if (!pOut)
        return false;
    pkey = PEM_read_bio_PrivateKey(pOut,&pkey,NULL,NULL);
    if (pkey == NULL)
        return false;

    BIO_free_all( pOut );
    return true;
}

bool QtOpenssl3RSA::loadPublicKeyFromPEM(QString fileName)
{
    BIO* pOut = BIO_new_file( fileName.toStdString().c_str(), "rb");

    if (!pOut)
        return false;

    pkey = PEM_read_bio_PUBKEY(pOut,&pkey,NULL,NULL);
    if (pkey == NULL)
        return false;

    BIO_free_all( pOut );
    return true;
}

bool QtOpenssl3RSA::loadPrivateKeyFromArray(QByteArray &privateKey)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_puts(mem, privateKey);

    if (!mem)
        return false;
    pkey = PEM_read_bio_PrivateKey(mem,&pkey,NULL,NULL);
    if (pkey == NULL)
        return false;

    BIO_free_all( mem );
    return true;
}

bool QtOpenssl3RSA::loadPublicKeyFromArray(QByteArray &publicKey)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_puts(mem, publicKey);

    if (!mem)
        return false;

    pkey = PEM_read_bio_PUBKEY(mem,&pkey,NULL,NULL);

    if (pkey == NULL)
        return false;

    BIO_free_all( mem );
    return true;

}

bool QtOpenssl3RSA::signWithPrivateKey(QByteArray &inputText, QByteArray &sign)
{
    if (!pkey)
        return false;

    EVP_MD_CTX *mdctx = NULL;
    bool ret = true;
    size_t slen;
    unsigned char  *sig;

    /* Create the Message Digest Context */
    if(!(mdctx = EVP_MD_CTX_create())) ret = false;

    /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey)) ret = false;

    /* Call update with the message */
    if(1 != EVP_DigestSignUpdate(mdctx, inputText, inputText.size())) ret = false;

    /* Finalise the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
      * signature. Length is returned in slen */

    if(1 != EVP_DigestSignFinal(mdctx, NULL, &slen)) ret = false;
    /* Allocate memory for the signature based on size in slen */
    sig = (unsigned char *) OPENSSL_malloc(slen);
    /* Obtain the signature */
    if(1 != EVP_DigestSignFinal(mdctx, sig, &slen))  ret = false;
    /* Success */

    sign = QByteArray(reinterpret_cast<char*>(sig),slen);

    /* Clean up */
    if(*sig) OPENSSL_free(sig);
    if(mdctx) EVP_MD_CTX_destroy(mdctx);

    return ret;
}

bool QtOpenssl3RSA::verifyWithPublicKey(QByteArray &inputText, QByteArray &sign)
{
    if (!pkey)
        return false;

    EVP_MD_CTX *mdctx = NULL;
    bool ret = true;
    size_t slen = 256;

    unsigned char* sig = reinterpret_cast<unsigned char*>(sign.data());

    /* Create the Message Digest Context */
    if(!(mdctx = EVP_MD_CTX_create())) ret = false;


    /* Initialize `key` with a public key */
    if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey)) ret = false;


    /* Initialize `key` with a public key */
    if(1 != EVP_DigestVerifyUpdate(mdctx, inputText,  inputText.size()))  ret = false;

    if (!ret){
        return false;
    }

    if(1 == EVP_DigestVerifyFinal(mdctx, sig, slen)) {
        return true;
    }

    return false;
}
