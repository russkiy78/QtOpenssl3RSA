#include "qtopenssl3rsa.h"



QtOpenssl3RSA::QtOpenssl3RSA()
{
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
bool QtOpenssl3RSA::encodeSealRSA(QByteArray &plainText, QByteArray ivLine,  QByteArray &encryptedKey, QByteArray &encryptedText){

    // add random padding
    QByteArray padding = generateRandom(16);
    plainText = padding + plainText;


    unsigned char* plaintext = reinterpret_cast<unsigned char*>(plainText.data());
    int plaintext_len = plainText.size();

    unsigned char* ciphertext;
    ciphertext = (unsigned char *) OPENSSL_malloc(plainText.size()*2);

    int encrypted_key_len = 256;
    unsigned char* iv = reinterpret_cast<unsigned char*>(ivLine.data());

    unsigned char* encrypted_key;
    encrypted_key = (unsigned char *) OPENSSL_malloc(256);

    EVP_CIPHER_CTX *ctx;
    int ciphertext_len;
    int len;

    ctx = EVP_CIPHER_CTX_new();

    EVP_SealInit(ctx, EVP_aes_256_cbc(), &encrypted_key, &encrypted_key_len, iv, &pkey, 1);


    EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_SealFinal(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    qDebug()<<"ciphertext_len"<<ciphertext_len<<QByteArray(reinterpret_cast<char*>(ciphertext),ciphertext_len).toBase64();

    encryptedKey = QByteArray(reinterpret_cast<char*>(encrypted_key),encrypted_key_len);
    encryptedText = QByteArray(reinterpret_cast<char*>(ciphertext),ciphertext_len);

    OPENSSL_free(ciphertext);
    OPENSSL_free(encrypted_key);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool QtOpenssl3RSA::decodeSealRSA(QByteArray &plainText, QByteArray &ivLine,  QByteArray &encryptedKey, QByteArray &encryptedText) {

    EVP_CIPHER_CTX *ctx;
    int ciphertext_len = encryptedText.size();
    int len;
    int plaintext_len;

    ctx = EVP_CIPHER_CTX_new();
    //EVP_CIPHER_CTX_set_padding(ctx, 1);

    unsigned char* plaintext;
    plaintext = (unsigned char *) OPENSSL_malloc(ciphertext_len);

    int encrypted_key_len = 256;
    unsigned char* iv = reinterpret_cast<unsigned char*>(ivLine.data());

    unsigned char* encrypted_key = reinterpret_cast<unsigned char*>(encryptedKey.data());

    unsigned char* ciphertext = reinterpret_cast<unsigned char*>(encryptedText.data());

    EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key, encrypted_key_len, iv, pkey);

    EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_OpenFinal(ctx, plaintext + len, &len);
    plaintext_len += len;

    plainText.clear();
    plainText = QByteArray(reinterpret_cast<char*>(plaintext),plaintext_len);

    //remove padding
    plainText.remove(0,16);

    OPENSSL_free(plaintext);
    EVP_CIPHER_CTX_free(ctx);

    return true;

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
