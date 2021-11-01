#ifndef QTOPENSSL3RSA_H
#define QTOPENSSL3RSA_H

#include "QtOpenssl3RSA_global.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <QDebug>
#include <QRandomGenerator>
#include <QFile>
#include <QString>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/encoder.h>

#define KEY_LENGTH       2048

class QTOPENSSL3RSA_EXPORT QtOpenssl3RSA
{    
private:

    EVP_PKEY* pkey = NULL;
    int keyLength = KEY_LENGTH;
    int encryptedKeyLen = 256;
    const EVP_CIPHER* evpCipherType = EVP_aes_256_cbc();

    QByteArray generateRandom(const int len);

public:
    QtOpenssl3RSA(int keyLength = KEY_LENGTH, int encryptedKeyLen = 256, const EVP_CIPHER* evpCipherType = EVP_aes_256_cbc());

    bool encode(QByteArray &plainText, QByteArray &encryptedText);
    bool decode(QByteArray &plainText, QByteArray &encryptedText);

    bool encodeSealRSA(QByteArray &plainText, QByteArray ivLine,  QByteArray &encryptedKey, QByteArray &encryptedText);
    bool decodeSealRSA(QByteArray &plainText, QByteArray &ivLine,  QByteArray &encryptedKey, QByteArray &encryptedText);

    bool createRSAKeypar(const int keyLength = KEY_LENGTH);
    bool signWithPublicKey(QByteArray &publicKey, QByteArray &inputHash, QByteArray &output);

    bool savePrivateKeyAsPEM (QString fileName);
    bool savePublicKeyAsPEM (QString fileName);

    bool savePrivateKeyAsArray (QByteArray &privateKey);
    bool savePublicKeyAsArray (QByteArray &publicKey);

    bool loadPrivateKeyFromPEM (QString fileName);
    bool loadPublicKeyFromPEM (QString fileName);

    bool loadPrivateKeyFromArray (QByteArray &privateKey);
    bool loadPublicKeyFromArray (QByteArray &publicKey);

    bool signWithPrivateKey(QByteArray &inputText, QByteArray &sign);
    bool verifyWithPublicKey(QByteArray &inputText, QByteArray &sign);
};

#endif // QTOPENSSL3RSA_H
