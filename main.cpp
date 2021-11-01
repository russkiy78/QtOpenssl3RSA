#include <QDebug>
#include <QString>
#include "qtopenssl3rsa.h"


int main() {
    QByteArray privateKey;
    QByteArray publicKey;
    QByteArray output;
    EVP_PKEY *pkey = NULL;
   // QByteArray inputHash = QCryptographicHash::hash(QString("dsfds fd sfdzsd sd asd asd afdgdfgsd asd as;lfjds89gudfpguf 978gf97g8f8gf0gf0g89f0g98f0g8d0gj9gjuds s ds fdsf sd").toUtf8(),QCryptographicHash::Sha256);
    //QByteArray input = QString("fsa d dfsasf dsf dsf ds").toUtf8();
   // QByteArray key = QString("fsa d dsf dsfdsdsf sd dsf dsf ds").toUtf8();
    //QByteArray sig =  QByteArray::fromBase64(QString("BnxDvq1yL6HI4J3xbVX5rF7wXmS65+l1v5r+/Drh6Y0iLDZKk/Hvl5ACGr9xMv1mdY57wb1rbhzfbxs2vF8TJT1eW6RjEWl0ytr/W1gsNlSHQMySnxng4li1ElE04Ossigtn9ZG7/ICAGbABXcY35KfdwKSA0tw1gy0dmkCbxFKoOMRedqyErZqdTMZ5zI4w/Zfs2yWWLwnWK4JHt/1RVo6WHdsmho+1uaJjSccfzjgzQIq+2lEXeRcOTm34TJAxnOA3X0RRGscajC4EQCYbhB64psY//pD8n0qkUvw1HufiJTHkDku4nIgqd+FHVD1GyCMKkhlSx9e9c8F4BmJ/xpAT7sHsVQ==").toUtf8());




       privateKey =       QByteArray::fromBase64(QString("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2QUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktZd2dnU2lBZ0VBQW9JQkFRRHlFRUttWGpmVEhjTGQKQ2VPTEc4QVJldUNQZXpyZGhhNXRTZzE3T0ZyakNFd0lwaGJ2V3ZxUGZIZDRiQzBBS2p4Vldvc2lPNGVLUEY0MQpMb3NqcC9aUGxra0czS2VrU0tKVTZTdHN5Ync3NEdQRDBRT3Q5OWpRSWE0akRXaXd6bGM2QW1vemNrMVdMQ2VTCkRQL2ZGUlRsVGpneGVGeHoySDloa1NlcXVFZVhSZStPalFGd3g5d3dxc2djRUJwL1pndG1QdFNoNWZaSnFER2gKZ0NETitnT09GRElIcUR1ZGZ0ZDY5cmRKK1RpRVFCR25pN0pDaVVacE1ZWVNmNUxlTkxOd29MMVlGTXBiSnhjcgo4S0lUVVI0d1hPMzYxdXJ4dUlEeURKVUJUR2tYSGFReTdOOFZFMzN3YnYxNEFJUFFUejFWVlFvREwrbkRJMTR5ClQ2MnhCcDV0QWdNQkFBRUNnZ0VBQlBnVEppOG1TT01zMk45c2JiS2RlQk81cXcyd2k2anUzUXpPeDE5dmM0YjgKRTBGZ1B5Ynk5Y3hzVE1DTHUvRWlBKzZKT2ZsVzNaNUNTMzB2eGdUd3FDUkJvNFBCWitkRnpkQnJpblFwdFF1ZgpnS21Od0hNblh1a1NGZzRmRkF5OXBhYzBYdWRUSEcyK1I0cVV4aE9TQzVNQTBhTW9PQWlUQ2l4Y3BXM2EvN1B1CjcrcVJEUHk0TWw1VGRLcHB2M0dmNnhnMVh2VS9yZlUvNWZGekxidVlReVdZcFJXb0pFZmdxeDMrVmQyYVNYM1AKK3Q2eVJrL2QzTWwyTi9rVTgrUE5UVUdWUWozYmVhUnd4T2EyOU9mMXdPN21DeDR2VkxqWU0wRVBzd0VIeEFLRwo3ZDRUZW9KVitSdVBQTE9tYVpXd2x4VWoySXRnSlo1akVYbFdJK2xBVVFLQmdRRDRuZnB0QVBZUTlYWVFJampvCmZrZThNZTNFRWo2K210aUZONU9iYSthZXhpbnVibjBRM0pGOHRkNUZNUFRodlYwVGNyaGVjR2JDNkxpTWFaZ2YKQUJkcU0rN200bHBPZ0FoUWQ0Sm9xbE5XZ1JnSVVMTmFlTGdpdk80UFpsTDM0Q0VYYzIzNXNnL28zaWpNMmNjMApGQllwbkZmdHZDZWtWdVZqeUN3bXlHRUNad0tCZ1FENVFIWDZ4UHd4Wmh5RnJaK3QrTjE2dE8xRCtISnpOQmJlClM3cVVRUktCc0xvWStLS3dGL0xCZG5HN01lU1lhSHcySmRxNG02K01BUHRTTUFPeFZmcU55dnozZWZURUFiT0EKcld5Nm43OGRCR1RPY2tjZ1NNTUwvQXZ5THdHS3BHalZ2a29lM250L25JTUVLdjZlSndTbXV6SlhVNXpSU1FBeAp3Rk5Na2YzY0N3S0JnRFZwdTJPdjBTM1Rqb25vMEZFaTBFYWVjM2FzZE01K2RnWW82bzE1b1JKN2dJYTVOaVZwClBkaU5Pak9qVVBrdXRkQjMxU1IxQVo3ZVlNZko1K1RCSUVhdzRhSzQvcTNlMCtwMXdvNjZDUzJNanAwNnVVMjIKb2RqVXZsQ1FxMEtWNUlZbFJudGV4Z3hCcm9KVVIzZm8yTm9Ydk14V29DMnVmWm55WjRudGd1b0JBb0dBWmw0WApGbHI0eU1FTFRjdTFIUnBzdkF5NnRZUEFYWmd6SERFMSs5V042RDNROEppTkdJMTlZZjluVGw1N2FDemhkc3V0ClBNeVVHSWYrc0E2UU5iRCtLbVlINXd2cmZ1VEQrRUZCdXBRSlJiMmNPVDJ1QUpCaHF2WmxZWjMwb0NCTi9oc2QKRGZpSitDc3JrL2FraEFlNlhVL2NxUWpxQ3ZwVVhocURHNXVLQzJrQ2dZQjFuN1VvQjVMdTZUblRBS0JOSklwWgpaUWdSc2VNc3RSMkhOaU11b2NIbGpJTVVXRUZnZUErbVVwMmRUR2lsbHcxRW9Eem9NU1crWHpDelhEY2s1ZjZTCkptWkEyLzJMaVJhRVNpVEc2b1crdWlXcldDN002cUN2QXAwbkd6RWxHQmtGSnpSbTdHd2JINnlCdWJwK093VXkKWkZaK2lTeUpXdDZzWHNrejhlRWpjdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K").toUtf8());
       publicKey=     QByteArray::fromBase64(QString("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE4aEJDcGw0MzB4M0MzUW5qaXh2QQpFWHJnajNzNjNZV3ViVW9OZXpoYTR3aE1DS1lXNzFyNmozeDNlR3d0QUNvOFZWcUxJanVIaWp4ZU5TNkxJNmYyClQ1WkpCdHlucEVpaVZPa3JiTW04TytCanc5RURyZmZZMENHdUl3MW9zTTVYT2dKcU0zSk5WaXdua2d6LzN4VVUKNVU0NE1YaGNjOWgvWVpFbnFyaEhsMFh2am8wQmNNZmNNS3JJSEJBYWYyWUxaajdVb2VYMlNhZ3hvWUFnemZvRApqaFF5QjZnN25YN1hldmEzU2ZrNGhFQVJwNHV5UW9sR2FUR0dFbitTM2pTemNLQzlXQlRLV3ljWEsvQ2lFMUVlCk1GenQrdGJxOGJpQThneVZBVXhwRngya011emZGUk45OEc3OWVBQ0QwRTg5VlZVS0F5L3B3eU5lTWsrdHNRYWUKYlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==").toUtf8());



    QtOpenssl3RSA rsa = QtOpenssl3RSA();

    qDebug()<< " createRSAKeypar" <<  rsa.createRSAKeypar();

     QByteArray input = QString("fsa d dfsasf dsfsdfsdfsdfdsssssssssssssssssssssssssssssssssssl;fm sdf;dsfl ;sdlfk;s dfkds;f ksd;f dslkfsd ;fksd ;lsfdk ;sdfksd;flsdkf; sdlkfsd;lksdf; lsdkf;ldskfds;f ksd;f lsdkf; sdfsd;f ksdf sdk;lfkds; fk sd;fld skfdg dfg dfg dfgfd;flsdkf;l dsf ;ld sk;fldkf;sdfksd;fl dsk;flsdkf;sdfsdfsdfsdfdsfdsfdsfdsfdsf").toUtf8();

     qDebug()<< " input" << QString(input) << input.size();

     rsa.encode(input,output);
     qDebug()<< " output" << QString(output.toBase64()) << output.size();

     QByteArray res;

     rsa.decode(res,output);
     qDebug()<< " input" << QString(res) << res.size();

     /*
    QByteArray keyIv = QString("rtytds fds fds fds fds fdsfds fds fds sd ryrt").toUtf8();
    QByteArray key;
    QByteArray input2;

    qDebug()<< " ";
    qDebug()<< " input" << QString(input) << input.size();
    qDebug()<< " ";

    rsa.encodeSealRSA(input,keyIv, key, output);

    qDebug()<< " ";
    qDebug()<< " key" << QString(key.toBase64()) << key.size();
    qDebug()<< " ";
    qDebug()<< " output" << QString(output.toBase64()) << output.size();
    qDebug()<< " ";

    rsa.decodeSealRSA(input2,keyIv, key, output);

    qDebug()<< " decoded" << QString(input2) << input2.size();


    */




   // rsa.loadPublicKeyFromPEM("./public");
   // rsa.loadPrivateKeyFromPEM("./private");

   //rsa.savePrivateKeyAsArray(privateKey);
   //rsa.savePublicKeyAsArray(publicKey);


   //rsa.loadPublicKeyFromArray(publicKey);
   //rsa.loadPrivateKeyFromArray(privateKey);

   //qDebug()<< " privateKey" <<privateKey.toBase64();
   //qDebug()<< " publicKey" <<publicKey.toBase64();

   //rsa.savePrivateKeyAsPEM("./private");
   //rsa.savePublicKeyAsPEM("./public");


   //qDebug()<< " signWithPrivateKey" <<  rsa.signWithPrivateKey(input, output);
   //qDebug()<< " verifyWithPublicKey" <<  rsa.verifyWithPublicKey(input, output);

   // qDebug()<< " loadPublicKeyFromPEM" << rsa.loadPublicKeyFromPEM("./public");
   // qDebug()<< " loadPrivateKeyFromPEM" << rsa.loadPrivateKeyFromPEM("./private");


  //qDebug()<< " signWithPrivateKey" <<  rsa.signWithPrivateKey(input, output);

   //qDebug()<< " output" << output.toBase64();

   //qDebug()<< " verifyWithPublicKey" <<  rsa.verifyWithPublicKey(input, sig);


    //qDebug()<< " loadPrivateKeyFromPEM" << rsa.loadPublicKeyFromPEM("./public");

    //QtOpenssl3::loadPEM(privateKey,"./private");
    //QtOpenssl3::loadPEM(publicKey,"./public");


     //qDebug()<< " inputHash" << inputHash.toBase64() << QtOpenssl3::signWithPublicKey(privateKey, inputHash, output);


}
