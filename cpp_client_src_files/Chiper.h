#pragma once
#include "Client.h"
#include <cryptlib.h>
#include "rsa.h"
#include <aes.h>
#include <iomanip>
#include "osrng.h"
#define RSA_SIZE (160)
#define AES_SIZE (16)

class Chiper {
private:
	char _public_key[RSA_SIZE];
	std::string _private_key;
	std::string  _aes_key;

public:
	Chiper();
	void genRSAPair();
	char* getPublicKey();
	std::string getPrivateKey();
	std::string decrypt_aes_key(char* aes_key, unsigned int length);
	void setAES(std::string aes_key);
	std::string getAES();
};