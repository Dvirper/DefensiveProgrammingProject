#include "Chiper.h"
#include "Client.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#define RSA_SIZE (160)


Chiper::Chiper() {genRSAPair();}

// Generates RSA keys
void Chiper::genRSAPair() {
	RSAPrivateWrapper rsapriv;
	rsapriv.getPublicKey(_public_key, RSA_SIZE);
	_private_key = Base64Wrapper::encode(rsapriv.getPrivateKey());	
}

// Decrypts AES key using the RSA Wrapper
std::string Chiper::decrypt_aes_key(char* aes_key, unsigned int length) {
	RSAPublicWrapper rsapub(_public_key, RSA_SIZE);
	RSAPrivateWrapper rsapriv_other(Base64Wrapper::decode(_private_key));
	std::string decrypted = rsapriv_other.decrypt(aes_key, 128);
	return decrypted;
}

// Get/Set
char* Chiper::getPublicKey() {return _public_key;}
std::string Chiper::getPrivateKey() {return _private_key;}
void Chiper::setAES(std::string aes_key) {_aes_key = aes_key;}
std::string Chiper::getAES() {return _aes_key;}