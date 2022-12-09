#include "Protocol.h"
#include "RequestHandler.h"
#include "Chiper.h"
#include "ResponeHandler.h"

// Start new protocol instance
Protocol::Protocol() {

	_file = {};
	_client = new Client();
	_conn = new ConnHandler(_client);
	_chiper = new Chiper();

	initProtocol();
}

// Start Protocol
void Protocol::initProtocol() {
	requestRegistration();
	requestSendPublicKey();
	TransferFileProtocol();
	std::cout << "End of client protocol, You can exit the terminal.";
}

// Handles Registration:
// Request 1100 and response - Failed/Success registration
void Protocol::requestRegistration() {
	// Client already registered? Skip this part of the protocol
	if (_client->isRegistered()) {
		_client->readUID();
		return;
	}
	// fill request payload
	RequestRegisterPayload requestPayload;
	std::string name = _client->getName();
	memcpy(requestPayload.name, name.c_str(), name.length()); // fill name in request payload
	// fill request header
	fillRequestHeader(_client->getUID(), VERSION, REQUEST_REGISTRATION, PAYLOAD_SIZE_REGISTER);
	// send request
	try {
		_conn->send(reinterpret_cast<char*>(&requestHeader), sizeof(RequestHeader));
		_conn->send(reinterpret_cast<char*>(&requestPayload), sizeof(RequestRegisterPayload));
	} catch (boost::system::system_error const& se) {
		std::cout << "Error " << se.code().message() << "\n"; }
	
	// receive response
	ResponseHeader responseHeader;
	ResponseSesuccessfulRegistrationPayload payloadResponse;
	_conn->receive(reinterpret_cast<char*>(&responseHeader), sizeof(ResponseHeader));

	// Validity, Also throws error if code is different from registration success response
	if (!validResponseHeader(responseHeader.version, responseHeader.code, RESPONSE_REGISTRATION_SUCCESS)) {
		std::cout << "error: the name already exist in the server" << std::endl;
		throw std::runtime_error("");
	}
	else {
		std::cout << "New user registerd - Name " << _client->getName() << std::endl;
	}
	// get payload
	try {
		_conn->receive(reinterpret_cast<char*>(&payloadResponse), responseHeader.payload_size);
	} catch (boost::system::system_error const& se) {
		std::cout << "Error " << se.code().message() << "\n";
	}
	
	// Set ID 
	std::string id((char*)payloadResponse.client_id, ID_SIZE);
	_client->setUID(id);
	_client->createMeInfo(_chiper->getPrivateKey());
}

// Handles Public key trasnfer - Decrypting and storing in metadata for file encryption
// Request 1101 and response 2102
void Protocol::requestSendPublicKey() {

	// fill request header
	fillRequestHeader(_client->getUID(), VERSION, SEND_PUB_KEY, PAYLOAD_SIZE_SEND_PUB_KEY);
	RequestSendPubKeyPayload requestPayload;
	// fill payload
	Protocol::fillRequestSendPubKeyPayload(requestPayload, _client->getName(), _chiper->getPublicKey());
	// send data
	try {
		_conn->send(reinterpret_cast<char*>(&requestHeader), sizeof(RequestHeader));
		_conn->send(reinterpret_cast<char*>(&requestPayload), sizeof(RequestSendPubKeyPayload));
	}
	catch (boost::system::system_error const& se) {
		std::cout << "Error " << se.code().message() << "\n";
	}
	// get response
	ResponseHeader responseHeader;
	ResponsePublicKeyPayload payloadResponse;
	try {
		_conn->receive(reinterpret_cast<char*>(&responseHeader), sizeof(ResponseHeader));
		_conn->receive(reinterpret_cast<char*>(&payloadResponse), responseHeader.payload_size);
	}
	catch (boost::system::system_error const& se) {
		std::cout << "Error " << se.code().message() << "\n";
	}

	// Validity Check
	if (validResponseHeader(responseHeader.version, responseHeader.code, RESPONSE_PUBLIC_KEY))
		std::cout << "Public Key Sent" << std::endl;
	else {
		std::cout << "server responded with an error" << std::endl;
		throw std::runtime_error("");
	}
	// Store AES key and decrypt it
	char* encrypted_aes = (char*)payloadResponse.public_key;
	std::string aes = _chiper->decrypt_aes_key(encrypted_aes, sizeof(payloadResponse.public_key));
	_chiper->setAES(aes);
}
// Handles file trasnfer - Encrypting file and recieving CRC result
// Request 1103, Returns weather CRC equals in both server and client - 1, Or not 0
int Protocol::requestSendFile() {

	// fill request header
	Protocol::fillRequestHeader(_client->getUID(), VERSION, SEND_FILE, _file->getEncryptedFile().length() + 275);
	// fill payload header
	struct RequestSendFilePayload requestPayload;
	Protocol::fillRequestSendFile(requestPayload);
	// send data
	try {
		_conn->send(reinterpret_cast<char*>(&requestHeader), sizeof(RequestHeader));
		_conn->send(reinterpret_cast<char*>(&requestPayload), sizeof(requestPayload));
		_conn->send(_file->getEncryptedFile().c_str(), _file->getEncryptedFile().length());
	}
	catch (boost::system::system_error const& se) {
		std::cout << "Error " << se.code().message() << "\n";
	}
	// get response - CRC
	ResponseHeader responseHeader;
	ResponseFileRec payloadResponse;
	try {
		_conn->receive(reinterpret_cast<char*>(&responseHeader), sizeof(ResponseHeader));
		_conn->receive(reinterpret_cast<char*>(&payloadResponse), responseHeader.payload_size);
	}
	catch (boost::system::system_error const& se) {
		std::cout << "Error " << se.code().message() << "\n";
	}
	// Check Validity
	if (validResponseHeader(responseHeader.version, responseHeader.code, RESPONSE_FILE_SUCCESS))
		std::cout << "File Sent" << std::endl;
	else {
		std::cout << "server responded with an error" << std::endl;
		throw std::runtime_error("");
	}
	// Calculate CRC and compare to server's response
	return (_file->calculateCRC() == payloadResponse.cksum);
}

// Implementation of File transfer protocol - 3 retries.
// Using a loop with retry int - loops twice, val 1/2
// Sends Invalid crc - 1104 + retry: 1105 and 1106.
// If CRC is valid, breaks the loop.
// Implemented in a do..while.. fashion
void Protocol::TransferFileProtocol() {

	_file = new FileHandler(_client->getFilePath(), _chiper->getAES());
	int crc_valid = requestSendFile();
	for (int retry = 1; retry < 3; retry++) {
		if (crc_valid == 0) 
			sendCRC(1104 + retry);
		else {
			sendCRC(1104);
			break;}
		crc_valid = requestSendFile();
	}
	if (crc_valid == 0) {
		std::cout << "Fatal Error, CRC Check Failed 3 times!\n";
		throw std::runtime_error("");
	}
}

// Fill request header for server using struct defined in RequestHandler.H
void Protocol::fillRequestHeader(std::array<uint8_t, 16>& client_id, uint8_t version, uint16_t code, uint32_t payload_size) {
	requestHeader = {};
	std::copy(std::begin(client_id), std::end(client_id), std::begin(requestHeader.client_id));
	requestHeader.version = version;
	requestHeader.code = code;
	requestHeader.payload_size = payload_size;
}

// Fill public key transfer request payload for server using struct defined in RequestHandler.H
void Protocol::fillRequestSendPubKeyPayload(RequestSendPubKeyPayload& requestPayload, std::string name, char* pub_key) {
	std::memcpy(requestPayload.name, name.c_str(), name.length()); // fill name in request payload
	std::memcpy(requestPayload.public_key, pub_key , 160);
}

// Fill file transfer request payload for server using struct defined in RequestHandler.H
void Protocol::fillRequestSendFile(RequestSendFilePayload& requestPayload) {
	std::memcpy(requestPayload.file_name, _file->getFileName().c_str(), _file->getFileName().length());
	std::copy(std::begin(_client->getUID()), std::end(_client->getUID()), std::begin(requestPayload.client_id));
	uint32_t file_size = _file->getEncryptedFile().length();
	requestPayload.content_size = file_size;
}

// return true if valid response header
bool Protocol::validResponseHeader(uint8_t responseVersion, uint16_t responseCode, uint16_t code)
{
	return responseVersion == VERSION && responseCode == code;
}

// Fill CRC value request payload for server using struct defined in RequestHandler.H
void Protocol::fillCRCPayload(RequestSendCRC& requestPayload) {
	std::memcpy(requestPayload.file_name, _file->getFileName().c_str(), _file->getFileName().length());
	std::copy(std::begin(_client->getUID()), std::end(_client->getUID()), std::begin(requestPayload.client_id));
}

// Sends CRC request - valid or not depends on code.
// Code = 1104 - Sends valid CRC response.
// Code 1105/1106, Invalid. 
// Since payload is the same for all 3 crc req, Protocol only needs one function
void Protocol::sendCRC(int code) {
	// fill request header
	fillRequestHeader(_client->getUID(), VERSION, code, PAYLOAD_SEND_CRC_SIZE);
	// fill payload for crc request
	RequestSendCRC requestPayload;
	Protocol::fillCRCPayload(requestPayload);
	// send data
	try {
		_conn->send(reinterpret_cast<char*>(&requestHeader), sizeof(RequestHeader));
		_conn->send(reinterpret_cast<char*>(&requestPayload), sizeof(RequestSendCRC));
	}
	catch (boost::system::system_error const& se) {
		std::cout << "Error " << se.code().message() << "\n";
	}
	// If code isn't 1104, We do not expect to recieve response 2104
	// MSG Recieved, Therfore we exit.
	if (code != 1104) {
		return;
	}

	// Otherwise, Valid CRC therefore server should send us response 2104
	ResponseHeader responseHeader;
	try {
		_conn->receive(reinterpret_cast<char*>(&responseHeader), sizeof(ResponseHeader));
	}
	catch (boost::system::system_error const& se) {
		std::cout << "Error " << se.code().message() << "\n";
	}

	if (validResponseHeader(responseHeader.version, responseHeader.code, RESPONSE_MSG_REC))
		std::cout << "CRC Request sent - Number " << code << std::endl;
	else {
		std::cout << "server responded with an error" << std::endl;
		throw std::runtime_error("");
	}
	// End of protocol, We can disconnect
	_conn->disconnect();
}

