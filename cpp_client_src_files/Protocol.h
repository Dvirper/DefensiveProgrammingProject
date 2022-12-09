#include "ConnHandler.h"
#include "Client.h"
#include "FileHandler.h"
#include "Chiper.h"
#include "RequestHandler.h"

constexpr uint8_t VERSION = 3;
constexpr uint8_t ZERO = 0;
constexpr uint32_t PAYLOAD_SIZE_REGISTER = 255;
constexpr uint32_t PAYLOAD_SIZE_SEND_PUB_KEY = 415;
constexpr uint32_t PAYLOAD_SEND_CRC_SIZE = 271;
constexpr uint8_t MAX_SIZE_NAME = 255;
constexpr uint8_t ID_SIZE = 16;

class Protocol {
public:
	Protocol();
	void run();
	ConnHandler* _conn;
	FileHandler* _file;
	Client* _client;
	Chiper* _chiper;
	RequestHeader requestHeader;
	void requestRegistration();
	void requestSendPublicKey();
	int requestSendFile();
	void fillRequestHeader(std::array<uint8_t, 16>& client_id, uint8_t version, uint16_t code, uint32_t payload_size);
	void fillRequestSendPubKeyPayload(RequestSendPubKeyPayload& requestPayload, std::string name, char* pub_key);
	bool validResponseHeader(uint8_t responseVersion, uint16_t responseCode, uint16_t code);
	void fillRequestSendFile(RequestSendFilePayload& requestPayload);
	void TransferFileProtocol();
	void sendCRC(int res);
	void fillCRCPayload(RequestSendCRC& requestPayload);
	void initProtocol();

};