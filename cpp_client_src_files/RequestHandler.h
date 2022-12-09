#pragma once
#include "stdint.h"

#ifndef __REQUESTSTRUCT_H__
#define __REQUESTSTRUCT_H__

constexpr uint8_t CLIENT_VERSION = 3;
constexpr uint16_t SEND_PUB_KEY = 1101;
constexpr uint16_t SEND_FILE = 1103;
constexpr uint16_t SEND_VALID_CRC = 1104;

// request codes
enum request_code : uint16_t {
	REQUEST_REGISTRATION = 1100,
	VALID_CRC = 1104,
	INVALID_CRC = 1105,
	INVALID_END_OF_COMMS = 1106
};


// Basic request header struct
#pragma pack(push, 1)
struct RequestHeader
{
	uint8_t client_id[16] = {0};
	uint8_t version = CLIENT_VERSION;
	uint16_t code;
	uint32_t payload_size;
};
#pragma pack(pop)

// request payload struct code 1101
#pragma pack(push, 1)
struct RequestSendPubKeyPayload
{
	uint8_t name[255] = { 0 };
	uint8_t public_key[160] = { 0 };
};
#pragma pack(pop)

// request payload struct code 1101
#pragma pack(push, 1)
struct RequestRegisterPayload
{
	uint8_t name[255] = {0};
};
#pragma pack(pop)

// request payload struct code 103.
#pragma pack(push, 1)
struct RequestSendFilePayload
{
	uint8_t client_id[16] = { 0 };
	uint32_t content_size;
	uint8_t file_name[255] = { 0 };
};
#pragma pack(pop)


// request payload struct code 103.
#pragma pack(push, 1)
struct RequestSendCRC
{
	uint8_t client_id[16] = { 0 };
	uint8_t file_name[255] = { 0 };
};
#pragma pack(pop)

#endif /* __REQUESTSTRUCT_H__ */