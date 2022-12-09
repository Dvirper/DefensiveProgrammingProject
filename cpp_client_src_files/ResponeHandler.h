#pragma once
#include <stdint.h>

// response codes.
enum response_code : uint16_t {
	RESPONSE_REGISTRATION_SUCCESS = 2100,
	RESPONSE_REGISTRATION_FAIL = 2101,
	RESPONSE_PUBLIC_KEY = 2102,
	RESPONSE_FILE_SUCCESS = 2103,
	RESPONSE_MSG_REC = 2104
};

// Basic response header struct
#pragma pack(push, 1)
struct ResponseHeader
{
	uint8_t version;
	uint16_t code;
	uint32_t payload_size;
};
#pragma pack(pop)

// response payload struct code 1000
#pragma pack(push, 1)
struct ResponseSesuccessfulRegistrationPayload
{
	uint8_t client_id[16] = { 0 };
};
#pragma pack(pop) 

// response payload struct code 1002.
#pragma pack(push, 1)
struct ResponsePublicKeyPayload
{
	uint8_t client_id[16] = { 0 };
	uint8_t public_key[128] = { 0 };
};
#pragma pack(pop)

// response payload struct code 1004
#pragma pack(push, 1)
struct ResponseFileRec
{
	uint8_t client_id[16] = { 0 };
	uint32_t content_size;
	uint8_t file_name[255] = { 0 };
	uint32_t cksum;
};
#pragma pack(pop)
