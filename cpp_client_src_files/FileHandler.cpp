#pragma once
#include "FileHandler.h"
#include <boost/filesystem.hpp>
#include <iostream>
#include "boost/filesystem/fstream.hpp"
#include "AESWrapper.h"
#include "Chiper.h"
#include "boost/crc.hpp"

// Constructor
FileHandler::FileHandler(std::string path, std::string key) {
	_file_name = path;
	readFile(path);
	encrypt_file(key);
}

// Reads file content by path
void FileHandler::readFile(std::string path) {
	std::ifstream t(path);
	std::string data((std::istreambuf_iterator<char>(t)),
	std::istreambuf_iterator<char>());
	_file_content = data;
}

// Encrypt file content using AES Wrapper
void FileHandler::encrypt_file(std::string key) {
	AESWrapper aes((unsigned char*)key.c_str(), key.size());
	std::string ciphertext = aes.encrypt(_file_content.c_str(), _file_content.length());
	_encrypted_content = ciphertext;
}

std::string FileHandler::getEncryptedFile() { return _encrypted_content; }
std::string FileHandler::getFileName() { return _file_name; }

// Calculates CRC for client's file content and returns the result
uint32_t FileHandler::calculateCRC() {
	boost::crc_32_type result;
	result.process_bytes(_file_content.data(), _file_content.length());
	return result.checksum();
}