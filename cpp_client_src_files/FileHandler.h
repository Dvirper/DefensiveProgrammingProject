#pragma once
#include <iostream>
class FileHandler {
private:
	std::string _file_name;
	uint32_t _cksum;
	std::string _file_content;
	std::string _encrypted_content;

public:
	void readFile(std::string path);
	void encrypt_file(std::string key);
	std::string getEncryptedFile();
	std::string getFileName();
	FileHandler(std::string path, std::string key);
	uint32_t calculateCRC();
};