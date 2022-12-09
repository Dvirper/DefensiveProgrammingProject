#pragma once
#include <iostream>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include "ConnHandler.h"
#include <stdint.h>


class Client {
private:
	std::string _host, _port, _file_path, private_key, public_key, _name;
	std::array<uint8_t, 16> _id;

public:
	Client();
	int isRegistered();
	std::string getName();
	std::array<uint8_t, 16>& getUID();
	void setUID(std::string id);
	std::string getFilePath();
	void createMeInfo(std::string privateKey);
	void readUID();
	std::string getPort();
	std::string getHost();
};