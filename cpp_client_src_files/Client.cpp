#pragma once
#include "Client.h"
#include <boost/filesystem.hpp>
#include <iostream>
#include "boost/filesystem/fstream.hpp"
#include <boost/algorithm/hex.hpp>
#include "Base64Wrapper.h"
#include "utils.h"

Client::Client() {
	_id = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	try {
		// Parse transfer.info file
		boost::filesystem::ifstream input;
		input.open("transfer.info");
		if (!std::getline(input, this->_host, ':')) throw std::exception("Error: the host\'s address in the file: \'server.info\' is not right.");
		if (!std::getline(input, this->_port)) throw std::exception("Error: the port in the file: \'server.info\' is not right.");
		if (!std::getline(input, this->_name)) throw std::exception("Error: name in the file is not right");
		if (!std::getline(input, this->_file_path)) throw std::exception("Error: file path is not right.");
	}
	catch (...) {
		std::cerr << "Error: wrong input!";
	}

	if (_name.length() > 100)
		throw std::exception("Name is longer than 100 characters!");
}

// Get/Set
std::string Client::getPort() { return _port; }
std::string Client::getHost() { return _host; }
std::string Client::getFilePath() { return _file_path; }
int Client::isRegistered() {return boost::filesystem::exists("me.info");}
std::string Client::getName(){return _name;}
std::array<uint8_t, 16>& Client::getUID() {return _id;}

void Client::setUID(std::string client_id) {
	std::copy(client_id.begin(), client_id.end(), _id.data());
}

// Creates me.info txt file for a client
void Client::createMeInfo(std::string privateKey)
{	
	std::string id_str(std::begin(_id), std::end(_id));
	Base64Wrapper base64;
	std::string private_key_64 = base64.encode(privateKey);
	std::ofstream myFile("me.info");
	if (myFile)
	{
		myFile << _name << std::endl;
		myFile << stringToHex(id_str) << std::endl;
		myFile << private_key_64; // Make sure it is at base 64
		myFile.close();
	}
	else {
		std::cerr << "Error: Unable to open " << "me.info" << " file." << std::endl;
	}
}

// Reads UID from existing me.info file
void Client::readUID() {
	std::ifstream meFile("me.info");
	std::string name, id_string;
	if (meFile) {
		std::getline(meFile, name);
		std::getline(meFile, id_string);
		setUID(hexToString(id_string));
	}
}

