#include "ConnHandler.h"
#include <iostream>
#include "Client.h"
#include  "Chiper.h"


// Basic Connection handling class for sending/rec

ConnHandler::ConnHandler(Client* client) {
	this->_skt = new boost::asio::ip::tcp::socket(_io);
	this ->_resolver = new boost::asio::ip::tcp::resolver(_io);
	this->connect(client->getHost(), client->getPort());
}

void ConnHandler::connect(std::string host, std::string port) {
	if (this->_skt->is_open()) {
		return;
	}
	try {
		boost::asio::connect(*this->_skt, this->_resolver->resolve(host, port));
	}
	catch (const std::exception& e) {
		std::cerr << e.what() << std::endl;;
		throw std::exception(e);
	}
}

void ConnHandler::disconnect() {
	if (this->_skt->is_open())
		this->_skt->close();
}


void ConnHandler::send(const char* buffer, size_t size_buffer) {
	_skt->send(boost::asio::buffer(buffer, size_buffer));
}

void ConnHandler::receive(char* buffer, size_t size_buffer) {
	this->_skt->receive(boost::asio::buffer(buffer, size_buffer));
}
