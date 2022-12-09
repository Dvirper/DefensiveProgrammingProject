#pragma once
#include <boost/asio.hpp>
#include "Chiper.h"
class ConnHandler {

	friend class Client;
	friend class Chiper;
	
protected:
	boost::asio::io_context _io;
	boost::asio::ip::tcp::socket* _skt;
	boost::asio::ip::tcp::resolver* _resolver;

public:
	ConnHandler(Client* _client);
	void connect(std::string host, std::string port);
	void disconnect();
	void send(const char* buffer, size_t size_buffer);
	void receive(char* buffer, size_t size_buffer);
};


