#include "utils.h"

// Utils for me.info handler
std::string stringToHex(const std::string str)
{
	std::string hexStr;
	boost::algorithm::hex_lower(str.begin(), str.end(), std::back_inserter(hexStr));
	return hexStr;
}

// Utils for me.info handling
std::string hexToString(const std::string str)
{
	std::string strHex;
	boost::algorithm::unhex(str.begin(), str.end(), std::back_inserter(strHex));
	return strHex;
}
