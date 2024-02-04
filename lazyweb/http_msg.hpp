#pragma once
/*****************************************************************************
* http_msg.h
* Http message support
*****************************************************************************/

namespace lazy
{
	class Msg
	{
	private:
		//Analysis the msg
		bool analysis();

	public:
		//Filename
		std::string filename = "";

		//Analysised data
		
		//First line
		std::string fline;
		//Header
		std::vector<std::pair<std::string, std::string>> header;
		//Parameters (after url)
		std::vector<std::pair<std::string, std::string>> par;
		//Msg main body
		std::string body;

		Msg();
		~Msg();
		
		//Load from file then analysis
		bool load_from_file(std::string filename);

		//Get string of the msg
		std::string get_str();
		//NOTICE: Remember to delete str
		bool get_str(char **str,size_t *size);

		//Delete the msg file
		bool del_file();
	};
}