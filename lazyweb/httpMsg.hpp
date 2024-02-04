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

		//Analysised data

		//First line
		std::string fline;
		//Header
		std::vector<std::pair<std::string, std::string>> header;
		//Parameters (after url)
		std::vector<std::pair<std::string, std::string>> par;

	public:
		//Filename
		std::string filename = "";

		Msg();
		~Msg();
		
		//Load from file then analysis
		bool load_from_file(std::string filename);
		//Delete the msg file
		bool del_file();

		//Get string of the msg file
		std::string get_str();
		//NOTICE: Remember to delete str
		bool get_str(char **str,size_t *size);

		//Get the first line
		std::string get_fline();
		//Get the HTTP state (response msg only)
		int get_state_code();
		//Get the header items
		std::string get_header(std::string item);
		//Get the parameters (request msg only)
		std::string get_par(std::string par);
	};
}