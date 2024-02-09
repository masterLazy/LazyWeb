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
		//Analysis the post body
		bool analysis_form_data();

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
		bool get_str(char** str, size_t* size);

		//Get the first line
		std::string get_fline();
		//Get the HTTP state (response msg only)
		int get_state_code();
		//Get the header items
		std::string get_header(std::string key);
		//Get the parameters (request msg only)
		std::string get_par(std::string par);
		//Get resource requested (request msg only)
		std::string get_req(std::string par);

		//If body is html (response msg only)
		bool is_html();
		//Get the string of body
		std::string get_body();
	};

	class MsgMaker
	{
	private:
		//temp
		std::string file, r, m;
		std::string body;

	public:
		int httpv;

		//First line
		std::string fline;
		//Header
		std::vector<std::pair<std::string, std::string>> header;
		//Parameters (after url)
		std::vector<std::pair<std::string, std::string>> par;

		//httpv: lazy::HttpVer
		MsgMaker(int httpv = 1);
		~MsgMaker();

		//Set the request line
		void set_request_line(std::string res, std::string method = "GET");
		//Set the state line (response msg only)
		void set_state_line(int state_code);

		//Set header
		void set_header(std::string key, std::string value);
		//Set header automaticlly
		//Support key: Connection, Date, Content-Length, Content-Type, User-Agent, Accept, Accept-Encoding
		std::string set_header(std::string key);

		//Set parameter (request msg only)
		void set_par(std::string key, std::string value);

		//Set body (response msg only)
		void set_body(std::string);
		//Load body from file (response msg only)
		bool load_body_from_file(std::string filename);

		//Make the message
		std::string make();
	};
}