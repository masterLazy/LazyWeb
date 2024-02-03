#pragma once
/*****************************************************************************
* http_msg.h
* Http message support
*****************************************************************************/

namespace lazy
{
	//From resource name get type
	std::string GetResType(std::string resourceName)
	{
		using namespace std;
		if (resourceName.find(".") == string::npos)
		{
			return "text/html";
		}
		else
		{
			string suf = resourceName.substr(resourceName.find("."));
			//text
			if (suf == ".html" || suf == ".htm")return "text/html";
			else if (suf == ".txt")return "text/plain";
			else if (suf == ".css")return "text/css";
			else if (suf == ".js")return "text/javascript";
			else if (suf == ".json")return "application/json";
			//image
			else if (suf == ".jpg" || suf == ".jpeg")return "image/jpeg";
			else if (suf == ".png")return "image/png";
			else if (suf == ".gif")return "image/gif";
			else if (suf == ".ico")return "image/x-ico";
			else if (suf == ".webp")return "image/webp";
			//audio
			else if (suf == ".mp3")return "audio/mp3";
			else if (suf == ".wav")return "audio/wav";
			//video
			else if (suf == ".mp4")return "video/mpeg4";
			else if (suf == ".avi")return "video/avi";
			//zips
			else if (suf == ".zip")return "application/x-zip-compressed";
			else if (suf == ".rar")return "application/octet-stream";
			else if (suf == ".7z")return "application/x-7z-compressed";
			else return "application/octet-stream";
		}
	}

	class Msg
	{
	private:
		//Analysis the msg
		bool analysis();

	public:
		//Filename
		std::string file = "";

		//Analysised data
		
		//First Line
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
		bool load(std::string filename);

		//Get the string of msg
		std::string get_str();

		//Delete the msg file
		bool del_file();
	};
}