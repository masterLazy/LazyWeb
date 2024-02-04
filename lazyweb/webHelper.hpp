#pragma once
/*****************************************************************************
* webHelper.h
* Auxiliary class
*****************************************************************************/

namespace lazy
{
	class WebHelper
	{
	private:
		Web* web = nullptr;
	public:
		WebHelper();
		WebHelper(Web&);
		~WebHelper();


		//String helper


		//Get time string (the one and only)
		//Example: 20130108_08-53-29_0001
		static std::string get_time_str();

		//Get date string
		//Example: Tue, 08 Jan 2013 08:53:29 GMT
		static std::string get_date_str();


		//URL helper


		//Get host name from URL
		static std::string get_url_host(std::string url);
		//Get resource name from URL
		static std::string get_url_res(std::string url);
		//Get port from URL
		static int get_url_port(std::string url);


		//File type / suf helper


		//Get file type from name 
		static std::string get_file_type(std::string filename);
		//Get file suf from type
		static std::string get_file_suf(std::string filetype);


		//URI helper
		static std::string uri_encode(const std::string& _s);
		static std::string uri_decode(const std::string& _s);


		//CLIENT helper


		bool send_get_msg(std::string url);


		//SERVER helper


	};
}