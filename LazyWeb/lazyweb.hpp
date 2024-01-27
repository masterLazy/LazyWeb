#pragma once
/*****************************************************************************
* lazyweb.h
* The main header of lazyweb.
*****************************************************************************/

//STL
#include <string>
#include <vector>
#include <thread>

//Windows API
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")

//Open SSL
#include <openssl\ssl.h>
#include <openssl\err.h>
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

/*****************************************************************************
* lazy::Web
* Main class
*****************************************************************************/
namespace lazy
{
	class Web
	{
	private:
		bool inited = false;

	public:
		bool del_msg = false;	//Whether delete recived msg when ~Web()

		Web();
		~Web();

		//Run init() first
		bool init();


		//Manual doing


		bool connect();

		bool close();

		bool send_msg(Msg*);

		//Whether the queue of recived msg is empty
		bool recv_empty();

		bool read_msg(Msg*);


		//Helper doing
		class
		{
			//Client helper

			bool download(Msg*);


			//Server helper

		}helper;
	};
}
#include "main.hpp"

//Http message support
#include "http_msg.hpp"