#pragma once
/*****************************************************************************
* lazyweb.h
* The main header of lazyweb.
*****************************************************************************/

//Cpp Standard
#include <string>
#include <vector>
#include <queue>
#include <thread>
#include <fstream>
#include <ctime>
#ifdef _DEBUG
#include <iostream>
#endif

//Windows API
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")

//Open SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

//Http message support
#include "http_msg.hpp"

/*****************************************************************************
* lazy::Web
* Main class
*****************************************************************************/
namespace lazy
{
	const int HTTP_PORT = 80;
	const int HTTPS_PORT = 443;

	//Recv, write, read, write, etc. buffer size
	const int WEB_IO_BUFSIZE = 16 * 1024;

	//Recv overtime time
	const int WEB_RECV_OVERTIME = 1000;

	class Web
	{
	private:
		WSADATA wd;

		//SSL
		SSL* ssl = nullptr;
		SSL_CTX* ctx = nullptr;

		//Recv thread
		std::thread* recv_td;
		//Signals
		bool sg_end = false;	//Main->Recv: Time to quit
		bool sg_end_ok = false;	//Recv->Main: Already quit
		bool sg_recv = false;	//Main->Recv: Start to read
		static void recv_loop(Web&);

		std::string recv_path;		//Recv msg save path
		std::queue<Msg> msg_queue;	//Recv msg queue

		SOCKET sock;		//Self's SOCKET
		SOCKET cli_sock;

		//For CLIENT: Target server addr
		//For SERVER: Bound addr
		sockaddr_in addr;

		//For CLIENT: Server host name
		std::string host;

		enum class Mode
		{
			undefined, client, server
		}
		mode = Mode::undefined;


	public:
		bool del_msg = false;	//If delete recived msg when ~Web()

		Web();
		~Web();

		//Initialize as CLIENT
		bool init(bool startup_ssl = true);

		//Initialize as SERVER
		bool init(std::string ip, int port, bool not_startup_ssl = false);

		//Set path of received file
		bool set_recv_path(std::string);

		//Get self's SOCKET
		SOCKET get_socket();
		static int get_error();
		static std::string get_error_str();
		Mode get_mode();


		//Manual doing

		//For CLIENT: connect to the server
		bool connect(std::string host, int port, float waitSec = 3.0);
		//For CLIENT: connect to the server
		bool connect(std::string url, float waitSec = 3.0);
		//For CLIENT: get the server host's name
		std::string get_hostname();

		//For SERVER: start to listen connection
		bool listen();
		//For SERVER: accept connection
		bool accept();
		//For SERVER: close connection
		bool close_connect();

		//Close socket
		void close();

		//Send msg
		bool write(std::string);
		//Send msg
		bool write(Msg*);

		//If the read queue is empty
		bool msg_empty();
		//Clear the read queue
		void msg_clear();
		//Read a msg for read queue
		Msg read();
	};
}

#include "webHelper.hpp"

#include "main.hpp"