#pragma once
/*****************************************************************************
* lazyweb.h
* The main header of lazyweb.
*****************************************************************************/

//Defining for openssl/applink.c
#define _CRT_SECURE_NO_WARNINGS

//Cpp Standard
#include <string>
#include <vector>
#include <queue>
#include <regex>
#include <thread>
#include <iostream>
#include <fstream>
#include <ctime>

//Windows API
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"crypt32.lib")

//Open SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/applink.c>
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

//Http message support
#include "httpMsg.hpp"

/*****************************************************************************
* lazy::Web
* Main class
*****************************************************************************/
namespace lazy
{
	const int PORT_HTTP = 80;
	const int PORT_HTTPS = 443;

	//Recv, write, read, write, etc. buffer size
	const int WEB_IO_BUFSIZE = 16 * 1024;

	//Recv overtime time
	const int WEB_RECV_OVERTIME = 2*1000;

	//Auto operation overtime time
	const int WEB_AUTO_OVERTIME = 1000 * 10;

	//Address family
	//AF_INET:	IPv4
	//AF_INET6:	IPv6
	const int WEB_ADDR_FAMILY = AF_INET;

	//Web protocol
	enum class WebProt
	{
		http,		//HTTP
		https,		//HTTP + TLS/SSL
		https_quic	//HTTP + QUIC
	};
	//HTTP version
	enum class HttpVer
	{
		http_1_0,	//HTTP 1.0 (old)
		http_1_1,	//HTTP 1.1 (common)
		http_3		//HTTP 3 (UDP)
	};

	class Web
	{
	public:
		enum class Mode
		{
			undefined, client, server
		};
	private:
		WSADATA wd;

		WebProt prot;
		HttpVer httpv;

		//SSL
		SSL* ssl = nullptr;
		SSL_CTX* ctx = nullptr;
		bool verify;

		//Recv thread
		std::thread* recv_td;
		//Signals
		bool sg_end = false;	//Main->Recv: Time to quit
		bool sg_end_ok = false;	//Recv->Main: Already quit
		bool sg_recv = false;	//Main->Recv: Start to read
		static void recv_loop(Web&);

		std::string recv_path;		//Recv msg save path
		std::queue<Msg> msg_queue;	//Recv msg queue

		//For CLIENT: self's
		//For SERVER: client's
		SOCKET sock;
		SOCKET svr_sock;

		//For CLIENT: Target server addr
		//For SERVER: Bound addr
		addrinfo* addr;

		//For SERVER: Server addr
		addrinfo* cli_addr;

		//For CLIENT: Server host name
		std::string host;

		Mode mode = Mode::undefined;

		bool init_winsock_c();
		bool init_winsock_s(std::string, int);

		bool load_def_ca(SSL_CTX* ctx);
		bool check_par_ok(WebProt, HttpVer);


	public:
		Web();
		~Web();

		//Initialize as CLIENT
		bool init(WebProt, HttpVer = HttpVer::http_1_1, bool verify = true);

		//Initialize as SERVER
		bool init(std::string hostname, int port, WebProt, HttpVer = HttpVer::http_1_1,
			std::string certificate_file = "", std::string private_key_file = "");

		//Set path of received file
		bool set_recv_path(std::string);

		//For CLIENT: get the server host's name
		std::string get_hostname();
		//Get self's SOCKET
		SOCKET get_socket();
		//Get IPv4 address string
		//For CLIENT: get server's 
		//For SERVER: get client's
		std::string get_ipv4();
		//Get WSA error code
		static int get_err();
		//Get WSA error string
		static std::string get_err_str();
		//Get SSL error string
		std::string get_ssl_err_str();
		//Get mode
		Mode get_mode();
		//Get HTTP version
		HttpVer get_http_ver();
		//Get web protocol
		WebProt get_protocol();


		//Manual doing

		//For CLIENT: connect to the server
		bool connect(std::string hostname, int port, float waitSec = 3.0);
		//For CLIENT: connect to the server
		bool connect(std::string url, float waitSec = 3.0);

		//For SERVER: start to listen connection
		bool listen(int backlog = 5);
		//For SERVER: if available connection is empty [if could accept()]
		bool accept_empty();
		//For SERVER: accept connection
		bool accept();
		//For SERVER: close client connection
		bool close_client();

		//Close socket
		void close();

		//Send msg
		bool write(std::string);
		//Send msg
		bool write(MsgMaker&);

		//If the read queue is empty
		bool msg_empty();
		//Clear the read queue
		void msg_clear();
		//Read a msg in queue
		Msg read();
		//Peek a msg in queue but not pop it
		Msg peek();
	};
}

#include "webHelper.hpp"

#include "main.hpp"