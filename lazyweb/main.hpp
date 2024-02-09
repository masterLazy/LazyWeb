#pragma once
/*****************************************************************************
* main.hpp
* The realization of lazy::web
*****************************************************************************/


//lazy::Web


lazy::Web::Web()
{
	set_recv_path("recv/");
}
lazy::Web::~Web()
{
	if (mode != Mode::undefined)close();
	sg_end = true;
	while (sg_end_ok);
	delete recv_td;
}

void lazy::Web::recv_loop(Web& web)
{
	using namespace std;

	ofstream of;

	bool recving = false;
	string filename;
	char* buf = new char[WEB_IO_BUFSIZE + 1];
	memset(buf, 0, WEB_IO_BUFSIZE + 1);
	clock_t timer = 0;

	int res;
	while (!web.sg_end)
	{
		if (web.sg_recv)
		{
			memset(buf, 0, WEB_IO_BUFSIZE + 1);

			//SSL
			if (web.ssl != nullptr)
			{
				res = SSL_read(web.ssl, buf, WEB_IO_BUFSIZE);
			}
			//WinSock
			else
			{
				res = recv(web.sock, buf, WEB_IO_BUFSIZE, NULL);
			}

			//Recv begin
			if (buf[0] != '\0')
			{
				if (recving == false)
				{
					recving = true;
					string path = web.recv_path + WebHelper::get_time_str();
					CreateDirectoryA(path.c_str(), NULL);
					filename = path + "/msg" + ".dat";

					if (of.is_open())of.close();
					of.open(filename, ios::binary);
#ifdef _DEBUG
					cout << "[recv_thread] Recv begin." << endl;
#endif
				}
				string temp(buf);
				for (int i = 0; i < res; i++)
				{
					of << buf[i];
				}
				timer = clock();
			}
		}
		//Recv complete
		if (recving == true && (clock() - timer > WEB_RECV_OVERTIME || !web.sg_recv))
		{
			recving = false;
			of.close();

			Msg msg;
			msg.load_from_file(filename);
			web.msg_queue.push(msg);
#ifdef _DEBUG
			cout << "[recv_thread] Recv completed." << endl;
#endif
		}
	}
	delete buf;
	if (of.is_open())of.close();
	web.sg_end_ok = true;
}

bool lazy::Web::load_def_ca(SSL_CTX* ctx)
{
	using namespace std;
	//Using windows API to get system pre-installed CA certs
	HCERTSTORE hStore = CertOpenSystemStore(0, L"ROOT");
	if (hStore == NULL)
	{
#ifdef _DEBUG
		cout << "Error: Failed to load CA certificate: CertOpenSystemStore() failed." << endl;
#endif
		return false;
	}

	//Enum and load
	PCCERT_CONTEXT cert = NULL;
	X509_STORE* store = X509_STORE_new();
	while ((cert = CertEnumCertificatesInStore(hStore, cert)) != NULL)
	{
		//.cer->.pem
		X509* x509 = d2i_X509(NULL, (const unsigned char**)&cert->pbCertEncoded, cert->cbCertEncoded);

		X509_STORE_add_cert(store, x509);

		X509_free(x509);
	}
	SSL_CTX_set_cert_store(ctx, store);
	//X509_STORE_free(store);

	//Check the number of CA certs
	X509_STORE* store_c = SSL_CTX_get_cert_store(ctx);
	STACK_OF(X509)* certs = X509_STORE_get1_all_certs(store_c);
	if (certs != NULL)
	{
		int num_certs = sk_X509_num(certs);
		if (num_certs <= 0)
		{
#ifdef _DEBUG
			cout << "Error: Failed to load CA certificate. " << endl;
#endif
			CertCloseStore(hStore, 0);
			return false;
		}
#ifdef _DEBUG
		cout << "Notice: Loaded " << num_certs << " CA certificate(s)." << endl;
#endif
	}
	else
	{
#ifdef _DEBUG
		cout << "Error: Failed to load CA certificate." << endl;
#endif
		CertCloseStore(hStore, 0);
		return false;
	}

	CertCloseStore(hStore, 0);
	return true;
}
bool lazy::Web::check_par_ok(WebProt p, HttpVer v)
{
	if ((p == WebProt::http || p == WebProt::https) &&
		v == HttpVer::http_3)
	{
		return false;
	}
	if (p == WebProt::https_quic && v != HttpVer::http_3)
	{
#ifdef _DEBUG
		std::cout << "Warning: Using QUIC not but using HTTP 3." << std::endl;
#endif
	}
	return true;
}


bool lazy::Web::set_recv_path(std::string path)
{
	//Format
	while (path.find('\\') != std::string::npos)
	{
		path[path.find('\\')] = '/';
	}
	if (path.back() != '/')
	{
		path.push_back('/');
	}

	bool res = CreateDirectoryA(path.c_str(), NULL);
	if (!res && GetLastError() != ERROR_ALREADY_EXISTS)
	{
#ifdef _DEBUG
		std::cout << "Failed to set recv path: failed to create directory" << std::endl;
#endif
		return false;
	}
	recv_path = path;
	return true;
}

//Client
bool lazy::Web::init_winsock_c()
{
	int res;
	//Startup WSA
	res = WSAStartup(MAKEWORD(2, 2), &wd);
	if (res != 0)
	{
#ifdef _DEBUG
		std::cout << "Error: Failed to startup WSA." << std::endl;
#endif
		return false;
	}


	//Create SOCKET
	if (prot != WebProt::https_quic)
	{
		sock = socket(WEB_ADDR_FAMILY, SOCK_STREAM, 0);//TCP
	}
	else
	{
		sock = socket(WEB_ADDR_FAMILY, SOCK_DGRAM, 0);//UDP
	}
	if (sock == -1)
	{
#ifdef _DEBUG
		std::cout << "Error: Failed to create SOCKET: " << get_err_str() << "." << std::endl;
#endif
		close();
		return false;
	}
	//Set SOCKET non-blocking
	u_long ul = 1;
	ioctlsocket(sock, FIONBIO, &ul);

	//Link
	if (ssl != nullptr)SSL_set_fd(ssl, sock);


	//Create thread
	recv_td = new std::thread(recv_loop, std::ref(*this));
	recv_td->detach();

	return true;
}
bool lazy::Web::init(lazy::WebProt p, lazy::HttpVer v, bool _verify)
{
	using namespace std;
	//If parameters are valid
	if (!check_par_ok(p, v))
	{
#ifdef _DEBUG
		cout << "Error: Failed to initialize: Web protocol does not match HTTP version." << endl;
#endif
		return false;
	}
	verify = _verify;
	prot = p;
	v = httpv;

	int res;
	//Startup SSL
	if (p == WebProt::https || p == WebProt::https_quic)
	{
		OpenSSL_add_all_algorithms();
		SSL_library_init();
		SSL_load_error_strings();
		SSLeay_add_ssl_algorithms();
		//Create CTX
		if (p == WebProt::https)
		{
			ctx = SSL_CTX_new(TLS_client_method());
		}
		else if (p == WebProt::https_quic)
		{
			ctx = SSL_CTX_new(OSSL_QUIC_client_method());
		}
		if (ctx == NULL)
		{
#ifdef _DEBUG
			cout << "Error: Failed to initialize: Failed to create SSL_CTX." << endl;
#endif
			return false;
		}
		//Set verify mode
		SSL_CTX_set_verify(ctx, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);
		if (verify)
		{
			//Load CA certificate
			if (!load_def_ca(ctx))return false;
		}
		//Create SSL
		ssl = SSL_new(ctx);
		if (ssl == NULL)
		{
#ifdef _DEBUG
			cout << "Error: Failed to initialize: Failed to create SSL." << endl;
#endif
			SSL_CTX_free(ctx);
			return false;
		}
		SSL_set_verify(ssl, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);
	}

	bool bRes = init_winsock_c();
	if (!bRes)return false;
	mode = Mode::client;
	return true;
}
bool lazy::Web::connect(std::string hostname, int port, float waitSec)
{
	using namespace std;
	host = hostname;

	if (mode != Mode::client)
	{
#ifdef _DEBUG
		if (mode == Mode::undefined)
		{
			cout << "Error: Failed to connect: Not initialized." << endl;
		}
		else
		{
			cout << "Error: Failed to connect: Should be in client mode." << endl;
		}
#endif
		return false;
	}

#ifdef _DEBUG
	if (port == PORT_HTTP && ssl != nullptr)
	{
		cout << "Warning: Using http port (80) but using SSL." << endl;
	}
	if (port == PORT_HTTPS && ssl == nullptr)
	{
		cout << "Warning: Using https port (443) but not using SSL." << endl;
	}
#endif

	int res, err = 0;

	//Set addrinfo
	addrinfo hints, * result;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = WEB_ADDR_FAMILY;
	if (prot != WebProt::https_quic)
	{
		hints.ai_socktype = SOCK_STREAM;//TCP
	}
	else
	{
		hints.ai_socktype = SOCK_DGRAM;//UDP
	}
	//Set port
	string ports = to_string(port);
	if (getaddrinfo(hostname.c_str(), ports.c_str(), &hints, &result) != 0)
	{
#ifdef _DEBUG
		cout << "Error: Failed to connect: getaddrinfo() failed." << endl;
#endif
		return false;
	}
	addr = result;

	//QUIC
	if (prot == WebProt::https_quic)
	{
		//Set ALPN
		//unsigned char alpn[] = { 2, 'h', '3' };
		string alpn;
		switch (httpv)
		{
		case lazy::HttpVer::http_1_0:
			alpn = "HTTP/1.0";
			break;
		case lazy::HttpVer::http_1_1:
			alpn = "HTTP/1.1";
			break;
		case lazy::HttpVer::http_3:
			alpn = "h3";
			break;
		}
		alpn.insert(alpn.begin(), alpn.size());
		if (SSL_set_alpn_protos(ssl, (unsigned char*)alpn.c_str(), alpn.size()) != 0)
		{
			cout << "Error: Failed to init: Failed to set ALPN." << endl;
			return -1;
		}
		//Set peer addr
		BIO_ADDR* peer_addr = (BIO_ADDR*)(addr->ai_addr);
		if (SSL_set1_initial_peer_addr(ssl, peer_addr) == 0)
		{
			cout << "Error: Failed to set the initial peer address." << endl;
			return -1;
		}
	}


	clock_t timer = clock();
	//Connect (WinSock)
	while (clock() - timer <= waitSec * 1000)
	{
		res = ::connect(sock, addr->ai_addr, addr->ai_addrlen);
		if (res == 0)break;
		else
		{
			err = WSAGetLastError();
			if (err != WSAEWOULDBLOCK && err != WSAEALREADY)
				//WSAEWOULDBLOCK: Target server is busy
				//WSAEALREADY: Operation has done
			{
				break;
			}
		}
	}
	if (clock() - timer > waitSec * 1000)
	{
#ifdef _DEBUG
		cout << "Error: Failed to connect: TCP connection overtime. "
			<< get_err_str() << "." << endl;
#endif
		return false;
	}

	//Connect (SSL)
	if (ssl != nullptr)
	{
		//TLS ex
		if (!SSL_set_tlsext_host_name(ssl, hostname.c_str()))
		{
#ifdef _DEBUG
			cout << "Warning: Failed to set the SNI hostname." << endl;
#endif
		}
		if (!SSL_set1_host(ssl, hostname.c_str()))
		{
#ifdef _DEBUG
			cout << "Warning: Failed to set the SNI hostname." << endl;
#endif
		}

		SSL_set_connect_state(ssl);
		while (clock() - timer <= waitSec * 1000)
		{
			res = SSL_connect(ssl);
			if (res == 0)break;

			err = SSL_get_error(ssl, res);
			if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
			{
				break;
			}
		}
		if (err != SSL_ERROR_NONE)
		{
#ifdef _DEBUG
			cout << "Error: Failed to connect. ";
			if (clock() - timer > waitSec * 1000)
			{
				cout << "SSL connection overtime. ";
			}
			if (err == SSL_ERROR_SYSCALL)
			{
				cout << get_err_str() << get_ssl_err_str() << "." << endl;
			}
			else
			{
				cout << get_ssl_err_str() << "." << endl;
			}
#endif
			return false;
		}

		//Verify
		if (verify)
		{
			if (SSL_get_verify_result(ssl) != X509_V_OK)
			{
				cout << "Warning: Server certificate verification failed." << endl;
			}
			else
			{
#ifdef _DEBUG
				cout << "Notice: Server certificate verified." << endl;
#endif
			}
		}
	}

	//Send signal
	sg_recv = true;
	return true;
}
bool lazy::Web::connect(std::string url, float waitSec)
{
	return connect(WebHelper::get_url_host(url), WebHelper::get_url_port(url), waitSec);
}

//Server
bool lazy::Web::init_winsock_s(std::string hostname, int port)
{
	using namespace std;
	int res;
	//Startup WSA
	res = WSAStartup(MAKEWORD(2, 2), &wd);
	if (res != 0)
	{
#ifdef _DEBUG
		std::cout << "Error: Failed to startup WSA." << std::endl;
#endif
		return false;
	}


	//Create SOCKET
	svr_sock = socket(WEB_ADDR_FAMILY, SOCK_STREAM, 0);
	if (sock == -1)
	{
#ifdef _DEBUG
		std::cout << "Error: Failed to create SOCKET: " << get_err_str() << "." << std::endl;
#endif
		close();
		return false;
	}
	//Set SOCKET non-blocking
	u_long ul = 1;
	ioctlsocket(svr_sock, FIONBIO, &ul);


	//Set addrinfo
	addrinfo hints, * result;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = WEB_ADDR_FAMILY;
	hints.ai_socktype = SOCK_STREAM;//TCP
	//Set port
	string ports = to_string(port);
	if (getaddrinfo(hostname.c_str(), ports.c_str(), &hints, &result) != 0)
	{
#ifdef _DEBUG
		cout << "Error: Failed to connect: getaddrinfo() failed." << endl;
#endif
		return false;
	}
	addr = result;

	//Bind addr(Name socket)
	if (bind(svr_sock, addr->ai_addr, addr->ai_addrlen) == -1)
	{
		close();
#ifdef _DEBUG
		std::cout << "Error: Failed to bind SOCKET: " << get_err_str() << "." << std::endl;
#endif
		return false;
	}

	//Create thread
	recv_td = new std::thread(recv_loop, std::ref(*this));
	recv_td->detach();

	return true;
}
bool lazy::Web::init(std::string ip, int port, lazy::WebProt p, lazy::HttpVer v, std::string cert, std::string key)
{
	using namespace std;
	//If parameters are valid
	if (!check_par_ok(p, v))
	{
#ifdef _DEBUG
		cout << "Error: Failed to initialize: Web protocol doesn't match HTTP version." << endl;
#endif
		return false;
	}
	if (p == WebProt::https_quic || v == HttpVer::http_3)
	{
#ifdef _DEBUG
		cout << "Error: Failed to initialize: Server doesn't support QUIC or HTTP 3." << endl;
#endif
		return false;
	}
	if (!cert.empty() && key.empty())
	{
#ifdef _DEBUG
		cout << "Error: Failed to initialize: Not set private key file." << endl;
#endif
		return false;
	}
	if (cert.empty() && !key.empty())
	{
#ifdef _DEBUG
		cout << "Error: Failed to initialize: Not set certificate file." << endl;
#endif
		return false;
	}
	verify = !cert.empty();
	prot = p;
	v = httpv;

	int res;
	//Startup SSL
	if (p == WebProt::https)
	{
		OpenSSL_add_all_algorithms();
		SSL_library_init();
		SSL_load_error_strings();
		SSLeay_add_ssl_algorithms();
		//Create CTX
		ctx = SSL_CTX_new(TLS_server_method());
		//Set verify method
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		//Create SSL
		ssl = SSL_new(ctx);
		SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

		if (verify)
		{
			if (SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM) != 1)
			{
#ifdef _DEBUG
				cout << "Error: Failed to initialize: Failed to set certificate file." << endl;
#endif
				return false;
			}
			if (SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) != 1)
			{
#ifdef _DEBUG
				cout << "Error: Failed to initialize: Failed to set private key file." << endl;
#endif
				return false;
			}
			if (SSL_CTX_check_private_key(ctx) != 1)
			{
#ifdef _DEBUG
				cout << "Error: Failed to initialize: Failed to check certificate file and private key file." << endl;
#endif
				return false;
			}
		}
	}

	bool bRes = init_winsock_s(ip, port);
	if (!bRes)return false;
	mode = Mode::server;
	return true;
}
bool lazy::Web::listen(int backlog)
{
	using namespace std;
	if (mode != Mode::server)
	{
#ifdef _DEBUG
		if (mode == Mode::undefined)
		{
			cout << "Error: Failed to connect: Not initialized." << endl;
		}
		else
		{
			cout << "Error: Failed to connect: Should be in server mode." << endl;
		}
#endif
		return false;
	}

	if (::listen(svr_sock, backlog) != 0)
	{
#ifdef _DEBUG
		cout << "Error: Failed to listen. "
			<< get_err_str() << "." << endl;
#endif
		return false;
	}
	return true;
}
bool lazy::Web::accept_empty()
{
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(svr_sock, &fds);
	timeval timeout = { 0 };
	int res = select(NULL, &fds, NULL, NULL, &timeout);
	if (res == SOCKET_ERROR)
	{
#ifdef _DEBUG
		std::cout << "Error: SOCKET error." << std::endl;
#endif
		return false;
	}
	return res == 0;
}
bool lazy::Web::accept()
{
	//Connect (WinSock)
	sockaddr_in _addr = { 0 };
	int len = sizeof(_addr);
	sock = ::accept(svr_sock, (sockaddr*)&_addr, &len);
	if (sock == -1)
	{
#ifdef _DEBUG
		std::cout << "Error: Failed to accept connection. " <<
			get_err_str() << std::endl;
#endif
		return false;
	}

	//Connect (SSL)
	if (ssl != nullptr)
	{
		SSL_set_fd(ssl, sock);
		SSL_set_accept_state(ssl);
		int res = 0;
		while (res == -1)res = SSL_accept(ssl);
		if (res != 1)
		{
			if (SSL_get_error(ssl, res) == SSL_ERROR_SYSCALL)
			{
				std::cout << "Error: Failed to accept connection. " <<
					get_err_str() << std::endl;
			}
			else
			{
#ifdef _DEBUG
				std::cout << "Error: Failed to accept connection: SSL error. " <<
					get_ssl_err_str() << std::endl;
#endif
			}
			//close_client();
			//return false;
		}
	}

	//sockaddr->addrinfo
	char cliIP[INET_ADDRSTRLEN] = { 0 };
	inet_ntop(WEB_ADDR_FAMILY, &_addr.sin_addr, cliIP, INET_ADDRSTRLEN);

	addrinfo hints, * result;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = WEB_ADDR_FAMILY;
	hints.ai_socktype = SOCK_STREAM;//TCP

	if (getaddrinfo(cliIP, NULL, &hints, &result) != 0)
	{
#ifdef _DEBUG
		std::cout << "Error: Failed to accept connection: getaddrinfo() failed." << std::endl;
#endif
		close_client();
		return false;
	}
	cli_addr = result;


	sg_recv = true;
	return true;
}
bool lazy::Web::close_client()
{
	sg_recv = false;
	freeaddrinfo(cli_addr);
	if (::closesocket(sock) != 0)
	{
#ifdef _DEBUG
		std::cout << "Error: Failed to close client connection: Failed to get addrinfo. " <<
			get_err_str() << std::endl;
#endif
		return false;
	}
	return true;
}

bool lazy::Web::write(std::string msg)
{
	using namespace std;
	if (mode == Mode::undefined)
	{
#ifdef _DEBUG
		cout << "Error: Failed to write: Not initialized." << endl;
#endif
		return false;
	}

	if (ssl != nullptr)
	{
		if (SSL_get_state(ssl) != TLS_ST_OK)
		{
#ifdef _DEBUG
			cout << "Error: Failed to write: SSL state error. The SSL state is \"" <<
				SSL_state_string_long(ssl) << "\"(" << SSL_get_state(ssl) << ")" << "." << endl;
#endif
			return false;
		}
	}

	size_t written = 0;
	int res, err;
	//SSL
	if (ssl != nullptr)
	{
		int n = 0;
		while (true)
		{
			res = SSL_write_ex(ssl, msg.c_str(), msg.size(), &written);
			n += written;
			if (n >= msg.size())break;

			err = SSL_get_error(ssl, res);
			switch (err)
			{
			case SSL_ERROR_NONE:
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				continue;

			case SSL_ERROR_SYSCALL:
				if (get_err() == WSAEWOULDBLOCK ||
					get_err() == WSAEALREADY)continue;
#ifdef _DEBUG
				cout << "Error: Failed to write: " << get_err_str() << "." << endl;
#endif
				return false;

			default:
#ifdef _DEBUG
				cout << "Error: Failed to write: " <<
					get_ssl_err_str() << "." << endl;
#endif
				return false;
			}
		}
	}
	//TCP
	else
	{
		res = send(sock, msg.c_str(), msg.size(), NULL);
		if (res < 0)
		{
#ifdef _DEBUG
			cout << "Error: Failed to write: " << get_err_str() << "." << endl;
#endif
			return false;
		}
	}
	return true;
}
bool lazy::Web::write(lazy::MsgMaker& msg)
{
	return write(msg.make());
}

bool lazy::Web::msg_empty()
{
	return msg_queue.empty();
}
void lazy::Web::msg_clear()
{
	while (!msg_queue.empty())msg_queue.pop();
}
lazy::Msg lazy::Web::read()
{
	if (msg_queue.empty())
	{
#ifdef _DEBUG
		std::cout << "Error: Failed to read msg: Msg queue is empty." << std::endl;
#endif
		return Msg();
	}
	Msg m = msg_queue.back();
	msg_queue.pop();
	return m;
}
lazy::Msg lazy::Web::peek()
{
	if (msg_queue.empty())
	{
#ifdef _DEBUG
		std::cout << "Error: Failed to peek msg: Msg queue is empty." << std::endl;
#endif
		return Msg();
	}
	return msg_queue.back();
}

std::string lazy::Web::get_hostname()
{
	return host;
}
SOCKET lazy::Web::get_socket()
{
	return sock;
}
std::string lazy::Web::get_ipv4()
{
	addrinfo* info;
	if (mode == Mode::client)info = addr;
	else if (mode == Mode::server)info = cli_addr;
	else return "";

	if (info == NULL)return "";
	char str[INET_ADDRSTRLEN] = { 0 };
	inet_ntop(info->ai_family, &((sockaddr_in*)info->ai_addr)->sin_addr, str, INET_ADDRSTRLEN);
	return str;
}
int lazy::Web::get_err()
{
	return WSAGetLastError();
}
std::string lazy::Web::get_err_str()
{
	int err = WSAGetLastError();
	char* temp = nullptr;

	DWORD result = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, err, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
		(LPSTR)&temp, 0, NULL);

	if (result == 0)
	{
		return "(" + std::to_string(err) + ")";
	}

	std::string res(temp);
	LocalFree(temp);

	res.erase(res.size() - 3);
	return res + "(" + std::to_string(err) + ")";
}
std::string lazy::Web::get_ssl_err_str()
{
	unsigned long err = ERR_get_error();
	const char* s = ERR_reason_error_string(err);
	if (s == NULL || s[0] == '\0')return "(" + std::to_string(err) + ")";

	std::string str = s;
	if (str == "ca md too weak")str = "CA MD too weak";
	else if (str == "ee key too small")str = "EE key too small";
	else if (str == "nested asn1 error")str = "Nested ASN1 error";
	else str[0] = std::toupper(str[0]);
	str += "(" + std::to_string(err) + ")";
	return str;
}
lazy::Web::Mode lazy::Web::get_mode()
{
	return mode;
}
lazy::HttpVer lazy::Web::get_http_ver()
{
	return httpv;
}
lazy::WebProt lazy::Web::get_protocol()
{
	return prot;
}

void lazy::Web::close()
{
	sg_recv = false;
	if (mode == Mode::server)
	{
		close_client();
		closesocket(svr_sock);
	}
	else
	{
		closesocket(sock);
	}
	WSACleanup();
	freeaddrinfo(addr);
	if (ssl != nullptr)
	{
		SSL_shutdown(ssl);
		SSL_clear(ssl);
		SSL_CTX_free(ctx);
		ssl = nullptr;
		ctx = nullptr;
	}
	mode = Mode::undefined;
}


//lazy::Msg


lazy::Msg::Msg() {}
lazy::Msg::~Msg() {}

bool lazy::Msg::analyse()
{
	using namespace std;
	string msg = get_str();

	//analyse msg header

	//First line
	if (msg.find("\r\n") == string::npos)
	{
#ifdef _DEBUG
		cout << "Error: Failed to analyse msg: Invalid format." << endl;
#endif
		return false;
	}
	fline = msg.substr(0, msg.find("\r\n"));

	//Header
	size_t i = msg.find("\r\n") + 2;
	header.clear();
	while (true)
	{
		//analyse one line
		string key = msg.substr(i, msg.find(": ", i) - i);
		string value = msg.substr(msg.find(": ", i) + 2, msg.find("\r\n", i) - (msg.find(": ", i) + 2));
		header.push_back({ key, value });

		if (msg.find("\r\n\r\n") == msg.find("\r\n", i))
		{
			break;
		}
		i = msg.find("\r\n", i) + 2;

	}

	//Parameters
	string pars;
	if (fline.find("GET") != string::npos)
	{
		if (fline.find("?") != string::npos)
		{
			pars = fline.substr(fline.find("?") + 1, fline.find(" HTTP") - fline.find("?") - 1);
		}
	}
	if (!pars.empty())
	{
		i = 0;
		while (pars.find("&", i) != string::npos)
		{
			par.push_back({
				pars.substr(i, pars.find("=", i) - i),
				WebHelper::uri_decode(pars.substr(pars.find("=", i) + 1, pars.find("&", i) - pars.find("=", i) - 1)),
				});
			i = pars.find("&", i) + 1;
		}
		par.push_back({
				pars.substr(i, pars.find("=", i) - i),
				WebHelper::uri_decode(pars.substr(pars.find("=", i) + 1)),
			});
	}


	//analyse msg body
	if (get_header("Content-Type").find("multipart/form-data") != string::npos)
	{
		return analyse_form_data();
	}
	else
	{
		//Check if there is body
		i = msg.find("\r\n\r\n") + 4;
		if (msg.size() - i != 0)
		{
			//Save body to file
			string fname = filename.substr(0, filename.find_last_of('/') + 1) + "msg_body" + WebHelper::get_file_suf(get_header("Content-Type"));
			ofstream of;
			of.open(fname, ios::binary);
			if (!of.is_open())
			{
#ifdef _DEBUG
				cout << "Error: Failed to save msg body: Failed to open file." << endl;
#endif
				return false;
			}
			for (size_t j = i; j < msg.size(); j++)
			{
				of << msg[j];
			}
			of.close();
		}
	}
	return true;
}
bool lazy::Msg::analyse_form_data()
{
	using namespace std;
	//Get the boundary
	string type = get_header("Content-Type");
	string bdy = type.substr(type.find("boundary=") + 9);

	//Split
	string msg = get_str();
	int i = msg.find("\r\n\r\n") + 4;

	//Begin boundary: --[bdy]
	//End boundary: --[bdy]--
	int end_pos = msg.find("--" + bdy + "--", i);
	int num = 0, next = msg.find("--" + bdy, i);

	while (true)
	{
		//Goto next
		i = next;
		if (i == end_pos)break;

		//Save part to file
		next = msg.find("--" + bdy, i + bdy.size());
		string fname = filename.substr(0, filename.find_last_of('/') + 1) + "form-data_" + to_string(num) + ".dat";
		ofstream of;
		of.open(fname, ios::binary);
		if (!of.is_open())
		{
#ifdef _DEBUG
			cout << "Error: Failed to save msg form-data: Failed to open file." << endl;
#endif
			return false;
		}
		//+4 for "--" before bdy and "\r\n" after
		for (size_t j = i + bdy.size() + 4; j < next; j++)
		{
			of << msg[j];
		}
		of.close();

		//Save part body to file
		//Get file suf
		string suf = "";
		int iType = msg.find("Content-Type: ", i);
		if (iType != string::npos)
		{
			suf = WebHelper::get_file_suf(msg.substr(msg.find(":", iType) + 2, msg.find("\r\n", iType) - msg.find(":", iType) - 2));
		}
		//Save
		fname = filename.substr(0, filename.find_last_of('/') + 1) + "form-data_" + to_string(num) + suf;
		of.open(fname, ios::binary);
		if (!of.is_open())
		{
#ifdef _DEBUG
			cout << "Error: Failed to save msg form-data: Failed to open file." << endl;
#endif
			return false;
		}
		//-2 for "\r\n" after data
		for (size_t j = msg.find("\r\n\r\n", i) + 4; j < next - 2; j++)
		{
			of << msg[j];
		}
		of.close();


		num++;
	}


	return true;
}

bool lazy::Msg::load_from_file(std::string _filename)
{
	using namespace std;

	ifstream f;
	f.open(_filename);
	if (!f.is_open())
	{
#ifdef _DEBUG
		cout << "Error: Failed to load msg: cannot open file." << endl;
#endif
		return false;
	}
	f.close();

	filename = _filename;

	return analyse();
}
bool lazy::Msg::del_file()
{
	return DeleteFileA(filename.c_str());
}

std::string lazy::Msg::get_str()
{
	using namespace std;

	ifstream f;
	f.open(filename, ios::binary);
	if (!f.is_open())
	{
#ifdef _DEBUG
		cout << "Error: Failed to get msg string: Failed to open file." << endl;
#endif
		return "";
	}

	string res;
	char* buf = new char[WEB_IO_BUFSIZE + 1];
	memset(buf, 0, WEB_IO_BUFSIZE + 1);
	while (!f.eof())
	{
		f.read(buf, WEB_IO_BUFSIZE);
		for (size_t i = 0; i < f.gcount(); i++)
		{
			res += buf[i];
		}
	}
	delete buf;
	f.close();
	return res;
}
bool lazy::Msg::get_str(char** str, size_t* pSize)
{
	using namespace std;

	ifstream f(filename, ios::binary);
	if (!f.is_open())
	{
#ifdef _DEBUG
		cout << "Error: Failed to get msg string: Failed to open file." << endl;
#endif
		return false;
	}

	//Get file size
	f.seekg(0, ios::end);
	size_t size = f.tellg();
	*pSize = size;
	f.seekg(0, ios::beg);

	char* buf = new char[size + 1];
	memset(buf, 0, size + 1);
	f.read(buf, size);
	f.close();

	*str = buf;

	return true;
}

std::string lazy::Msg::get_fline()
{
	return fline;
}
int lazy::Msg::get_state_code()
{
	if (fline[0] != 'H')return 0;
	//           "HTTP/1.1 ".size = 9
	std::string code = fline.substr(9, fline.find_last_of(' ') - 9);
	return stoi(code);
}
std::string lazy::Msg::get_header(std::string key)
{
	if (header.empty())return "";
	for (size_t i = 0; i < header.size(); i++)
	{
		if (header[i].first == key)return header[i].second;
	}
	return "";
}
std::string lazy::Msg::get_par(std::string key)
{
	if (par.empty())return "";
	for (size_t i = 0; i < par.size(); i++)
	{
		if (par[i].first == key)return par[i].second;
	}
}
std::string lazy::Msg::get_req(std::string par)
{
	using namespace std;
	if (fline.empty())return "";
	if (fline.find(" ") == string::npos ||
		fline.find(" HTTP") == string::npos)
	{
		return "";
	}
	if (fline.find("?") == string::npos)
	{
		return fline.substr(fline.find(" ") + 1, fline.find(" HTTP") - (fline.find(" ") + 1));
	}
	else
	{
		return fline.substr(fline.find(" ") + 1, fline.find("?") - (fline.find(" ") + 1));
	}
}

bool lazy::Msg::is_html()
{
	return (WebHelper::get_file_suf(get_header("Content-Type")) == ".html");
}
std::string lazy::Msg::get_body()
{
	using namespace std;

	ifstream f;
	f.open(filename.substr(0, filename.find_last_of('/') + 1) + "body" + WebHelper::get_file_suf(get_header("Content-Type")),
		ios::binary);
	if (!f.is_open())
	{
#ifdef _DEBUG
		cout << "Error: Failed to get body string: Failed to open file." << endl;
#endif
		return "";
	}

	string res;
	char* buf = new char[WEB_IO_BUFSIZE + 1];
	memset(buf, 0, WEB_IO_BUFSIZE + 1);
	while (!f.eof())
	{
		f.read(buf, WEB_IO_BUFSIZE);
		res += buf;
	}
	delete buf;
	f.close();
	return res;
}


//lazy::MsgMaker


lazy::MsgMaker::MsgMaker(int hv)
{
	httpv = hv;
}
lazy::MsgMaker::~MsgMaker() {}

void lazy::MsgMaker::set_request_line(std::string res, std::string method)
{
	r = res;
	m = method;

	fline = method;
	fline += " ";
	fline += res;
	if (!par.empty())
	{
		fline += "?";
		for (int i = 0; i < par.size(); i++)
		{
			if (i > 0)fline += "&";
			fline += par[i].first;
			fline += "=";
			fline += WebHelper::uri_encode(par[i].second);
		}
	}
	if (httpv == (int)HttpVer::http_1_1)fline += " HTTP/1.1";
	else if (httpv == (int)HttpVer::http_1_0)fline += " HTTP/1.0";
}
void lazy::MsgMaker::set_state_line(int state)
{
	fline.clear();
	if (httpv == (int)HttpVer::http_1_1)fline += "HTTP/1.1 ";
	else if (httpv == (int)HttpVer::http_1_0)fline += "HTTP/1.0 ";
	switch (state)
	{
		//信息
	case 100:fline += "100 Continue"; break;
		//成功
	case 200:fline += "200 OK"; break;
		//重定向
	case 301:fline += "301 Moved Permanently"; break;
	case 302:fline += "302 Found"; break;
	case 304:fline += "304 Not Modified"; break;
	case 307:fline += "307 Temporary Redirect"; break;
		//客户端错误
	case 400:fline += "400 Bad Request"; break;
	case 401:fline += "401 Unauthorized"; break;
	case 403:fline += "403 Forbidden"; break;
	case 404:fline += "404 Not Found"; break;
		//服务器错误
	case 500:fline += "500 Internal Server Error"; break;
	case 503:fline += "503 Service Unavailable"; break;
	default:fline += "500 Internal Server Error"; break;
	}
}

void lazy::MsgMaker::set_header(std::string key, std::string value)
{
	if (header.empty())
	{
		header.push_back({ key,value });
	}
	for (size_t i = 0; i < header.size(); i++)
	{
		if (header[i].first == key)
		{
			header[i].second = value;
			return;
		}
	}
	header.push_back({ key,value });
}
std::string lazy::MsgMaker::set_header(std::string key)
{
	std::string value = "";
	if (key == "Connection")
	{
		if (httpv == (int)HttpVer::http_1_1)value = "keep-alive";
		else if (httpv == (int)HttpVer::http_1_0)fline += "close";
	}
	else if (key == "Date")
	{
		value = WebHelper::get_date_str();
	}
	else if (key == "Content-Length")
	{
		value = std::to_string(body.size());
	}
	else if (key == "Content-Type")
	{
		value = WebHelper::get_file_type(file);
	}
	else if (key == "User-Agent")
	{
		value = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0";
	}
	else if (key == "Accept")
	{
		value = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
	}
	else if (key == "Accept-Encoding")
	{
		value = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
	}
	else
	{
#ifdef _DEBUG
		std::cout << "Warning: Failed to set header automatically: Unsupported key." << std::endl;
#endif
		return "";
	}
	set_header(key, value);
	return value;
}

void lazy::MsgMaker::set_par(std::string key, std::string value)
{
	if (par.empty())
	{
		par.push_back({ key,value });
	}
	for (size_t i = 0; i < par.size(); i++)
	{
		if (par[i].first == key)
		{
			par[i].second = value;
			return;
		}
	}
	par.push_back({ key,value });
	//Upgrade
	set_request_line(r, m);
}

void lazy::MsgMaker::set_body(std::string str)
{
	body = str;
}
bool lazy::MsgMaker::load_body_from_file(std::string filename)
{
	using namespace std;

	ifstream f;
	f.open(filename, ios::binary);
	if (!f.is_open())
	{
#ifdef _DEBUG
		cout << "Error: Failed to load body: cannot open file." << endl;
#endif
		return false;
	}

	file = filename;
	//Load
	body.clear();
	char* buf = new char[WEB_IO_BUFSIZE + 1];
	memset(buf, 0, WEB_IO_BUFSIZE + 1);
	while (!f.eof())
	{
		f.read(buf, WEB_IO_BUFSIZE);
		for (size_t i = 0; i < f.gcount(); i++)
		{
			body += buf[i];
		}
	}
	delete buf;

	f.close();
	return true;
}

std::string lazy::MsgMaker::make()
{
	std::string temp;
	temp += fline;
	temp += "\r\n";
	for (size_t i = 0; i < header.size(); i++)
	{
		temp += header[i].first;
		temp += ": ";
		temp += header[i].second;
		temp += "\r\n";
	}
	temp += "\r\n";
	if (!body.empty())
	{
		temp += body;
		temp += "\r\n\r\n";
	}
	return temp;
}


//lazy::WebHelper


lazy::WebHelper::WebHelper() {}
lazy::WebHelper::~WebHelper() {}

lazy::WebHelper::WebHelper(lazy::Web& _web)
{
	web = &_web;
}

std::string lazy::WebHelper::get_time_str()
{
	time_t t;
	time(&t);
	srand(t);

	//Avoid repeating
	static time_t last_t = t;
	static int count = 0;
	if (last_t == t)
	{
		count++;
	}
	else
	{
		last_t = t;
		count = 0;
	}
	std::string cnt = std::to_string(count);
	while (cnt.size() < 4)cnt.insert(cnt.begin(), '0');

	tm lt;
	localtime_s(&lt, &t);

	char str[64];
	strftime(str, 64 * sizeof(char), "%Y%m%d_%H-%M-%S", &lt);
	return std::string(str) + '_' + cnt;
}
std::string lazy::WebHelper::get_date_str()
{
	time_t t;
	time(&t);
	tm gmt;
	gmtime_s(&gmt, &t);

	char str[64];
	strftime(str, 64 * sizeof(char), "%a, %d %b %Y %H:%M:%S GMT", &gmt);

	return str;
}

std::string lazy::WebHelper::get_url_host(std::string url)
{
	using namespace std;

	int res = url.find("//");
	if (res == string::npos) res = 0;
	else res += 2;
	if (url.find("/", res) == string::npos) return url.substr(res);
	return url.substr(res, url.find("/", res) - res);
}
std::string lazy::WebHelper::get_url_res(std::string url)
{
	using namespace std;

	int res = url.find("//");
	if (res == string::npos) res = 0;
	else res += 2;
	if (url.find("/", res) == string::npos) return "/";
	else
	{
		if (url.find(":", res) == string::npos)
		{
			return url.substr(url.find("/", res));
		}
		else
		{
			return url.substr(url.find("/", res), url.find(":") - url.find("/", res));
		}
	}
}
int lazy::WebHelper::get_url_port(std::string url)
{
	using namespace std;

	int res = url.find("//");
	if (res == string::npos) res = 0;
	else res += 2;
	if (url.find(":", res) != string::npos)
	{
		if (url.find("/", res) != string::npos)
		{
			return atoi(url.substr(url.find(":", res) + 1, url.find("/", res) - url.find(":", res)).c_str());
		}
		else
		{
			return atoi(url.substr(url.find(":", res) + 1).c_str());
		}
	}
	if (url.find("http://") != string::npos)
	{
		return PORT_HTTP;
	}
	else if (url.find("https://") != string::npos)
	{
		return PORT_HTTPS;
	}
#ifdef _DEBUG
	cout << "Error: Failed to get port from URL." << endl;
#endif

	return 0;
}

std::vector<std::string> lazy::WebHelper::find_url(std::string str)
{
	using namespace std;
	vector<string> urls;

	//Replace "\" with "/"
	while (str.find("\\/") != string::npos)
	{
		str.erase(str.find("\\/"), 1);
	}

	//Find it!
	string::const_iterator start = str.begin();
	string::const_iterator end = str.end();
	string url;
	smatch mat;
	regex reg("https://[^\\s'\"<>():,]+");
	while (regex_search(start, end, mat, reg))
	{
		url = string(mat[0].first, mat[0].second);
		start = mat[0].second;
		urls.push_back(url);
	}
	reg = "http://[^\\s'\"<>():,]+";
	while (regex_search(start, end, mat, reg))
	{
		url = string(mat[0].first, mat[0].second);
		start = mat[0].second;
		urls.push_back(url);
	}
	return urls;
}
std::vector<std::string> lazy::WebHelper::find_url(Msg msg)
{
	if (msg.is_html())return find_url(msg.get_body());
	else return std::vector<std::string>();
}

std::string lazy::WebHelper::get_file_type(std::string filename)
{
	using namespace std;
	if (filename.find(".") == string::npos)
	{
		return "text/html";
	}
	else
	{
		string suf = filename.substr(filename.find("."));
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
std::string lazy::WebHelper::get_file_suf(std::string filetype)
{
	using namespace std;
	//text
	if (filetype.find("text/html") != string::npos)return ".html";
	else if (filetype == "text/plain")return ".txt";
	else if (filetype == "text/css")return ".css";
	else if (filetype == "text/javascript")return ".js";
	else if (filetype == "application/json")return ".json";
	//image
	else if (filetype == "image/jpeg")return ".jpg";
	else if (filetype == "image/png")return ".png";
	else if (filetype == "image/gif")return ".gif";
	else if (filetype == "image/x-ico")return ".ico";
	else if (filetype == "image/webp")return ".webp";
	//audio
	else if (filetype == "audio/mp3")return ".mp3";
	else if (filetype == "audio/wav")return ".wav";
	//video
	else if (filetype == "video/mpeg4")return ".mpeg4";
	else if (filetype == "video/avi")return ".avi";
	//zips
	else if (filetype == "application/x-zip-compressed")return ".zip";
	else if (filetype == "application/x-7z-compressed")return ".7z";
	else return "";
}

std::string lazy::WebHelper::uri_encode(const std::string& _s)
{
	std::string s = _s;
	char temp, cstr[3];
	for (size_t i = 0; i < s.size(); i++)
	{
		if (!(s[i] >= 'A' && s[i] <= 'Z' ||
			s[i] >= 'a' && s[i] <= 'z' ||
			s[i] >= '0' && s[i] <= '9' ||
			s[i] == '-' ||
			s[i] == '_' ||
			s[i] == '.' ||
			s[i] == '~'))
		{
			temp = s[i];
			memset(cstr, 0, sizeof(cstr));
			_itoa_s(temp, cstr, 16);
			if (temp < 16)
			{
				cstr[1] = cstr[0];
				cstr[0] = '0';
			}
			_strupr_s(cstr);
			s[i] = '%';
			s.insert(i + 1, cstr, 2);
			i += 2;
		}
	}
	return s;
}
std::string lazy::WebHelper::uri_decode(const std::string& _s)
{
	std::string s = _s;
	int where;
	char temp;
	while (s.find("%") != std::string::npos)
	{
		where = s.find("%");
		temp = strtoul(s.substr(where + 1, 2).c_str(), NULL, 16);
		s.erase(where + 1, 2);
		s[where] = temp;
	}
	return s;
}

bool lazy::WebHelper::send_get_msg(std::string url)
{
	if (web == nullptr)
	{
#ifdef _DEBUG
		std::cout << "WebHelper error: Not initialized." << std::endl;
#endif
		return false;
	}

	MsgMaker msg;
	msg.set_request_line(WebHelper::get_url_res(url));
	msg.set_header("Host", web->get_hostname());
	msg.set_header("User-Agent");
	msg.set_header("Connection");
	msg.set_header("Date");
	std::cout << msg.make();
	return web->write(msg);
}

lazy::Msg lazy::WebHelper::auto_get(std::string url)
{
	Web web;
	if (url.find("https") != std::string::npos)
	{
		web.init(WebProt::https, HttpVer::http_1_1, true);
	}
	else
	{
		web.init(WebProt::http, HttpVer::http_1_1, false);
	}
	web.connect(url);

	WebHelper(web).send_get_msg(url);

	time_t timer = clock();
	while (web.msg_empty() && clock() - timer < WEB_AUTO_OVERTIME);

	return web.read();
}