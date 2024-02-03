#pragma once
/*****************************************************************************
* main.hpp
* The realization of lazy::web
*****************************************************************************/

std::string lazy::Get_time_string()
{
	time_t t = time(NULL);
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

	tm lt;
	localtime_s(&lt, &t);

	using namespace std;
	string y = to_string(lt.tm_year + 1900);

	string m = to_string(lt.tm_mon + 1);
	if (m.size() == 1)m.insert(m.begin(), '0');

	string d = to_string(lt.tm_mday);
	if (d.size() == 1)d.insert(d.begin(), '0');

	string h = to_string(lt.tm_hour);
	if (h.size() == 1)h.insert(h.begin(), '0');

	string min = to_string(lt.tm_min);
	if (min.size() == 1)min.insert(min.begin(), '0');

	string s = to_string(lt.tm_sec);
	if (s.size() == 1)s.insert(s.begin(), '0');

	string cnt = to_string(count);
	while (cnt.size() < 4)cnt.insert(cnt.begin(), '0');

	return y + '-' + m + '-' + d + '_' + h + min + s + '_' + cnt;
}


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
			//TCP
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
					filename = web.recv_path + Get_time_string() + ".dat";
					of.open(filename);
					cout << "[recv_thread] Recv begin." << endl;
				}
				of << buf;
				timer = clock();
			}
			//Recv complete
			if (recving == true && clock() - timer > WEB_RECV_OVERTIME)
			{
				recving = false;
				of.close();

				Msg msg;
				msg.load(filename);
				web.msg_queue.push(msg);
				cout << "[recv_thread] Recv completed." << endl;
			}
		}
	}
	delete buf;
	if (of.is_open())of.close();

	web.sg_end_ok = true;
}

bool lazy::Web::init(bool startup_ssl)
{
	int res;
	//Startup SSL
	if (startup_ssl)
	{
		OpenSSL_add_ssl_algorithms();
		SSL_load_error_strings();
		SSLeay_add_ssl_algorithms();
		//Create CTX
		ctx = SSL_CTX_new(TLS_client_method());
		//Set verify method (non-verify)
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		//Create SSL
		ssl = SSL_new(ctx);
	}


	//Startup WSA
	res = WSAStartup(MAKEWORD(2, 2), &wd);
	if (res != 0)
	{
#ifdef _DEBUG
		std::cout << "Failed to startup WSA." << std::endl;
#endif
		return false;
	}


	//Create SOCKET
	sock = socket(AF_INET, SOCK_STREAM, NULL);
	if (sock == -1)
	{
#ifdef _DEBUG
		std::cout << "Failed to create SOCKET: " << get_error_str() << "." << std::endl;
#endif
		close();
		return false;
	}
	//Set SOCKET non-blocking
	u_long ul = 1;
	ioctlsocket(sock, FIONBIO, &ul);


	//Create thread
	recv_td = new std::thread(recv_loop, std::ref(*this));
	recv_td->detach();

	mode = Mode::client;
	return true;
}
bool lazy::Web::init(std::string ip, int port, bool startup_ssl)
{
	int res;
	//Startup SSL
	if (startup_ssl)
	{
		OpenSSL_add_ssl_algorithms();
		SSL_load_error_strings();
		SSLeay_add_ssl_algorithms();
		//Create CTX
		ctx = SSL_CTX_new(TLS_server_method());
		//Set verify method (non-verify)
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		//Create SSL
		ssl = SSL_new(ctx);
	}


	//Startup WSA
	res = WSAStartup(MAKEWORD(2, 2), &wd);
	if (res != 0)
	{
#ifdef _DEBUG
		std::cout << "Failed to startup WSA." << std::endl;
#endif
		return false;
	}


	//Create SOCKET
	sock = socket(AF_INET, SOCK_STREAM, NULL);
	if (sock == -1)
	{
#ifdef _DEBUG
		std::cout << "Failed to create SOCKET: " << get_error_str() << "." << std::endl;
#endif
		close();
		return false;
	}
	//Set SOCKET non-blocking
	u_long ul = 1;
	ioctlsocket(sock, FIONBIO, &ul);


	//Bind addr(Name socket)
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
	if (bind(sock, (sockaddr*)&addr, sizeof(addr)) == -1)
	{
		close();
#ifdef _DEBUG
		std::cout << "Failed to bind SOCKET: " << get_error_str() << "." << std::endl;
#endif
		return false;
	}

	//Create thread
	recv_td = new std::thread(recv_loop, std::ref(*this));
	recv_td->detach();

	mode = Mode::server;
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

bool lazy::Web::connect(std::string host, int port, float waitSec)
{
	using namespace std;

	if (mode != Mode::client)
	{
#ifdef _DEBUG
		if (mode == Mode::undefined)
		{
			cout << "Failed to connect: Not initialized." << endl;
		}
		else
		{
			cout << "Failed to connect: Should be in client mode." << endl;
		}
#endif
		return false;
	}

#ifdef _DEBUG
	if (port == HTTP_PORT && ssl != nullptr)
	{
		cout << "Warning: Using http port (80) but using SSL." << endl;
	}
	if (port == HTTPS_PORT && ssl == nullptr)
	{
		cout << "Warning: Using https port (443) but not using SSL." << endl;
	}
#endif

	//Config addr port
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	//Config addr IP
	bool hostName = false;
	for (int i = 0; i < host.size(); i++)
	{
		if (host[i] >= 'A' && host[i] <= 'Z' ||
			host[i] >= 'a' && host[i] <= 'z')
		{
			hostName = true;
			break;
		}
	}
	//Given "host" is host name
	if (hostName)
	{
		if (gethostbyname(host.c_str()) == nullptr)
		{
#ifdef _DEBUG
			cout << "Failed to connect: Host not found." << endl;
#endif
			return false;
		}
		else
		{
			memcpy(&addr.sin_addr, gethostbyname(host.c_str())->h_addr, 4);
		}
	}
	//is IP
	else
	{
		inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
	}

	int res, err = 0;
	clock_t timer = clock();
	//Connect (TCP)
	while (clock() - timer <= waitSec * 1000)
	{
		res = ::connect(sock, (sockaddr*)&addr, sizeof(addr));
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
		cout << "Failed to connect: TCP connection overtime. "
			<< get_error_str() << "." << endl;
#endif
		return false;
	}

	//Connect (SSL)
	if (ssl != nullptr)
	{
		SSL_set_fd(ssl, sock);//Set socket
		SSL_set_connect_state(ssl);//Before SSL_connect()
		while (clock() - timer <= waitSec * 1000)
		{
			res = SSL_connect(ssl);
			if (res == 0)break;
			{
				err = SSL_get_error(ssl, res);
				if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
				{
					break;
				}
			}
		}
		if (clock() - timer > waitSec * 1000)
		{
#ifdef _DEBUG
			cout << "Failed to connect: Failed to connect: SSL connection overtime. "
				<< get_error_str() << "." << endl;
#endif
			return false;
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

bool lazy::Web::write(std::string msg)
{
	if (mode == Mode::undefined)
	{
#ifdef _DEBUG
		std::cout << "Failed to write: Not initialized." << std::endl;
#endif
		return false;
	}

	size_t written;
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
				if (get_error() == WSAEWOULDBLOCK ||
					get_error() == WSAEALREADY)continue;
#ifdef _DEBUG
				std::cout << "Failed to write: " << get_error_str() << "." << std::endl;
#endif
				return false;

			default:
#ifdef _DEBUG
				std::cout << "Failed to write. SSL_get_error() returned " << err << "." << std::endl;
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
			std::cout << "Failed to write: " << get_error_str() << "." << std::endl;
#endif
			return false;
		}
	}
	return true;
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
		std::cout << "Failed to read: Msg queue is empty." << std::endl;
#endif
		Msg m;
		return m;
	}
	return msg_queue.back();
}

SOCKET lazy::Web::get_socket()
{
	return sock;
}
int lazy::Web::get_error()
{
	return WSAGetLastError();
}
std::string lazy::Web::get_error_str()
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
lazy::Web::Mode lazy::Web::get_mode()
{
	return mode;
}

void lazy::Web::close()
{
	sg_recv = false;
	closesocket(sock);
	WSACleanup();
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


//lazy::WebHelper


lazy::WebHelper::WebHelper() {}
lazy::WebHelper::~WebHelper() {}

lazy::WebHelper::WebHelper(lazy::Web* _web)
{
	web = _web;
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
		return HTTP_PORT;
	}
	else if (url.find("https://") != string::npos)
	{
		return HTTPS_PORT;
	}
	return -1;
}

bool lazy::WebHelper::send_get_msg(std::string resourceName)
{
	if (web == 0)
	{
#ifdef _DEBUG
		std::cout << "WebHelper error: Not initialized." << endl;
#endif
		return false;
	}
}


//lazy::Msg


lazy::Msg::Msg() {}
lazy::Msg::~Msg() {}

bool lazy::Msg::load(std::string filename)
{
	using namespace std;

	ifstream f;
	f.open(filename);
	if (!f.is_open())
	{
#ifdef _DEBUG
		cout << "Failed to load msg: cannot open file." << endl;
#endif
		return false;
	}
	f.close();

	file = filename;

	return analysis();
}
std::string lazy::Msg::get_str()
{
	using namespace std;

	ifstream f;
	f.open(file);
	if (!f.is_open())
	{
#ifdef _DEBUG
		cout << "Failed to get msg string: cannot open file." << endl;
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

	return res;
}
bool lazy::Msg::analysis()
{
	return true;
}