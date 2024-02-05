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
					string path = web.recv_path + WebHelper::get_time_str();
					CreateDirectoryA(path.c_str(), NULL);
					filename = path + "/msg" + ".dat";

					if (of.is_open())of.close();
					of.open(filename, ios::binary);
					cout << "[recv_thread] Recv begin." << endl;
				}
				string temp(buf);
				for (int i = 0; i < res; i++)
				{
					of << buf[i];
				}
				timer = clock();
			}
			//Recv complete
			if (recving == true && clock() - timer > WEB_RECV_OVERTIME)
			{
				recving = false;
				of.close();

				Msg msg;
				msg.load_from_file(filename);
				web.msg_queue.push(msg);
				cout << "[recv_thread] Recv completed." << endl;
			}
		}
	}
	delete buf;
	if (of.is_open())of.close();

	web.sg_end_ok = true;
}

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
	sock = socket(WEB_ADDR_FAMILY, quic ? SOCK_DGRAM : SOCK_STREAM, 0);
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


	//Create thread
	recv_td = new std::thread(recv_loop, std::ref(*this));
	recv_td->detach();

	mode = Mode::client;

	SSL_set_fd(ssl, sock);
	return true;
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
			//CertCloseStore(hStore, 0);
			//return false;
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

bool lazy::Web::init(bool _ssl, bool verify, bool _quic)
{
	using namespace std;
	int res;
	quic = _quic;
	//Startup SSL
	if (_ssl)
	{
		ssl_verify = verify;
		OpenSSL_add_all_algorithms();
		SSL_library_init();
		SSL_load_error_strings();
		SSLeay_add_ssl_algorithms();
		//Create CTX
		ctx = SSL_CTX_new(quic ? OSSL_QUIC_client_method() : TLS_client_method());
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
	else
	{
		ssl_verify = false;
	}

	return init_winsock_c();
}
bool lazy::Web::init(std::string ip, int port, bool startup_ssl)
{
	int res;
	//Startup SSL
	if (startup_ssl)
	{
		OpenSSL_add_all_algorithms();
		SSL_library_init();
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
		std::cout << "Error: Failed to startup WSA." << std::endl;
#endif
		return false;
	}


	//Create SOCKET
	sock = socket(WEB_ADDR_FAMILY, SOCK_STREAM, 0);
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


	//Bind addr(Name socket)
	/*memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
	if (bind(sock, (sockaddr*)&addr, sizeof(addr)) == -1)
	{
		close();
#ifdef _DEBUG
		std::cout << "Error: Failed to bind SOCKET: " << get_error_str() << "." << std::endl;
#endif
		return false;
	}*/

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
	if (port == HTTP_PORT && ssl != nullptr)
	{
		cout << "Warning: Using http port (80) but using SSL." << endl;
	}
	if (port == HTTPS_PORT && ssl == nullptr)
	{
		cout << "Warning: Using https port (443) but not using SSL." << endl;
	}
#endif

	int res, err = 0;

	//Set addrinfo
	addrinfo hints, * result;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = WEB_ADDR_FAMILY;
	hints.ai_socktype = quic ? SOCK_DGRAM : SOCK_STREAM;

	string ports = to_string(port);
	if (getaddrinfo(hostname.c_str(), ports.c_str(), &hints, &result) != 0)
	{
#ifdef _DEBUG
		cout << "Error: Failed to connect: getaddrinfo() failed." << endl;
#endif
		return false;
	}
	addr = result;


	clock_t timer = clock();
	//Connect (TCP)
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
		//SSL_set_fd(ssl, sock);//Set socket
		SSL_set_connect_state(ssl);//Before SSL_connect()
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
		if (clock() - timer > waitSec * 1000)
		{
#ifdef _DEBUG
			cout << "Error: Failed to connect: SSL connection overtime. "
				<< get_err_str() << "." << endl;
#endif
			return false;
		}
		else if (err != SSL_ERROR_NONE)
		{
#ifdef _DEBUG
			if (err == SSL_ERROR_SYSCALL)
			{
				cout << "Error: Failed to connect. "
					<< get_err_str() << get_ssl_err_str() << "." << endl;
			}
			else
			{
				cout << "Error: Failed to connect. "
					<< get_ssl_err_str() << "." << endl;
			}
#endif
			return false;
		}

		//Verify
		if (ssl_verify)
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

std::string lazy::Web::get_hostname()
{
	return host;
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
				cout << "Error: Failed to write. SSL_get_error() returned " <<
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

SOCKET lazy::Web::get_socket()
{
	return sock;
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


//lazy::Msg


lazy::Msg::Msg() {}
lazy::Msg::~Msg() {}

bool lazy::Msg::analysis()
{
	using namespace std;
	string msg = get_str();

	//Analysis msg header

	//First line
	if (msg.find("\r\n") == string::npos)
	{
#ifdef _DEBUG
		cout << "Error: Failed to analysis msg: Invalid format." << endl;
#endif
		return false;
	}
	fline = msg.substr(0, msg.find("\r\n"));

	//Header
	size_t i = msg.find("\r\n") + 2;
	header.clear();
	while (true)
	{
		//Analysis one line
		header.push_back({
			msg.substr(i, msg.find(": ", i) - i),
			msg.substr(msg.find(": ", i) + 2,
			(msg.find("; ", i) == string::npos ? msg.find("\r\n",i) : min(msg.find("\r\n",i),msg.find("; ",i)))
			- (msg.find(": ", i) + 2))
			});

		if (msg.find("\r\n\r\n") == msg.find("\r\n", i))break;
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


	//Analysis msg body
	char* msg_c;
	size_t size;
	get_str(&msg_c, &size);

	//Save body to file
	string fname = filename.substr(0, filename.find_last_of('/') + 1) + "body" + WebHelper::get_file_suf(get_header("Content-Type"));
	ofstream of;
	of.open(fname, ios::binary);
	if (!of.is_open())
	{
#ifdef _DEBUG
		cout << "Error: Failed to save msg body: Failed to open file." << endl;
#endif
		return false;
	}

	//Split body
	i = msg.find("\r\n\r\n") + 4;
	for (size_t j = i; j < size; j++)
	{
		of << msg_c[j];
	}

	of.close();
	delete msg_c;
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

	return analysis();
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
		res += buf;
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
std::string lazy::Msg::get_header(std::string item)
{
	if (header.empty())return "";
	for (size_t i = 0; i < header.size(); i++)
	{
		if (header[i].first == item)return header[i].second;
	}
	return "";
}
std::string lazy::Msg::get_par(std::string item)
{
	if (par.empty())return "";
	for (size_t i = 0; i < par.size(); i++)
	{
		if (par[i].first == item)return par[i].second;
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


lazy::MsgMaker::MsgMaker() {}
lazy::MsgMaker::~MsgMaker() {}


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
		return HTTP_PORT;
	}
	else if (url.find("https://") != string::npos)
	{
		return HTTPS_PORT;
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
	std::string msg;
	msg += "GET " + WebHelper::get_url_res(url) + " HTTP/1.1\r\n";

	//Neccessary
	msg += "Connection: keep-alive\r\n";
	msg += "Host: " + web->get_hostname() + "\r\n";
	msg += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0\r\n";
	//Unneccessary, maybe
	msg += "Date: " + WebHelper::get_date_str() + "\r\n";
	msg += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n";
	msg += "Accept-Encoding: identity\r\n";
	msg += "\r\n";

	return web->write(msg);
}

lazy::Msg lazy::WebHelper::auto_get(std::string url)
{
	Web web;
	web.init(url.find("https") != std::string::npos);
	web.connect(url);

	WebHelper(web).send_get_msg(url);

	time_t timer = clock();
	while (web.msg_empty() && clock() - timer < WEB_AUTO_OVERTIME);

	return web.read();
}