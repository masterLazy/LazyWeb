# LazyWeb

A new **HTTP** SDK strives to be perfect and easy to use. (I have developed mWeb but I thought it was trash so I decide to create this. ) Both **HTTP Client** and **HTTP Server** are supported in LazyWeb.

## Introduction

LazyWeb is based on Windows API (WinSock) and OpenSSL.

LazyWeb offers a class, `lazy::Web`, as the interface. LazyWeb creates a `recv_thread` to receive messages so that LazyWeb will be **non-blocking**. All the messages will be stored to a file at once.

LazyWeb offers `lazy::Msg` to manage HTTP messages, `lazy::MsgMaker` to make HTTP messages, and `lazy::WebHelper`. 

| Questions                                      | Answers                                         |
| ---------------------------------------------- | ----------------------------------------------- |
| What platform does LazyWeb support?            | Windows                                         |
| What should I install as extra to run LazyWeb? | OpenSSL (Suggest using OpenSSL v3.2.1)          |
| What network protocol does LazyWeb support?    | HTTP; HTTP + SSL/TLS; HTTP + QUIC (client only) |

## Quickstart

### Start as Client

```cpp
#include <iostream>
//Includes the lib
#include <lazyweb/lazyweb.hpp>
using namespace std;
using namespace lazy;
int main()
{
	string url="https://www.microsoft.com/en-us/"

	//Initializate
	Web web;
	web.init(WebProt::https, HttpVer::http_1_1);
	//Connect to the server
	web.connect(url);

	//Send a GET msg
	WebHelper(web).send_get_msg(url);

	//Wait and recv msg
	while(web.msg_empty());
	Msg msg = web.read();
	//Print the msg
	cout << msg.get_str() << endl;

	//Close
	web.close();
	return 0;
}
```

### Start with automatic helper

```cpp
#include <iostream>
#include "lazyweb/lazyweb.hpp"
using namespace std;
using namespace lazy;
int main()
{
	Msg msg = WebHelper::auto_get("https://www.microsoft.com/en-us/");
	cout << msg.get_str() << endl;
	return 0;
}
```

See? LazyWeb is easy to use.

## File `#include` tree

`lazyweb.hpp`

|- `httpMsg.hpp`

|- `webHelper.hpp`

|- `main.hpp` (Function definitions)

## Situation

The development of LazyWeb is nearly half-done. It's still under development. 
