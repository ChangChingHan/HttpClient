// HttpClient.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <process.h>
using namespace std;

#define GET_METHOD				"GET %s HTTP/1.1\r\n"
#define HOST_SECTION			"Host: %s\r\n"
#define CONNECTION_SECTION		"Connection: keep-alive\r\n"
#define AUTH_SECTION			"Authorization: Basic %sz\r\n"
#define ACCECPT_SECTION			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
#define AGENT_SECTION			"User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36\r\n"
#define ENCODE_SECTION			"Accept-Encoding: gzip,deflate,sdch\r\n"
#define LANGUAGE_SECTION		"Accept-Language: en-US,en;q=0.8,zh-TW;q=0.6,zh;q=0.4\r\n\r\n"

HANDLE g_handle = NULL;

void Base64Encode (const char* s, char* dest)
{
	char * Code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char coded [5];
	int x;
	int y = strlen(s) - (strlen(s) % 3);

	// clear to NULL string
	*dest = 0;

	for(x = 0; x < y; x += 3)
	{
		/* Take the bottom six bits of the last byte, and the
		 * top six bits of the first byte.
		 */

		coded [3] = Code [s [x + 2] % 64];
		coded [0] = Code [s [x] >> 2];

		/* The second character requires the bottom two bits of
		 * the first byte and the top four bits of the second byte.
		 */

		coded [1] = (s [x] % 4) << 4;
		coded [1] += (s [x + 1] >> 4);
		coded [1] = Code [coded [1]];

		/* The third character requires the bottom four bits of
		 * the second byte and the top two bits of the third byte.
		 */

		coded [2] = (s [x + 1] % 16) << 2;
		coded [2] += (s [x + 2] / 64);
		coded [2] = Code [coded [2]];

		/* Zero terminate the string and append it to the result */

		coded [4] = 0;
		strcat (dest, coded);
	}

	x = y;

	if ((strlen (s) % 3) != 0)
	{
		/* The next blocks of code are if the length of the string is not
		 * a zero modulus of three.
		 */
		if ((strlen (s) % 3) == 1)
		{
			/* Pad the last two characters as equal signs */

			coded [2] = '=';
			coded [3] = '=';

			/* Character 1 is the same as above, character 2 uses only
		 	 * the bottom two bits of the only byte.
		 	 */

			coded [0] = Code [s [x] >> 2];
			coded [1] = Code [(s [x] % 4) << 4];

			/* Zero terminate the string and append it to the result,
			 * then retrn.
			 */

			coded [4] = 0;
			strcat (dest, coded);
		}
		else
		{
			/* Pad the last character with an equal sign */
			coded [3] = '=';

			/* First and second characters exactly as above */

			coded [0] = Code [s [x] >> 2];
			coded [1] = (s [x] % 4) << 4;
			coded [1] += (s [x + 1] >> 4);
			coded [1] = Code [coded [1]];

			/* Third character uses only the bottom four bits of the second byte */

			coded [2] = Code [(s [x + 1] % 16) << 2];

			/* Zero terminate, append to the result, and return */

			coded [4] = 0;
			strcat (dest, coded);
		}
	}
}
char* GetResponseMsg(char* receive_message)
{
	char *chString = NULL;
	chString = strstr(receive_message, "\r\n\r\n");

	if (chString)
	{
		chString = (chString+4);
	}
	return chString;
}

#define PTZ_PRESET_CGI				"/config/ptz_preset.cgi?name=%d&act=go"
#define PTZ_AUTOSCAN_CGI			"/config/ptz_autorun.cgi?name=scan"


enum PTZ_ACTION
{
	PTZ_PRESET = 0,
	PTZ_AUTOSCAN
};
struct PTZAuthenticate
{
	wstring		strIP;
	wstring		strUserName;
	wstring		strPassword;
	int			nPort;
	PTZ_ACTION	ptzAction;
	int			ptzPresetPoint;
};

void GetCGIString(const PTZAuthenticate& ptzAuthenticate, char* chValue)
{
	if (ptzAuthenticate.ptzAction == PTZ_PRESET)
	{
		sprintf(chValue, PTZ_PRESET_CGI, ptzAuthenticate.ptzPresetPoint);
	}
	else
	{
		sprintf(chValue, PTZ_AUTOSCAN_CGI);
	}
}


char* HttpClient()
{
	PTZAuthenticate	m_ptzAuthenticate;
	m_ptzAuthenticate.strIP = _T("10.1.21.110");
	m_ptzAuthenticate.nPort = 80;
	m_ptzAuthenticate.strUserName = _T("root");
	m_ptzAuthenticate.strPassword = _T("pass");
	m_ptzAuthenticate.ptzAction = PTZ_PRESET;
	m_ptzAuthenticate.ptzPresetPoint = 1;

	sockaddr_in webserver;
	int nResult = 0, sockfd = 0, addr_len = sizeof(sockaddr_in);
	char receive_message[1024] = {0};
	char chAuthEncode[30] = {0};
	char chIP[16] = {0};
	char chCGI[125] = {0};
	char chUserPass[125] = {0};

	int nPort = m_ptzAuthenticate.nPort;
	string str( m_ptzAuthenticate.strIP.begin(), m_ptzAuthenticate.strIP.end() );
	sprintf(chIP, str.c_str());

	GetCGIString(m_ptzAuthenticate, chCGI);
// 	if (m_ptzAuthenticate.ptzAction == PTZ_PRESET)
// 	{
// 		sprintf(chCGI, PTZ_PRESET_CGI, m_ptzAuthenticate.ptzPresetPoint);
// 	}
// 	else
// 	{
// 		sprintf(chCGI, PTZ_AUTOSCAN_CGI);
// 	}

	string strUser(m_ptzAuthenticate.strUserName.begin(),m_ptzAuthenticate.strUserName.end());
	string strPass(m_ptzAuthenticate.strPassword.begin(),m_ptzAuthenticate.strPassword.end());
	sprintf(chUserPass, "%s:%s",strUser.c_str(), strPass.c_str());
	Base64Encode(chUserPass, chAuthEncode);

	sockfd = socket(AF_INET,SOCK_STREAM,0);
	webserver.sin_family=AF_INET;
	webserver.sin_port=htons(nPort);
	webserver.sin_addr.s_addr=inet_addr(chIP);

	char chCGIString[1024] = {0};
	sprintf(chCGIString, GET_METHOD, chCGI);

	char chIPString[1024] = {0};
	sprintf(chIPString, HOST_SECTION, chIP);

	char chAuthString[1024] = {0};
	sprintf(chAuthString, AUTH_SECTION, chAuthEncode);

	char send_message[1024] = {0};
	sprintf(send_message,"%s%s%s%s%s%s%s%s",
		chCGIString,
		chIPString,
		CONNECTION_SECTION,
		chAuthString,
		ACCECPT_SECTION,
		AGENT_SECTION,
		ENCODE_SECTION,
		LANGUAGE_SECTION);

	nResult = connect(sockfd,(sockaddr*)(&webserver),sizeof(sockaddr));
	nResult = send(sockfd,send_message,sizeof(send_message), 0);
	nResult = recvfrom(sockfd, receive_message,sizeof(receive_message), 0 , (sockaddr*)&webserver ,&addr_len);
	closesocket(sockfd);
	return GetResponseMsg(receive_message);

	/*sockaddr_in webserver;
	int nResult = 0, sockfd = 0, addr_len = sizeof(sockaddr_in);
	char receive_message[1024] = {0};
	char chAuthEncode[30] = {0};

	int nPort = 80;
	char chIP[] = "10.1.21.64";
	char chCGI[] = "/config/stream_info.cgi";
	Base64Encode("root:pass", chAuthEncode);

	sockfd = socket(AF_INET,SOCK_STREAM,0);
	webserver.sin_family=AF_INET;
	webserver.sin_port=htons(nPort);
	webserver.sin_addr.s_addr=inet_addr(chIP);

	char chCGIString[1024] = {0};
	sprintf(chCGIString, GET_METHOD, chCGI);

	char chIPString[1024] = {0};
	sprintf(chIPString, HOST_SECTION, chIP);

	char chAuthString[1024] = {0};
	sprintf(chAuthString, AUTH_SECTION, chAuthEncode);

	char send_message[1024] = {0};
	sprintf(send_message,"%s%s%s%s%s%s%s%s",
		chCGIString,
		chIPString,
		CONNECTION_SECTION,
		chAuthString,
		ACCECPT_SECTION,
		AGENT_SECTION,
		ENCODE_SECTION,
		LANGUAGE_SECTION);

	nResult = connect(sockfd,(sockaddr*)(&webserver),sizeof(sockaddr));
	nResult = send(sockfd,send_message,sizeof(send_message), 0);
	nResult = recvfrom(sockfd, receive_message,sizeof(receive_message), 0 , (sockaddr*)&webserver ,&addr_len);
	closesocket(sockfd);
	return GetResponseMsg(receive_message);*/
}

void SendENCPBroadcast()
{
	sockaddr_in ENCPserver;
	int nResult = 0, sockfd = 0;
	char receive_message[1024] = {0};

	sockfd = socket(AF_INET,SOCK_DGRAM,0);
	ENCPserver.sin_family=AF_INET;
	ENCPserver.sin_port=htons(32154);
	ENCPserver.sin_addr.s_addr=inet_addr("255.255.255.255");

	char send_message[12] = 
	{
		0x41, 0x44, 0x43, 0x54, 0x05, 0x0c, 0x00, 0x03, 
		0xff, 0xe0, 0x00, 0x00
	};

	int bcast = 1;
	nResult = setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (char *)&bcast, sizeof(bcast));
	nResult = sendto(sockfd,send_message,sizeof(send_message),0,(struct sockaddr *)(&ENCPserver),sizeof(struct sockaddr));
	//nResult = connect(sockfd,(struct sockaddr *)(&ENCPserver),sizeof(struct sockaddr));
	//nResult = send(sockfd,send_message,sizeof(send_message), 0);
	closesocket(sockfd);
}

void UnpackMsg(sockaddr_in& localserver, char *preceive_message)
{
	char *pAddr = inet_ntoa(localserver.sin_addr);

	unsigned char mac[6] = {0};
	memcpy(mac, (preceive_message+9), 6);

	char ip[16] = {0};

	memcpy(ip, pAddr, 16);
	printf("%s\t %02x-%02x-%02x-%02x-%02x-%02x\n", ip, 
		 mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

	

	char model[125] = {0};
	preceive_message+17;
}

void ENCPBroadcast()
{
	sockaddr_in localserver;
	int nResult = 0;
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	char receive_message[1024] = {0};
	int addr_len = sizeof(sockaddr_in);

	localserver.sin_family=AF_INET;
	localserver.sin_port=htons(32153);
	localserver.sin_addr.s_addr=INADDR_ANY;

	nResult = bind(sockfd,(sockaddr*)&localserver,sizeof(localserver));
	SendENCPBroadcast();

	fd_set fd;
	timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	FD_ZERO(&fd);
	FD_SET(sockfd,&fd);
	
	while(1)
	{
		nResult = select(sockfd,&fd,NULL,NULL,&tv);
		if (nResult != -1)
		{
			if (FD_ISSET(sockfd,&fd))
			{
				nResult = recvfrom(sockfd, receive_message,sizeof(receive_message), 0 , (sockaddr*)&localserver ,&addr_len);
				UnpackMsg(localserver, receive_message);
			}
			else
			{	
				break;
			}
		}
		else
		{
			break;
		}
	}
	closesocket(sockfd);
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (!AfxSocketInit())
	{
		return FALSE;
	}
	
	//char chMsg[1024] = {0};
	//memcpy(chMsg, HttpClient(), 1024);
	//ENCPBroadcast();
	//printf("%s", chMsg);

	HttpClient();

	int a = 0;
	cin>>a;
	return 0;
}
