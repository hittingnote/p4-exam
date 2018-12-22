#include <sys/socket.h>
#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>

//#define __IS_SERVER

using namespace std;

#define SERVER_PORT		8080
#define SERVER_ADDR		"10.0.2.2"

int main(int argc, char *argv[])
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0)
	{
		perror("socket");
		exit(1);
	}

	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_port = htons(SERVER_PORT);
	local.sin_addr.s_addr = inet_addr(SERVER_ADDR);
	socklen_t len = sizeof(struct sockaddr_in);

#ifdef __IS_SERVER
	if(bind(sock, (struct sockaddr*)&local, len) < 0)
	{
		perror("bind");
		exit(1);
	}

	if(listen(sock, 100) < 0)
	{
		perror("listen");
		exit(1);
	}

#else
	if(connect(sock, (struct sockaddr*)&local, len) < 0)
	{
		perror("connect");
		exit(2);
	}
#endif

#ifdef __IS_SERVER
	struct sockaddr_in remote;
	socklen_t len_remote = sizeof(struct sockaddr_in);
	while(1)
	{
		int sock_remote = accept(sock, (struct sockaddr*)&remote, &len_remote);
		if(sock_remote < 0)
		{
			perror("accept");
			continue;
		}

		printf("Get a client, IP: %s, port: %d\n", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
	}
#endif

	return 0;
}


