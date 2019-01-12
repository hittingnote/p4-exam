#include <sys/socket.h>
#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

using namespace std;


#define SERVER_PORT   8080
#define SERVER_ADDR   "10.0.2.2"

int main(int argc, char *argv[])
{
	while(1)
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

		if(connect(sock, (struct sockaddr*)&local, len) < 0)
		{
			perror("connect");
			exit(2);
		}
	}
}
