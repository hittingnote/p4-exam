#include <sys/socket.h>
#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

//#define __IS_SERVER

using namespace std;

int sock;

#define SERVER_PORT		8080
#define SERVER_ADDR		"10.0.2.2"


void exit_handler(int signo)
{
	close(sock);
	exit(0);
}

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
	signal(SIGINT, exit_handler);
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

//		printf("Get a client, IP: %s, port: %d\n", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));

		char buffer[1024];
		unsigned int size = recvfrom(sock_remote, buffer, 1023, 0, (struct sockaddr*)&remote, &len_remote);
		buffer[size] = 0;
		printf("Recv from client: %s\n", buffer);

		sprintf(buffer, "Hello, client!");
		sendto(sock_remote, buffer, sizeof(buffer), 0, (const struct sockaddr*)&remote, len_remote);
		printf("Send to client: Hello client!\n");

		close(sock_remote);
	}
#else
	char buffer[1024];
	sprintf(buffer, "Hello, server!");
	sendto(sock, buffer, sizeof(buffer), 0, (const struct sockaddr*)&local, len);
	printf("Send to server: Hello server!\n");

	unsigned int size = recvfrom(sock, buffer, 1023, 0, (struct sockaddr*)&local, &len);
	buffer[size] = 0;
	printf("Recv from server: %s\n", buffer);

	close(sock);
#endif

	return 0;
}


