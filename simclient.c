#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DIE(x) { printf("Error %s.\n", x); exit(1); }

int main(int argc, char* argv[]) {
	int rport = 0;
	if(!(argc != 1 && sscanf(argv[1], "%d", &rport) == 1))
		DIE("in arguments");

	printf("Remote port is %d\n", rport);

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if(sock == -1)
		DIE("creating sock");

	struct sockaddr_in remote_addr;

	memset((char*) &remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(rport);
	remote_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	char buf[256];
	memset(buf, 0, sizeof(buf));
	if(sendto(sock, buf, 0, sizeof(buf), (struct sockaddr*) &remote_addr, sizeof(remote_addr)) == -1)
		DIE("sending packet");

	//once we've done a sendto, we can recvfrom the same socket with no further work. don't even need to know the port

	close(sock);
	return 0;
}


