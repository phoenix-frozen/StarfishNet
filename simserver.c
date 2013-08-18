#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DIE(x) { printf("Error %s.\n", x); exit(1); }

int main(void) {
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if(sock == -1)
		DIE("creating sock");

	struct sockaddr_in local_addr, remote_addr;
	memset((char*) &local_addr, 0, sizeof(local_addr));

	local_addr.sin_family = AF_INET;
	local_addr.sin_port = 0;
	local_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if(bind(sock, (struct sockaddr*) &local_addr, sizeof(local_addr)) == -1)
		DIE("binding sock");

	int slen = sizeof(local_addr);
	if(getsockname(sock, (struct sockaddr*) &local_addr, &slen) == -1)
		DIE("getting socket info");

	//success
	printf("Socket bound to port %d\n", ntohs(local_addr.sin_port));

	char buf[256];
	memset((char*) &remote_addr, 0, sizeof(remote_addr));
	slen = sizeof(remote_addr);
	if(recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*) &remote_addr, &slen) == -1)
		DIE("listening for packet");

	close(sock);
	return 0;
}


