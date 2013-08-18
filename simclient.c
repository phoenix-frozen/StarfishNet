#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#define DIE(x) { printf("Error %s (errno says %s).\n", x, strerror(errno)); exit(1); }

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

	while(1) {
		char buf[256];
		memset(buf, 0, sizeof(buf));
		if(sendto(sock, buf, sizeof(buf), 0, (struct sockaddr*) &remote_addr, sizeof(remote_addr)) == -1)
			DIE("sending packet");
		printf("Sent packet to %s:%d\n", inet_ntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port));

		for(int i = 0; i < 5; i++) {
			int slen = sizeof(remote_addr);
			if(recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*) &remote_addr, &slen) == -1)
				DIE("listening for packet");

			printf("Received packet from %s:%d\n", inet_ntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port));
		}
	}

	close(sock);
	return 0;
}

