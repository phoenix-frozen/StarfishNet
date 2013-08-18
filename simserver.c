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

//linked list structure containing broadcast group
typedef struct sockaddr_list {
	struct sockaddr_in addr;
	struct sockaddr_list* next;
} sockaddr_list;
sockaddr_list* sockaddr_list_head = NULL;

int main(void) {
	//create socket
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock == -1)
		DIE("creating sock");

	//init some data structures
	struct sockaddr_in local_addr, remote_addr;
	memset((char*) &local_addr, 0, sizeof(local_addr));

	//set the socket to listen to any port on localhost...
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = 0;
	local_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	//... and bind the socket
	if(bind(sock, (struct sockaddr*) &local_addr, sizeof(local_addr)) == -1)
		DIE("binding sock");

	//now find out what port the socket is bound on
	int slen = sizeof(local_addr);
	if(getsockname(sock, (struct sockaddr*) &local_addr, &slen) == -1)
		DIE("getting socket info");

	printf("Socket bound to port %d\n", ntohs(local_addr.sin_port));

	//enter broadcast loop
	while(1) {
		//allocate and clear some data structures
		char buf[256];
		memset((char*) &remote_addr, 0, sizeof(remote_addr));
		slen = sizeof(remote_addr);

		//receive packet
		if(recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*) &remote_addr, &slen) == -1)
			DIE("listening for packet");
		printf("Received packet from %s:%d\n", inet_ntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port));

		/* Broadcast logic: we have a linked list of nodes we've received packets from before.
		 * For each entry in that linked list:
		 * * Compare the entry with the source of the packet.
		 * * If it's the same, do nothing and move on.
		 * * If it's not the same, tx to that address.
		 * Finally, if we didn't see any 'same' addresses, this must be a new note, so we add
		 * it to the list.
		 */

		//initialise variables
		int addtolist = 1;

		//for each element in the list...
		for(sockaddr_list* list = sockaddr_list_head; list != NULL; list = list->next) {
			//... check if it's the sender...
			if(memcmp(&remote_addr, &(list->addr), sizeof(remote_addr)) == 0) {
				//... in which case we won't record it, and don't send to it
				addtolist = 0;
				continue;
			}

			//... otherwise, send
			if(sendto(sock, buf, sizeof(buf), 0, (struct sockaddr*) &(list->addr), sizeof(remote_addr)) == -1)
				DIE("sending packet");
			printf("Sent packet to %s:%d\n", inet_ntoa(list->addr.sin_addr), ntohs(list->addr.sin_port));
		}

		//if we didn't see the sender in the list, then add it
		if(addtolist) {
			sockaddr_list* newentry = malloc(sizeof(sockaddr_list));
			memcpy(&(newentry->addr), &remote_addr, sizeof(remote_addr));
			newentry->next = sockaddr_list_head;
			sockaddr_list_head = newentry;
		}
	}

	close(sock);
	return 0;
}

