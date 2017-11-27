#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <openssl/aes.h>
#include <openssl/rand.h>


#define BUFFER_SIZE 4096

char* read_file(const char* filename) {
	unsigned char *buffer = 0;
	long length ;
	FILE *f = fopen (filename, "rb");
	
	if (f) {
		fseek (f, 0, SEEK_END);
		length = ftell (f);
		fseek (f, 0, SEEK_SET);
		buffer = malloc (length);
		if (buffer)
			fread (buffer, 1, length, f);
		fclose (f);
	} else
		return 0;
	
	return buffer;
}

struct ctr_state {
	unsigned char ivec[AES_BLOCK_SIZE];  
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
};

int init_ctr(struct ctr_state *state, const unsigned char iv[8]) {
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
	 * first call. */
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);

	/* Initialise counter in 'ivec' to 0 */
	memset(state->ivec + 8, 0, 8);

	/* Copy IV into 'ivec' */
	memcpy(state->ivec, iv, 8);
}

int main(int argc, char *argv[]) {
	int opt = 0;
	char *listen_port = NULL;
	char *dest = NULL;		
	char *dst_port = NULL;
	int server_mode = 0;
	unsigned char *key_fd = NULL;
	struct hostent *host;
	
	while ((opt = getopt(argc, argv, "l:k:")) != -1) {
		switch(opt) {
			case 'l':
				listen_port = optarg;
				server_mode = 1;
				break;
			case 'k':
				key_fd = optarg;
				break;
			case '?':
				if (optopt == 'l') {
					fprintf(stderr, "Please specify port number\n");
					return 0;
				} else if (optopt == 'k') {
					fprintf(stderr, "Please specify the key file\n");
					return 0;
				} else {
					fprintf(stderr, "Unknown argument\n");
					return 0;
				}
			default:
				return 0;
		}
	}
	
	if (optind == argc - 2) {
		dest = argv[optind];
		dst_port = argv[optind+1];
	} else {
		fprintf(stderr, "optind: %d, argc: %d\n", optind, argc);
		return 0;
	}
	
	if (key_fd == NULL) {
		fprintf(stderr, "Specify key file %s\n",strerror(errno));
		return 0;
	}
	
	unsigned const char *key = read_file(key_fd);

	if (!key) {
		fprintf(stderr, "Unable to read key file%s\n",strerror(errno));
		return 0;
	}

	struct sockaddr_in pservaddr, sshservaddr;
	//Clear the addr
	bzero(&pservaddr, sizeof(pservaddr));
	bzero(&sshservaddr, sizeof(sshservaddr));

	int dstport = (int)strtol(dst_port, NULL, 10);
	
	//Get the hostname from the argument
	if ((host=gethostbyname(dest)) == 0) {
		fprintf(stderr, "Hostname resolution error %s\n",strerror(errno));
		return 0;
	}
		
	// struct ctr_state state;
	struct ctr_state client_state;
	unsigned char iv[8];
	struct ctr_state server_state;
	// unsigned char iv_server[8];
	AES_KEY aes_key;
	
	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
		fprintf(stderr, "Error while setting Key %s\n",strerror(errno));
		exit(1);
	}

	//Server Mode
	if (server_mode == 1) {
		int psockfd;
		int lport = (int)strtol(listen_port, NULL, 10);	
		if ((psockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	    {
			fprintf(stderr, "Error while Opening Socket%s\n",strerror(errno));
			return 0;
	    }
		sshservaddr.sin_family = AF_INET;
		sshservaddr.sin_port = htons(dstport);//convert to big-endian order
		sshservaddr.sin_addr.s_addr = ((struct in_addr *)(host->h_addr))->s_addr;

		pservaddr.sin_family = AF_INET;
		//Let the kernel choose the IP address for the proxy server.
		pservaddr.sin_addr.s_addr = htons(INADDR_ANY);
		pservaddr.sin_port = htons(lport);

	    if (bind(psockfd, (struct sockaddr *)&pservaddr, sizeof(pservaddr))<0)
	    {
	        fprintf(stderr,"Error during binding%s\n",strerror(errno));
	     	return 0;
	    }
		if (listen(psockfd, 20) < 0) {
			fprintf(stderr,"Error during listen%s\n",strerror(errno));
			return 0;
		};
		int listensockfd;
		socklen_t clilen;
		struct sockaddr_in clientddr, servaddr;
		//Keep on listening to clients till the server is killed.
		while (1) {	
			bzero(&servaddr, sizeof(servaddr));
			//A new accept means a new client
			listensockfd = accept(psockfd,NULL,NULL);
			if(listensockfd > 0){
				int pid;
				pid = fork();
				if(pid == 0)
				{			
					//Read the IV send from client for decryption on the server
					int t =0;
					if((t = read(listensockfd, client_state.ivec, AES_BLOCK_SIZE)) < 0) {
						fprintf(stderr,"Error during getting IV%s\n",strerror(errno));
						close(listensockfd);
						return 0;
					}
					client_state.num = 0;
					memset(client_state.ecount, 0, AES_BLOCK_SIZE);


					//Once the client is initiated create the IV and send to client
					if(!RAND_bytes(iv, 8)) {
						fprintf(stderr, "Error generating random bytes.\n");
						return 0;
					}
					init_ctr(&server_state, iv);

					if(write(listensockfd,server_state.ivec,AES_BLOCK_SIZE)<0){
						fprintf(stderr, "Error in writing .%s\n",strerror(errno));
						close(listensockfd);
						return 0;
					}


					servaddr = sshservaddr;
					fprintf(stderr,"Connected to  %s\n",host->h_name);
			
					unsigned char buffer[BUFFER_SIZE];
					int serversock_fd, n;
					int end_session = 0;
									
					if ((serversock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
				    {
						fprintf(stderr, "Error Opening Socket%s\n",strerror(errno));
						return 0;
				    }
					
					if (connect(serversock_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
						fprintf(stderr,"Connection to ssh failed %s\n",strerror(errno));
						return 0;
					}

					fcntl(listensockfd, F_SETFL, O_NONBLOCK);
					fcntl(serversock_fd, F_SETFL, O_NONBLOCK);

					//Keep on receiving the requests for the current session.
					while (1) {
						//Read from client and decrypt and send the data to ssh
						while ((n = read(listensockfd, buffer, BUFFER_SIZE)) > 0) {
							unsigned char decryptdata[n];
							AES_ctr128_encrypt(buffer, decryptdata, n, &aes_key, client_state.ivec, client_state.ecount, &client_state.num);
							write(serversock_fd, decryptdata, n);

							if (n < BUFFER_SIZE)
								break;
						}
						if(n==0)
							break;
						
						//Read gives a zero when we reach the End of file.
						while ((n = read(serversock_fd, buffer, BUFFER_SIZE)) > 0) {
							//if(n == 0) goto stop;
								unsigned char encrypdata[n];
								AES_ctr128_encrypt(buffer, encrypdata, n, &aes_key, server_state.ivec, server_state.ecount, &server_state.num);		
								write(listensockfd, encrypdata, n);
								usleep(20000);	
								if (n < BUFFER_SIZE)
									break;
						}
						
					 }
					 close(serversock_fd);
				}else{
					close(listensockfd);

				}	
			}

		}
		//Server code ends here
			close(psockfd);
			
		}
	else 
	{
		// pbproxy running in client mode
		int sockfd, n;
		unsigned char buffer[BUFFER_SIZE];
		
		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	    {
			fprintf(stderr, "Error Opening Socket%s\n",strerror(errno));
			return 0;
	    }
		
		pservaddr.sin_family = AF_INET;
		pservaddr.sin_port = htons(dstport);//convert to big-endian order		
		pservaddr.sin_addr.s_addr = ((struct in_addr *)(host->h_addr))->s_addr;
		
		if (connect(sockfd, (struct sockaddr *)&pservaddr, sizeof(pservaddr)) == -1) {
			fprintf(stderr, "Connection failed%s\n",strerror(errno));
			return 0;
		}
		
		//Once the client is initiated create the IV and send to server
		if(!RAND_bytes(iv, 8)) {
			fprintf(stderr, "Error generating random bytes.\n");
			return 0;
		}
		init_ctr(&client_state, iv);
		// fprintf(stderr,"ivect at client : %s",state.ivec);

		if(write(sockfd,client_state.ivec,AES_BLOCK_SIZE)<0){
			fprintf(stderr, "Error in writing .%s\n",strerror(errno));
			close(sockfd);
			return 0;
		}

		int t =0;
		if((t = read(sockfd, server_state.ivec, AES_BLOCK_SIZE)) < 0) {
			fprintf(stderr,"Error during getting IV%s\n",strerror(errno));
			close(sockfd);
			return 0;
		}
		server_state.num = 0;
		memset(server_state.ecount, 0, AES_BLOCK_SIZE);

		fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
		fcntl(sockfd, F_SETFL, O_NONBLOCK);

		while(1) {
			// When a TCP connection terminates a 0 length message is read
			while ((n = read(STDIN_FILENO, buffer, BUFFER_SIZE)) > 0) {
				//fprintf(stderr,"Inside client reading input\n");
				unsigned char encrypdata[n];
				AES_ctr128_encrypt(buffer, encrypdata, n, &aes_key, client_state.ivec, client_state.ecount, &client_state.num);
				write(sockfd, encrypdata, n);
				usleep(20000);
				// send(sockfd, buffer, n,0);
				if (n < BUFFER_SIZE)
					break;
			}
			
			// while ((n = receive(sockfd, buffer, BUFFER_SIZE,0)) > 0) {
			while ((n = read(sockfd, buffer, BUFFER_SIZE)) > 0) {
				unsigned char decryptdata[n];
				AES_ctr128_encrypt(buffer, decryptdata, n, &aes_key, server_state.ivec, server_state.ecount, &server_state.num);
				write(STDOUT_FILENO, decryptdata, n); 
				// write(STDOUT_FILENO, buffer, n);
				if (n < BUFFER_SIZE)
					break;
			}
		}
		close(sockfd);
	}
	
	return 0;
}


