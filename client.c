/*
** client.c -- This template is copied from Beej. 
** However, I have modified most of the code to fit the project's needs.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define HOST "127.0.0.1" // the host client will be connecting to
#define PORT "24256"     // the port client will be connecting to
#define MAXBUFLEN 1024 
#define MAX_USERNAMES 10

// From Beej.
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

// From Beej.
int main(int argc, char *argv[])
{

    // set up TCP
    int sockfd, numbytes;
    char buf[MAXBUFLEN];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(HOST, PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1)
        {
            perror("client: socket");
            continue;
        }
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            perror("client: connect");
            close(sockfd);
            continue;
        }
        break;
    }

    if (p == NULL)
    {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    // get the port number and ip address of the client
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    int getsock_check;
    getsock_check = getsockname(sockfd, (struct sockaddr *)&name, &namelen);
    if (getsock_check == -1)
    {
        perror("getsockname");
        exit(1);
    }
    char *ip = inet_ntoa(name.sin_addr);
    int port = ntohs(name.sin_port);

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
              s, sizeof s);

    printf("Client is up and running.\n");

    
    while (1)
    {
        // get the input from the user
        printf("Please enter the usernames to check schedule availability:\n");
        char input[100];
        fgets(input, 100, stdin);
        input[strcspn(input, "\n")] = 0; // remove the newline character

        // send the input to the server
        if (send(sockfd, input, strlen(input), 0) < 0)
        {
            perror("Error sending string to server");
            close(sockfd);
            return -1;
        }
        printf("Client finished sending the usernames to Main Server.\n");

        char *input_names[MAX_USERNAMES];
        int num_input_names = 0;
        // Tokenize the user_input and store the usernames
        char *token = strtok(input, " ");
        while (token != NULL && num_input_names < MAX_USERNAMES)
        {
            input_names[num_input_names] = malloc(strlen(token) + 1);
            strcpy(input_names[num_input_names], token);
            num_input_names++;
            token = strtok(NULL, " ");
        }

        // receive the result from the server
        if ((numbytes = recv(sockfd, buf, MAXBUFLEN - 1, 0)) == -1)
        {
            perror("recv");
            exit(1);
        }
        buf[numbytes] = '\0';

        // store the non existent names
        char *non_exist_names[MAX_USERNAMES];
        int num_non_exist_names = 0;
        char *non_exist_names_string;

        // if the first character is not '[' then the server sent the non existent names
        if (buf[0] != '[') 
        {
            printf("Client received the reply from the Main Server using TCP over port %d:\n", port);
            printf("%sdo not exist.\n", buf);

            non_exist_names_string = malloc(strlen(buf) + 1);
            strcpy(non_exist_names_string, buf);

            // receive the result from the server again for intersections
            if ((numbytes = recv(sockfd, buf, MAXBUFLEN - 1, 0)) == -1)
            {
                perror("recv");
                exit(1);
            }
            buf[numbytes] = '\0';
        }
        
        // Tokenize the non_exist_names_string and store the usernames
        token = strtok(non_exist_names_string, ", ");
        while (token != NULL && num_non_exist_names < MAX_USERNAMES)
        {
            non_exist_names[num_non_exist_names] = malloc(strlen(token) + 1);
            strcpy(non_exist_names[num_non_exist_names], token);
            num_non_exist_names++;
            token = strtok(NULL, ", ");
        }

        // remove the non existent names from the input names in order to get the names_to_print
        char *names[MAX_USERNAMES];
        int num_names = 0;
        for (int i = 0; i < num_input_names; i++)
        {
            int found = 0;
            for (int j = 0; j < num_non_exist_names; j++)
            {
                if (strcmp(input_names[i], non_exist_names[j]) == 0)
                {
                    found = 1;
                    break;
                }
            }
            if (!found)
            {
                names[num_names] = malloc(strlen(input_names[i]) + 1);
                strcpy(names[num_names], input_names[i]);
                num_names++;
            }
        }

        // print the names_to_print
        char names_to_print[MAXBUFLEN] = "";

        for (int i = 0; i < num_names - 1; i++)
        {
            strcat(names_to_print, names[i]);
            strcat(names_to_print, ", ");
        }
        strcat(names_to_print, names[num_names - 1]);

        printf("Client received the reply from the Main Server using TCP over port %d:\n", port);
        printf("Time intervals %s works for %s.\n", buf, names_to_print);

        // start a new request
        printf("-----Start a new request-----\n");

    }

    freeaddrinfo(servinfo); // all done with this structure
    close(sockfd);

    return 0;
}
