#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>
#include <ctype.h>

#define PORT_TCP "24256" // the port users will be connecting to
#define PORT_UDP "23256" // the port backend servers will be connecting to
#define HOST "127.0.0.1" // the host client will be connecting to
#define PORT_A "21256"   // port of backend server A
#define PORT_B "22256"   // port of backend server B
#define MAXBUFLEN 1024
#define MAX_USERNAMES 100
#define BACKLOG 10 // how many pending connections queue will hold

// struct to store usernames
typedef struct
{
    char **usernames;
    int num_usernames;
} UsernamesData;

// struct to store intersections
typedef struct
{
    int (*intersections)[2];
    int num_intersections;
} IntersectionsData;

void sigchld_handler(int s);
void *get_in_addr(struct sockaddr *sa);
void receive_usernames_from_serverA(int sockfd_UDP, UsernamesData *userdata);
void receive_usernames_from_serverB(int sockfd_UDP, UsernamesData *userdata);
void receive_intersection_from_serverA(int sockfd_UDP, IntersectionsData *data);
void receive_intersection_from_serverB(int sockfd_UDP, IntersectionsData *data);
void initialize_TCP_socket(struct addrinfo *hints, struct addrinfo **servinfo);
int create_TCP_socket_and_bind(struct addrinfo *servinfo);
int create_UDP_socket();
void init_UsernamesData(UsernamesData *userdata);
void init_IntersectionsData(IntersectionsData *intersections_data);
void process_usernames(char *buffer, char *input_names[], int *num_input_names);
void create_backend_sockets(int *sockfd_A, int *sockfd_B, struct sockaddr_in *backend_addr_A, struct sockaddr_in *backend_addr_B);
void free_allocated_memory(IntersectionsData *intersections_data, char *input_names[], int num_input_names);
IntersectionsData find_intersection_of_intersections_data(IntersectionsData intersections_data_A, IntersectionsData intersections_data_B);
char *create_message_from_intersections_data(IntersectionsData intersections_data_M);
void convert_to_comma_separated(const char *input, char *output);\
void convert_to_printable_list(const char *input, char *output);

// This main function is also based on Beej's guide.
int main(void) {
    int sockfd_TCP, new_fd; // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;

    // Initialize the TCP socket
    initialize_TCP_socket(&hints, &servinfo);

    // Create the TCP socket and bind it to the port
    sockfd_TCP = create_TCP_socket_and_bind(servinfo);
    freeaddrinfo(servinfo); // all done with this structure
    if (listen(sockfd_TCP, BACKLOG) == -1)
    {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    // Create the UDP socket
    int sockfd_UDP = create_UDP_socket();

    printf("Main Server is up and running.\n");

    // Initialize the UsernamesData structure
    UsernamesData userdata_A, userdata_B;
    init_UsernamesData(&userdata_A);
    init_UsernamesData(&userdata_B);
    // Receive the usernames from the backend servers and store them in the UsernamesData structure
    receive_usernames_from_serverA(sockfd_UDP, &userdata_A);
    receive_usernames_from_serverB(sockfd_UDP, &userdata_B);

    while (1)
    { // main accept() loop

        // Initialize the IntersectionsData structure
        IntersectionsData intersections_data_A, intersections_data_B;
        init_IntersectionsData(&intersections_data_A);
        init_IntersectionsData(&intersections_data_B);

        // connect with the backend servers
        int sockfd_A, sockfd_B;
        struct sockaddr_in backend_addr_A, backend_addr_B;
        create_backend_sockets(&sockfd_A, &sockfd_B, &backend_addr_A, &backend_addr_B);

        // connect with the client
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd_TCP, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1)
        {
            perror("accept");
            continue;
        }

        // fork a child process to handle the client request
        if (!fork())
        {// this is the child process
            close(sockfd_TCP); // child doesn't need the listener

            while (1)
            {
                // receive the request from the client
                char buffer[MAXBUFLEN];
                memset(buffer, 0, MAXBUFLEN);
                int numbytes;
                if ((numbytes = recv(new_fd, buffer, 100 - 1, 0)) == -1)
                {
                    perror("recv");
                    exit(1);
                }
                buffer[numbytes] = '\0';
                printf("Main Server received the request from the client using TCP over port %s.\n", PORT_TCP);

                // store the usernames from the client request
                char *input_names[MAX_USERNAMES];
                int num_input_names = 0;
                // Tokenize the user_input and store the usernames
                char *token = strtok(buffer, " ");
                while (token != NULL && num_input_names < MAX_USERNAMES)
                {
                    input_names[num_input_names] = malloc(strlen(token) + 1);
                    strcpy(input_names[num_input_names], token);
                    num_input_names++;
                    token = strtok(NULL, " ");
                }

                // classify the usernames
                char names_in_A[MAXBUFLEN] = "";
                char names_in_B[MAXBUFLEN] = "";
                char names_not_found[MAXBUFLEN] = "";

                // Process the input names
                for (int i = 0; i < num_input_names; i++)
                {
                    int found = 0;
                    for (int j = 0; j < userdata_A.num_usernames; j++)
                    {
                        if (strcmp(input_names[i], userdata_A.usernames[j]) == 0)
                        {
                            found = 1;
                            strcat(names_in_A, input_names[i]);
                            strcat(names_in_A, " ");
                            break;
                        }
                    }
                    if (found == 0)
                    {
                        for (int j = 0; j < userdata_B.num_usernames; j++)
                        {
                            if (strcmp(input_names[i], userdata_B.usernames[j]) == 0)
                            {
                                found = 1;
                                strcat(names_in_B, input_names[i]);
                                strcat(names_in_B, " ");
                                break;
                            }
                        }
                    }
                    if (found == 0)
                    {
                        strcat(names_not_found, input_names[i]);
                        strcat(names_not_found, " ");
                    }
                }

                // print the required message in the console
                char names_not_found_to_print[strlen(names_not_found) + 20];
                convert_to_comma_separated(names_not_found, names_not_found_to_print);
                if (strlen(names_not_found) > 0) {
                    printf("%sdo not exist. Send a reply to the client.\n", names_not_found_to_print);
                        // send names_not_found to the client
                        if (send(new_fd, names_not_found_to_print, strlen(names_not_found_to_print), 0) == -1)
                    {
                        perror("send");
                        exit(1);
                    }
                    usleep(100000);
                }

                char names_in_A_to_print[strlen(names_in_A) + 20];
                convert_to_comma_separated(names_in_A, names_in_A_to_print);

                if (strlen(names_in_A_to_print) > 0) {
                    printf("Found %slocated at Server A. Send to Server A.\n", names_in_A_to_print);
                }

                char names_in_B_to_print[strlen(names_in_B) + 20];
                convert_to_comma_separated(names_in_B, names_in_B_to_print);

                if (strlen(names_in_B_to_print) > 0){
                    printf("Found %slocated at Server B. Send to Server B.\n", names_in_B_to_print);
                }

                // Initialize the IntersectionsData to store the intersections received from the backend servers
                init_IntersectionsData(&intersections_data_A);
                init_IntersectionsData(&intersections_data_B);

                if (strlen(names_in_A) > 0)
                {
                    // send the request to the backend server A
                    if (sendto(sockfd_A, names_in_A, strlen(names_in_A), 0, (struct sockaddr *)&backend_addr_A, sizeof backend_addr_A) == -1)
                    {
                        perror("sendto");
                        exit(1);
                    }


                    // Call the function to receive intersections from serverA
                    receive_intersection_from_serverA(sockfd_UDP, &intersections_data_A);
                }

                if (strlen(names_in_B) > 0)
                { // send the request to the backend server B
                    if (sendto(sockfd_B, names_in_B, strlen(names_in_B), 0, (struct sockaddr *)&backend_addr_B, sizeof backend_addr_B) == -1)
                    {
                        perror("sendto");
                        exit(1);
                    }   


                    // Call the function to receive intersections from serverB
                    receive_intersection_from_serverB(sockfd_UDP, &intersections_data_B);
                }

                // Initialize the IntersectionsData that will be sent to the client
                IntersectionsData intersections_data_M;

                // Find the intersection of intersections_data_A and intersections_data_B
                intersections_data_M = find_intersection_of_intersections_data(intersections_data_A, intersections_data_B);

                // Create the message from the intersected intersections_data_M
                char *message;
                message = create_message_from_intersections_data(intersections_data_M);

                // Print the message in the console
                printf("Found the intersection between the results from server A and B:\n%s.\n", message);
                printf("Main Server sent the result to the client.\n");

                // Send the response to the client
                send(new_fd, message, strlen(message), 0);

                // Free the allocated memory
                free(intersections_data_M.intersections);
            }

            free_allocated_memory(&intersections_data_A, userdata_A.usernames, userdata_A.num_usernames);
            free_allocated_memory(&intersections_data_B, userdata_B.usernames, userdata_B.num_usernames);
            close(sockfd_A);
            close(sockfd_B);
            close(sockfd_UDP);
            close(new_fd);
            exit(0);
        }

        close(new_fd); // parent doesn't need this
    }

    return 0;
}

void sigchld_handler(int s)
{
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void initialize_TCP_socket(struct addrinfo *hints, struct addrinfo **servinfo)
{
    memset(hints, 0, sizeof *hints);
    hints->ai_family = AF_UNSPEC;
    hints->ai_socktype = SOCK_STREAM;
    hints->ai_flags = AI_PASSIVE; // use my IP

    int rv;
    if ((rv = getaddrinfo(NULL, PORT_TCP, hints, servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }
}

int create_TCP_socket_and_bind(struct addrinfo *servinfo)
{
    struct addrinfo *p;
    int sockfd;
    int yes = 1;

    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    return sockfd;
}

int create_UDP_socket()
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT_UDP, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("listener: bind");
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        fprintf(stderr, "listener: failed to bind socket\n");
        return 2;
    }

    freeaddrinfo(servinfo);

    return sockfd;
}

void init_UsernamesData(UsernamesData *userdata)
{
    userdata->usernames = malloc(MAX_USERNAMES * sizeof(char *));
    for (int i = 0; i < MAX_USERNAMES; i++)
    {
        userdata->usernames[i] = NULL;
    }
    userdata->num_usernames = 0;
}

void init_IntersectionsData(IntersectionsData *intersections_data)
{
    intersections_data->intersections = malloc(MAX_USERNAMES * sizeof(int[2]));
    intersections_data->num_intersections = 0;
}

void process_usernames(char *buffer, char *input_names[], int *num_input_names)
{
    char *token = strtok(buffer, ",");
    *num_input_names = 0;

    while (token != NULL)
    {
        input_names[*num_input_names] = strdup(token);
        (*num_input_names)++;
        token = strtok(NULL, ",");
    }
}

void create_backend_sockets(int *sockfd_A, int *sockfd_B, struct sockaddr_in *backend_addr_A, struct sockaddr_in *backend_addr_B)
{
    *sockfd_A = socket(AF_INET, SOCK_DGRAM, 0);
    if (*sockfd_A < 0)
    {
        perror("socket");
        exit(1);
    }

    *sockfd_B = socket(AF_INET, SOCK_DGRAM, 0);
    if (*sockfd_B < 0)
    {
        perror("socket");
        exit(1);
    }

    memset(backend_addr_A, 0, sizeof(*backend_addr_A));
    backend_addr_A->sin_family = AF_INET;
    backend_addr_A->sin_port = htons(atoi(PORT_A));
    inet_pton(AF_INET, HOST, &(backend_addr_A->sin_addr));

    memset(backend_addr_B, 0, sizeof(*backend_addr_B));
    backend_addr_B->sin_family = AF_INET;
    backend_addr_B->sin_port = htons(atoi(PORT_B));
    inet_pton(AF_INET, HOST, &(backend_addr_B->sin_addr));
}

void free_allocated_memory(IntersectionsData *intersections_data, char *input_names[], int num_input_names)
{
    free(intersections_data->intersections);
    intersections_data->intersections = NULL;

    for (int i = 0; i < num_input_names; i++)
    {
        free(input_names[i]);
        input_names[i] = NULL;
    }
}

void receive_usernames_from_serverA(int sockfd_UDP, UsernamesData *data)
{
    struct sockaddr_in serverA_addr;
    socklen_t serverA_addr_len = sizeof(serverA_addr);
    char buffer[MAXBUFLEN];
    int recv_len;

    // Receive usernames from serverA
    memset(buffer, 0, sizeof(buffer));
    recv_len = recvfrom(sockfd_UDP, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&serverA_addr, &serverA_addr_len);
    if (recv_len == -1)
    {
        perror("recvfrom");
        exit(1);
    }

    buffer[recv_len] = '\0';
    printf("Main Server received the username list from server A using UDP over port %s.\n", PORT_UDP);
    // Split the received string into individual usernames and store them
    char *token = strtok(buffer, " ");
    while (token != NULL)
    {
        data->usernames = realloc(data->usernames, (data->num_usernames + 1) * sizeof(char *));
        data->usernames[data->num_usernames] = malloc((strlen(token) + 1) * sizeof(char));
        strcpy(data->usernames[data->num_usernames], token);
        data->num_usernames++;
        token = strtok(NULL, " ");
    }
}

void receive_usernames_from_serverB(int sockfd_UDP, UsernamesData *data)
{
    struct sockaddr_in serverB_addr;
    socklen_t serverB_addr_len = sizeof(serverB_addr);
    char buffer[MAXBUFLEN];
    int recv_len;

    // Receive usernames from serverB
    memset(buffer, 0, sizeof(buffer));
    recv_len = recvfrom(sockfd_UDP, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&serverB_addr, &serverB_addr_len);
    if (recv_len == -1)
    {
        perror("recvfrom");
        exit(1);
    }

    buffer[recv_len] = '\0';
    printf("Main Server received the username list from server B using UDP over port %s.\n", PORT_UDP);
    // Split the received string into individual usernames and store them
    char *token = strtok(buffer, " ");
    while (token != NULL)
    {
        data->usernames = realloc(data->usernames, (data->num_usernames + 1) * sizeof(char *));
        data->usernames[data->num_usernames] = malloc((strlen(token) + 1) * sizeof(char));
        strcpy(data->usernames[data->num_usernames], token);
        data->num_usernames++;
        token = strtok(NULL, " ");
    }
}

void receive_intersection_from_serverA(int sockfd_UDP, IntersectionsData *data)
{
    struct sockaddr_in serverA_addr;
    socklen_t serverA_addr_len = sizeof(serverA_addr);
    char buffer[MAXBUFLEN];
    int recv_len;

    // Receive intersections string from serverA
    memset(buffer, 0, sizeof(buffer));
    recv_len = recvfrom(sockfd_UDP, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&serverA_addr, &serverA_addr_len);
    if (recv_len == -1)
    {
        perror("recvfrom");
        exit(1);
    }

    buffer[recv_len] = '\0';
    char list_from_serverA[strlen(buffer) + 50];
    convert_to_printable_list(buffer, list_from_serverA);

    printf("Main Server received from server A the intersection result using UDP over port %s:\n", PORT_UDP);
    printf("%s.\n", list_from_serverA);

    // Parse the received string and store intersections in the data structure
    char *token = strtok(buffer, " ");
    while (token != NULL)
    {
        int start, end;
        sscanf(token, "[%d,%d]", &start, &end);

        data->intersections = realloc(data->intersections, (data->num_intersections + 1) * sizeof(*data->intersections));
        data->intersections[data->num_intersections][0] = start;
        data->intersections[data->num_intersections][1] = end;
        data->num_intersections++;

        token = strtok(NULL, " ");
    }
}

void receive_intersection_from_serverB(int sockfd_UDP, IntersectionsData *data)
{
    struct sockaddr_in serverB_addr;
    socklen_t serverB_addr_len = sizeof(serverB_addr);
    char buffer[MAXBUFLEN];
    int recv_len;

    // Receive intersections string from serverB
    memset(buffer, 0, sizeof(buffer));
    recv_len = recvfrom(sockfd_UDP, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&serverB_addr, &serverB_addr_len);
    if (recv_len == -1)
    {
        perror("recvfrom");
        exit(1);
    }

    buffer[recv_len] = '\0';
    char list_from_serverB[strlen(buffer) + 50];
    convert_to_printable_list(buffer, list_from_serverB);

    printf("Main Server received from server B the intersection result using UDP over port %s:\n", PORT_UDP);
    printf("%s.\n", list_from_serverB);

    // Parse the received string and store intersections in the data structure
    char *token = strtok(buffer, " ");
    while (token != NULL)
    {
        int start, end;
        sscanf(token, "[%d,%d]", &start, &end);

        data->intersections = realloc(data->intersections, (data->num_intersections + 1) * sizeof(*data->intersections));
        data->intersections[data->num_intersections][0] = start;
        data->intersections[data->num_intersections][1] = end;
        data->num_intersections++;

        token = strtok(NULL, " ");
    }
}

IntersectionsData find_intersection_of_intersections_data(IntersectionsData intersections_data_A, IntersectionsData intersections_data_B)
{
    if (intersections_data_A.num_intersections == 0 && intersections_data_B.num_intersections == 0)
    {
        IntersectionsData empty_result;
        empty_result.intersections = NULL;
        empty_result.num_intersections = 0;
        return empty_result;
    }

    if (intersections_data_A.num_intersections == 0)
    {
        return intersections_data_B;
    }

    if (intersections_data_B.num_intersections == 0)
    {
        return intersections_data_A;
    }

    IntersectionsData intersections_data_M;
    intersections_data_M.intersections = malloc(sizeof(int[2]) * 10);
    intersections_data_M.num_intersections = 0;

    for (int a_idx = 0; a_idx < intersections_data_A.num_intersections; a_idx++)
    {
        for (int b_idx = 0; b_idx < intersections_data_B.num_intersections; b_idx++)
        {
            int start = intersections_data_A.intersections[a_idx][0] > intersections_data_B.intersections[b_idx][0] ? intersections_data_A.intersections[a_idx][0] : intersections_data_B.intersections[b_idx][0];
            int end = intersections_data_A.intersections[a_idx][1] < intersections_data_B.intersections[b_idx][1] ? intersections_data_A.intersections[a_idx][1] : intersections_data_B.intersections[b_idx][1];

            if (start < end)
            {
                intersections_data_M.intersections[intersections_data_M.num_intersections][0] = start;
                intersections_data_M.intersections[intersections_data_M.num_intersections][1] = end;
                intersections_data_M.num_intersections++;
            }
        }
    }

    return intersections_data_M;
}

char *create_message_from_intersections_data(IntersectionsData intersections_data_M)
{
    const int MAX_INTERSECTION_STRING_LENGTH = 100;
    const int MAX_MESSAGE_LENGTH = intersections_data_M.num_intersections * MAX_INTERSECTION_STRING_LENGTH + 3;

    char *message_to_client = malloc(MAX_MESSAGE_LENGTH);
    memset(message_to_client, 0, MAX_MESSAGE_LENGTH);

    strcat(message_to_client, "[");

    for (int i = 0; i < intersections_data_M.num_intersections; i++)
    {
        char intersection_str[MAX_INTERSECTION_STRING_LENGTH];
        snprintf(intersection_str, MAX_INTERSECTION_STRING_LENGTH, "[%d,%d]", intersections_data_M.intersections[i][0], intersections_data_M.intersections[i][1]);

        strcat(message_to_client, intersection_str);

        if (i < intersections_data_M.num_intersections - 1)
        {
            strcat(message_to_client, ", ");
        }
    }

    strcat(message_to_client, "]");

    return message_to_client;
}

void convert_to_comma_separated(const char *input, char *output)
{
    int input_len = strlen(input);
    int output_index = 0;

    for (int i = 0; i < input_len; i++)
    {
        if (input[i] == ' ' && input[i + 1] != '\0')
        {
            output[output_index++] = ',';
            output[output_index++] = ' ';
        }
        else
        {
            output[output_index++] = input[i];
        }
    }
    output[output_index] = '\0';
}

void convert_to_printable_list(const char *input, char *output)
{
    int input_len = strlen(input);
    output[0] = '[';
    int output_index = 1;

    for (int i = 0; i < input_len; i++)
    {
        if (input[i] == ' ' && input[i + 1] != '\0')
        {
            output[output_index++] = ',';
            output[output_index++] = ' ';
        }
        else
        {
            output[output_index++] = input[i];
        }
    }
    output[output_index++] = ']';
    output[output_index] = '\0';
}
