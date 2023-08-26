#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PORT_A "21256"   // the port the main server will be connecting to
#define HOST "127.0.0.1" // the host the main server will be connecting to
#define MAXBUFLEN 1024
#define PORT_UDP "23256" // the port of the main server that backend servers will be connecting to
#define MAX_NAME_LEN 20
#define MAX_INTERVALS 20
#define MAX_LINE_LEN 200
#define MAX_USERNAMES 10

typedef struct
{
    char name[MAX_NAME_LEN];
    int intervals[MAX_INTERVALS][2];
    int num_intervals;
} TimeInfo;

void *get_in_addr(struct sockaddr *sa);
int setup_listener(const char *host, const char *port);
int read_data_from_file(TimeInfo *time_info_list, int *time_info_count);
int send_usernames_to_serverM(TimeInfo *time_info_list, int time_info_count);
int receive_names_from_serverM(int sockfd, char *names_from_M[], int *num_names_from_M);
void find_intersection(TimeInfo *time_info_list, int time_info_count, char *names_from_M[], int num_names_from_M, int intersection[][2], int *num_intersection_intervals);
void print_intersection(int intersection[][2], int num_intersection_intervals, char *names_from_M[], int num_names_from_M);
int send_intersection_to_serverM(int (*intersection)[2], int num_intersection_intervals);

int main(void)
{
    printf("ServerA is up and running using UDP on port %s.\n", PORT_A);
    
    // set up UDP
    int sockfd;
    sockfd = setup_listener(HOST, PORT_A);

    // read data from file
    TimeInfo time_info_list[MAX_INTERVALS];
    int time_info_count = 0;
    read_data_from_file(time_info_list, &time_info_count);

    // send usernames to main server
    send_usernames_to_serverM(time_info_list, time_info_count);
    printf("ServerA finished sending a list of usernames to Main Server.\n");

    // main while loop
    while (1)
    {
        // receive names from main server
        char *names_from_M[MAX_USERNAMES];
        int num_names_from_M = 0;
        receive_names_from_serverM(sockfd, names_from_M, &num_names_from_M);
        printf("Server A received the usernames from Main Server using UDP over port %s.\n", PORT_A);

        // find intersection
        int intersection[MAX_INTERVALS][2];
        int num_intersection_intervals = 0;
        find_intersection(time_info_list, time_info_count, names_from_M, num_names_from_M, intersection, &num_intersection_intervals);
        print_intersection(intersection, num_intersection_intervals, names_from_M, num_names_from_M);

        // send intersection to main server
        send_intersection_to_serverM(intersection, num_intersection_intervals);
        printf("Server A finished sending the response to Main Server.\n");
    }

    close(sockfd);
    return 0;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int setup_listener(const char *host, const char *port)
{
    struct addrinfo hints, *servinfo, *p;
    int sockfd;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

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
        return -1;
    }

    freeaddrinfo(servinfo);
    return sockfd;
}

int receive_names_from_serverM(int sockfd, char *names_from_M[], int *num_names_from_M)
{
    struct sockaddr_storage their_addr;
    socklen_t addr_len;
    char buf[MAXBUFLEN];
    int numbytes;

    addr_len = sizeof their_addr;
    if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN - 1, 0,
                             (struct sockaddr *)&their_addr, &addr_len)) == -1)
    {
        perror("recvfrom");
        return -1;
    }

    buf[numbytes] = '\0';

    char *token = strtok(buf, " ");
    while (token != NULL && *num_names_from_M < MAX_USERNAMES)
    {
        names_from_M[*num_names_from_M] = malloc(strlen(token) + 1);
        strcpy(names_from_M[*num_names_from_M], token);
        (*num_names_from_M)++;
        token = strtok(NULL, " ");
    }

    return 0;
}

int read_data_from_file(TimeInfo *time_info_list, int *time_info_count)
{
    FILE *file;
    char line[MAX_LINE_LEN];
    char line_without_spaces[MAX_LINE_LEN];

    *time_info_count = 0;

    file = fopen("a.txt", "r");

    while (fgets(line, sizeof(line), file))
    {
        TimeInfo temp;
        int name_len = 0;
        int interval_idx = 0;

        // remove all the spaces from the input line
        int i, j;
        for (i = 0, j = 0; line[i] != '\0'; i++)
        {
            if (line[i] != ' ')
            {
                line_without_spaces[j++] = line[i];
            }
        }
        line_without_spaces[j] = '\0';

        int line_len = strlen(line_without_spaces);

        while (line_without_spaces[name_len] != ';' && name_len < line_len)
        {
            name_len++;
        }

        strncpy(temp.name, line_without_spaces, name_len);
        temp.name[name_len] = '\0';

        i = name_len + 3;
        while (i < line_len && interval_idx < MAX_INTERVALS)
        {
            sscanf(&line_without_spaces[i], "%d,%d", &temp.intervals[interval_idx][0], &temp.intervals[interval_idx][1]);
            while (line_without_spaces[i] != ']' && i < line_len)
            {
                i++;
            }
            i += 3;

            // only store the interval if the start time is smaller than the end time
            if (temp.intervals[interval_idx][0] < temp.intervals[interval_idx][1] && temp.intervals[interval_idx][0] >= 0 && temp.intervals[interval_idx][1] <= 100)
            {
                interval_idx++;
            }
        }

        temp.num_intervals = interval_idx;
        time_info_list[*time_info_count] = temp;
        (*time_info_count)++;
    }

    fclose(file);
    return 0;
}

int send_usernames_to_serverM(TimeInfo *time_info_list, int time_info_count)
{
    struct sockaddr_in serverM_addr;
    int sockfd;

    // Create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd == -1)
    {
        perror("socket");
        return -1;
    }

    // Set the serverM address information
    memset(&serverM_addr, 0, sizeof(serverM_addr));
    serverM_addr.sin_family = AF_INET;
    serverM_addr.sin_port = htons(atoi(PORT_UDP));
    inet_pton(AF_INET, HOST, &serverM_addr.sin_addr);

    // Concatenate the usernames to a string separated by spaces
    char usernames_str[MAXBUFLEN] = "";
    for (int i = 0; i < time_info_count; i++)
    {
        if (i != 0)
        {
            strcat(usernames_str, " ");
        }
        strcat(usernames_str, time_info_list[i].name);
    }

    // Send the concatenated usernames string to serverM
    if (sendto(sockfd, usernames_str, strlen(usernames_str) + 1, 0,
               (struct sockaddr *)&serverM_addr, sizeof(serverM_addr)) == -1)
    {
        perror("sendto");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

void find_intersection(TimeInfo *time_info_list, int time_info_count, char *names_from_M[], int num_names_from_M, int intersection[][2], int *num_intersection_intervals)
{
    int current_intersection[MAX_INTERVALS][2] = {0};
    int current_num_intervals = 0;

    for (int i = 0; i < time_info_count; i++)
    {
        for (int j = 0; j < num_names_from_M; j++)
        {
            if (strcmp(time_info_list[i].name, names_from_M[j]) == 0)
            {
                if (current_num_intervals == 0)
                {
                    memcpy(current_intersection, time_info_list[i].intervals, sizeof(time_info_list[i].intervals));
                    current_num_intervals = time_info_list[i].num_intervals;
                }
                else
                {
                    int temp_intersection[MAX_INTERVALS][2] = {0};
                    int temp_num_intervals = 0;

                    for (int k = 0; k < current_num_intervals; k++)
                    {
                        for (int l = 0; l < time_info_list[i].num_intervals; l++)
                        {
                            int start = current_intersection[k][0] > time_info_list[i].intervals[l][0] ? current_intersection[k][0] : time_info_list[i].intervals[l][0];
                            int end = current_intersection[k][1] < time_info_list[i].intervals[l][1] ? current_intersection[k][1] : time_info_list[i].intervals[l][1];

                            if (start < end)
                            {
                                temp_intersection[temp_num_intervals][0] = start;
                                temp_intersection[temp_num_intervals][1] = end;
                                temp_num_intervals++;
                            }
                        }
                    }

                    memcpy(current_intersection, temp_intersection, sizeof(temp_intersection));
                    current_num_intervals = temp_num_intervals;
                }

                break;
            }
        }
    }

    memcpy(intersection, current_intersection, sizeof(current_intersection));
    *num_intersection_intervals = current_num_intervals;
}

void print_intersection(int intersection[][2], int num_intersection_intervals, char *names_from_M[], int num_names_from_M)
{
    printf("Found the intersection result: ");

    if (num_intersection_intervals == 0)
    {
        printf("[] ");
        printf("for ");
        for (int i = 0; i < num_names_from_M - 1; i++)
        {
            printf("%s, ", names_from_M[i]);
        }
        printf("%s.", names_from_M[num_names_from_M - 1]);
        printf("\n");
        return;
    }

    printf("[");
    for (int i = 0; i < num_intersection_intervals - 1; i++)
    {
        printf("[%d, %d],", intersection[i][0], intersection[i][1]);
    }
    printf("[%d, %d]] ", intersection[num_intersection_intervals - 1][0], intersection[num_intersection_intervals - 1][1]);
    printf("for ");
    for (int i = 0; i < num_names_from_M - 1; i++)
    {
        printf("%s, ", names_from_M[i]);
    }
    printf("%s.", names_from_M[num_names_from_M - 1]);
    printf("\n");
}

int send_intersection_to_serverM(int (*intersection)[2], int num_intersection_intervals)
{

    struct sockaddr_in serverM_addr;
    int sockfd;

    // Create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd == -1)
    {
        perror("socket");
        return -1;
    }

    // Set the serverM address information
    memset(&serverM_addr, 0, sizeof(serverM_addr));
    serverM_addr.sin_family = AF_INET;
    serverM_addr.sin_port = htons(atoi(PORT_UDP));
    inet_pton(AF_INET, HOST, &serverM_addr.sin_addr);

    char intersection_str[MAXBUFLEN];
    memset(intersection_str, 0, sizeof(intersection_str));

    for (int i = 0; i < num_intersection_intervals; i++)
    {
        char interval_str[MAX_NAME_LEN];
        snprintf(interval_str, sizeof(interval_str), "[%d,%d]", intersection[i][0], intersection[i][1]);

        if (i != 0)
        {
            strcat(intersection_str, " ");
        }
        strcat(intersection_str, interval_str);
    }

    int numbytes;
    if ((numbytes = sendto(sockfd, intersection_str, strlen(intersection_str) + 1, 0,
                           (struct sockaddr *)&serverM_addr, sizeof(serverM_addr))) == -1)
    {
        perror("sendto");
        close(sockfd);
        return -1;
    }

    return 0;
}
