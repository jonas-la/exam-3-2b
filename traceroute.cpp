#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <netdb.h>

/* IP Header */
struct ipheader {
    unsigned char iph_ihl : 4, iph_ver : 4;           // IP Header length & Version.
    unsigned char iph_tos;                            // Type of service
    unsigned short int iph_len;                       // IP Packet length (Both data and header)
    unsigned short int iph_ident;                     // Identification
    unsigned short int iph_flag : 3, iph_offset : 13; // Flags and Fragmentation offset
    unsigned char iph_ttl;                            // Time to Live
    unsigned char iph_protocol;                       // Type of the upper-level protocol
    unsigned short int iph_chksum;                    // IP datagram checksum
    struct in_addr iph_sourceip;                      // IP Source address (In network byte order)
    struct in_addr iph_destip;                        // IP Destination address (In network byte order)
};

/* ICMP Header */
struct icmpheader {
    unsigned char icmp_type;        // ICMP message type
    unsigned char icmp_code;        // Error code
    unsigned short int icmp_chksum; // Checksum for ICMP Header and data
    unsigned short int icmp_id;     // Used in echo request/reply to identify request
    unsigned short int icmp_seq;    // Identifies the sequence of echo messages,
                                    // if more than one is sent.
};

#define ICMP_ECHO_REPLY     0
#define ICMP_ECHO_REQUEST   8
#define ICMP_TIME_EXCEEDED  11
#define MAX_HOPS            30
#define MAX_RETRY           3
#define PACKET_LEN          1500

void traceroute(char* dest) {
    // raw sockets require root priviliges: no change necessary
    if (getuid() != 0) {
        perror("requires root privilige");
        exit(-1);
    }

    // open socket: no change necessary
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(-1);
    }

    // dns resolve and get ip for destination: no change necessary
    sockaddr_in addr;
    memset(&addr, 0, sizeof(sockaddr_in));
    addr.sin_family = AF_INET;
    hostent* getip = gethostbyname(dest);
    if (getip == NULL) {
        perror("failed gethostbyname");
        exit(-1);
    }
    memcpy((char*)(&addr.sin_addr), getip->h_addr, getip->h_length);

    printf("traceroute to %s (%s), %d hops max, %ld bytes packets\n", dest, inet_ntoa(addr.sin_addr), MAX_HOPS, sizeof(ipheader) + sizeof(icmpheader));
    
    char send_buf[PACKET_LEN], recv_buf[PACKET_LEN];
    /** TODO: 1
     * Prepare packet
     * a. outgoing packets only contain the icmpheader with type = ICMP_ECHO_REQUEST, code = 0
     * b. ID in the icmpheader should be set to current process id to identify received ICMP packets
     * c. checksum can be set to 0 for this test
     * d. write/copy the header to the send_buf  
     * 
     * HINT:
     * - icmpheader* icmp = (icmpheader*)send_buf;
     * - set header fields with required values: icmp->field = value;
     * */

    // DOING START 1
    // create icmp object
    // I moved this to inside the for loop
    

    // DOING END 1

    
    for (int ttl = 1; ttl <= MAX_HOPS; ) {
        printf("%2d ", ttl);
        /** TODO: 2
         * set the seq in icmpheader to ttl
         * 
         * HINT:
         * similar to TODO 1 HINT, just set the seq
         */

        // DOING START 2
        struct icmpheader* icmp = (struct icmpheader*)send_buf;

        // initialize my packet with the values in TODO 1
        icmp->icmp_type = ICMP_ECHO_REQUEST;
        icmp->icmp_code = 0;
        icmp->icmp_chksum = 0;
        // sets the id to my process' pid
        icmp->icmp_id = getpid();

        // updates sequence to current time to live
        icmp->icmp_seq = ttl;
        // updates the send_buf with the icmp
        memcpy(send_buf, icmp, sizeof(struct icmpheader));

        // DOING END 2
       

        // set ttl to outgoing packets: no need to change
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) < 0) {
            perror("setsockopt failed");
            exit(-1);
        }

        int retry = 0;
        while (1) {
            /** TODO: 3
             * send packet using sendto(...)
             * 
             * HINT:
             * - check man page of sendto(...)
             * - ensure we send one icmpheader in the packet
             * 
             */

            // DOING START 3
            socklen_t addr_len = sizeof(addr);

            // this sends the a single icmpheader stored in send_buf the address in addr
            if (sendto(sockfd, &send_buf, sizeof(struct icmpheader), 0,  (struct sockaddr*)&addr, addr_len) == -1) {
                // Error occurred
                perror("sendto");
                close(sockfd);
                exit(1);
            }
            // DOING END 3
           
           
            // wait to check if there is data available to receive; need to retry if timeout: no need to change
                 
            // DOING START 
            // The above comment is a lie, there is an issue with the starter code, this is my attempt to fix it
            // I'm initializing these variables that are used below
            timeval tv;
            fd_set rfd;
            // DOING END

            tv.tv_sec = 1;
            tv.tv_usec = 0;
            FD_ZERO(&rfd);
            FD_SET(sockfd, &rfd);
            int ret = select(sockfd + 1, &rfd, NULL, NULL, &tv);

            /** TOOD: 4
             * Check if data available to read or timeout
             * a. if ret == 0: timeout --> retry upto MAX_RETRY
             * b. if ret > 0: data available, use recvfrom(...) to read data to recv_buf and process --> see TODO 5 below
             */
            if (ret == 0) {
                // TODO 4.a

                // DOING START 4a

                // increments retry
                retry++;
                // prints the * but TODO 6 will add the new line character
                printf("*");

                // The pseudocode says to resend the message but it's unclear whether I am actually
                // resending the message here or just starting the while loop again.
                // I'm taking it that I should just exit the if else statement and let TODO 6 take care of resending

                // DOING END 4a

            }
            else if (ret > 0) {
                // TODO 4.b
                /** HINT: 
                 * a. check man page of recvfrom, function returns bytes received
                 * b. ensure data is received in recv_buf
                 */

                // DOING START 4b
                
                // This uses recvfrom the put the received information into the recv_buf
                // how many bytes received are stored in this variable
                int bytes_received = recvfrom(sockfd, recv_buf, PACKET_LEN, 0, NULL, 0);

                // int bytes_received = recvfrom(sockfd, recv_buf, PACKET_LEN, 0, (struct sockaddr*)&addr, &addr_len);

                // exits if there was an error with recvfrom
                if (bytes_received == -1) {
                    perror("recvfrom");
                    exit(1);
                }
                // DOING END 4b
                
                /** TODO: 5
                 * handle received packets based on received bytes
                 * a. if (i) two pairs of ipheader and icmpheader received, (ii) type is TIME_EXCEEDED, (iii) sequence is the same as ttl, and (iv) id is same as pid
                 *      --> print router ip and increment ttl to move on to processing next hop
                 *      NOTE: first pair contains the ipheader and icmpheader created by the router; second pair would contain the original ipheader and icmpheader sent by us
                 *  HINT:
                 *    - check if bytes returned by recvfrom is at least 2 * (sizeof(ipheader) + sizeof(icmpheader))
                 *    - if yes, use the icmpheader from the first pair to detect if the type is ICMP_TYPE_EXCEEDED
                 *    - use the icmpheader from the second pair to match (i) seq == ttl, and (ii) id = pid
                 * 
                 * b. else if (i) type is ECHO_REPLY, and (ii) id is same as pid --> reached destination. Print ip and exit.
                 * HINT:
                 *    - should return only one icmpheader
                 *    - match the type to ICMP_ECHO_REPLY and id to pid
                 * c. otherwise ignore packet
                 * 
                 */
               
                // ----------------

                // DOING START 5
                if (bytes_received >= 2 * (sizeof(struct ipheader) + sizeof(struct icmpheader))) {
                   
                    // This gets the first set of ip and icmp headers from recv_buf
                    struct ipheader* iphdr_router = (struct ipheader*)recv_buf;
                    struct icmpheader* icmphdr_router = (struct icmpheader*)(recv_buf + sizeof(struct ipheader));

                    // This gets the second set of ip and icmp headers from recv_buf
                    struct ipheader* iphdr_original = (struct ipheader*)(recv_buf + sizeof(struct ipheader) + sizeof(struct icmpheader));
                    struct icmpheader* icmphdr_original = (struct icmpheader*)(recv_buf + sizeof(struct ipheader) + sizeof(struct icmpheader) + sizeof(struct ipheader));
                    // I was using these to test
                    // printf("icmphdr_original->icmp_type: %d\n", icmphdr_original->icmp_type);
                    // printf("icmphdr_original->icmp_seq: %d\n", icmphdr_original->icmp_seq);
                    // printf("icmphdr_original->icmp_id: %d\n",  icmphdr_original->icmp_id);
                    // printf("my pid: %d\n", getpid());

                    // printf("icmphdr_router->icmp_type: %d\n", icmphdr_router->icmp_type);
                    // printf("icmphdr_router->icmp_seq: %d\n", icmphdr_router->icmp_seq);
                    // printf("icmphdr_router->icmp_id: %d\n",  icmphdr_router->icmp_id);

                    // printf("icmphdr_router->icmp_id: %d\n",  icmphdr_router->icmp_id);



                    

                    if (icmphdr_router->icmp_type == ICMP_TIME_EXCEEDED &&
                        icmphdr_original->icmp_seq == ttl &&
                        icmphdr_original->icmp_id == getpid()) {
                        
                        // Print router IP and increment ttl
                        // char router_ip[INET_ADDRSTRLEN];
                        // inet_ntop(AF_INET, &(addr.sin_addr), router_ip, INET_ADDRSTRLEN);
                        // 
                        printf("%s ", inet_ntoa(iphdr_router->iph_sourceip));
                        printf(" (%s) ", inet_ntoa(iphdr_router->iph_sourceip));
                        printf("%ld ms", tv.tv_usec/1000);
                        iphdr_original->iph_ttl++;
                        retry = MAX_RETRY;
                    }
                    else {

                        // Ignore packet
                    }
                }
                else if (bytes_received >= sizeof(struct icmpheader)) {
                    struct ipheader* iphdr_router = (struct ipheader*)recv_buf;
                    struct icmpheader* icmphdr = (struct icmpheader*)recv_buf + sizeof(struct ipheader);

                    // I was using these for testing
                    // printf("icmphdr->icmp_type: %d\n", icmphdr->icmp_type);
                    // printf("icmphdr->icmp_seq: %d\n", icmphdr->icmp_seq);
                    // printf("icmphdr->icmp_id: %d\n",  icmphdr->icmp_id);
                    // printf("my pid: %d\n", getpid());
                    // char destination_ip1[INET_ADDRSTRLEN];
                    // inet_ntop(AF_INET, &(addr.sin_addr), destination_ip1, INET_ADDRSTRLEN);
                    // printf("%s ", destination_ip1);
                    // printf(" (%s) ", destination_ip1);
                    // printf("%ld ms \n", tv.tv_usec/1000);

                    

                    if (icmphdr->icmp_type == ICMP_ECHO_REPLY) {
                        // should call if reached destination ip

                        char destination_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(addr.sin_addr), destination_ip, INET_ADDRSTRLEN);
                        printf("%s ", destination_ip);
                        printf(" (%s) ", destination_ip);
                        printf("%ld ms \n", tv.tv_usec/1000);
                        exit(0);
                    }
                }
                else {
                    // Ignore packet
                }
                // DOING END 5
            }
            else {
                perror("select failed");
                exit(-1);
            }
            fflush(stdout);

            /** TODO: 6
             * Check if timed out for MAX_RETRY times; increment ttl to move on to processing next hop
             */

            // DOING START 6
            // if retries maxed out
            if(retry == MAX_RETRY){
                // increments ttl
                ttl++;
                // prints end line character for *'s
                printf("\n");
                // breaks the infite loop
                break;
            }
            // DOING END 6
        }
    }
    close(sockfd);
}

int main(int argc, char** argv) {

    if (argc < 2) {
        printf("Usage: traceroute <destination hostname>\n");
        exit(-1);
    }
    
    char* dest = argv[1];
    traceroute(dest);

    return 0;
}