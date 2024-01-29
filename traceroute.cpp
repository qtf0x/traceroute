/**
 * @file traceroute.cpp
 * @author Dr. Philip Romig <promig3@mines.edu>
 * @author Vincent Marias <vmarias@mines.edu>
 * @date 12/03/2023
 *
 * @brief CSCI 471 - Computer Networks I (Fall 2023)
 *        Traceroute: Utility to follow a packet's hops through a network
 */

#include <chrono>  // for timing functions
#include <iomanip> // for I/O formatting

#include <cerrno> // for errono
#include <cstdio>
#include <cstdlib> // for EXIT_FAILURE, EXIT_SUCCESS
#include <cstring> // for memset, strerror

#include <unistd.h> // for getpid

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <sys/socket.h>

#include "traceroute.h"

int main(int argc, char* argv[]) {
    std::string destIP;

    // ********************************************************************
    // * Process the command line arguments
    // ********************************************************************
    int opt = 0;
    while ((opt = getopt(argc, argv, "d:v:")) != -1) {
        switch (opt) {
        case 'd':
            destIP = optarg;
            break;
        case 'v':
            LOG_LEVEL = atoi(optarg);
            break;
        default:
            std::cout << "useage: " << argv[0]
                      << " -d [destination ip] -v [Log Level]\n";
            return EXIT_FAILURE;
        }
    }

    INFO << "Destination address read as " << destIP << ENDL;

    // *************************************************************************
    // * Create RAW socket for sending
    // *************************************************************************

    DEBUG << "Calling socket(AF_INET, SOCK_RAW, IPPROTO_RAW)" << ENDL;
    int sendFD = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (sendFD == -1) {
        FATAL << strerror(errno) << " [socket]" << ENDL;
        return EXIT_FAILURE;
    }

    // *************************************************************************
    // * Build a custom datagram in memory with initial TTL=INIT_TTL
    // *************************************************************************

    auto datagram = buildDatagram(destIP);

    // place a dotted decimal string into a address structure
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(destIP.c_str());
    INFO << "sendto called with destination address "
         << dest_addr.sin_addr.s_addr << ENDL;

    // *************************************************************************
    // * Create RAW socket for receiving ICMP messages
    // *************************************************************************

    DEBUG << "Calling socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)" << ENDL;
    int recvFD = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (recvFD == -1) {
        FATAL << strerror(errno) << " [socket]" << ENDL;
        return EXIT_FAILURE;
    }

    // *************************************************************************
    // * Repeatedly ping the next hop to trace datagram route through network
    // *************************************************************************

    std::cout << "traceroute to " << destIP << ", " << std::to_string(MAX_HOPS)
              << " hops max, " << PKT_SZ << " byte packets" << std::endl;

    bool destReached = false;
    bool addrPrinted = false;

    // buffer for receiving datagrams
    auto recv_buf = new uint8_t[RECV_BUF_SZ];
    struct sockaddr_in recv_addr;

    char respondent_ip[INET_ADDRSTRLEN];

    for (uint8_t hops = INIT_TTL; !destReached && hops <= MAX_HOPS; ++hops) {
        addrPrinted = false;
        memset(respondent_ip, 0, INET_ADDRSTRLEN);

        std::cout << ' ' << std::to_string(hops) << "  ";

        // do 3 pings like we're the real traceroute :)
        for (std::size_t i = 0; i < 3; ++i) {
            DEBUG << "Calling sendto(" << sendFD << ", " << datagram << ", "
                  << PKT_SZ << ", 0, "
                  << reinterpret_cast<struct sockaddr*>(&dest_addr) << ", "
                  << sizeof(dest_addr) << ")" << ENDL;

            // set the TTL for the next datagram
            IP_set_TTL(datagram, hops);
            // increment echo sequence number
            auto newSeqNum = ICMP_update_sequence(datagram + IP_HDR_SZ);

            auto start = std::chrono::steady_clock::now(); // start the timer

            // send the datagram into the raw socket
            if (sendto(sendFD, datagram, PKT_SZ, 0,
                       reinterpret_cast<struct sockaddr*>(&dest_addr),
                       sizeof(dest_addr)) == -1) {
                FATAL << strerror(errno) << " [sendto]" << ENDL;
                return EXIT_FAILURE;
            }

            int response = 0;
            // continuing reading from socket until we receive a valid response
            do {
                // wait until a response arrives or timeout
                response = waitForResponse(recvFD);

                if (response == -1) { // select failed
                    return EXIT_FAILURE;
                } else if (response == 1) { // we got a response
                    memset(&recv_addr, 0, sizeof(recv_addr));
                    socklen_t addr_len = sizeof(recv_addr);

                    // read the response (oooo what could it be???)
                    if (recvfrom(recvFD, recv_buf, RECV_BUF_SZ, 0,
                                 reinterpret_cast<struct sockaddr*>(&recv_addr),
                                 &addr_len) == -1) {
                        FATAL << strerror(errno) << " [recvfrom]" << ENDL;
                        return EXIT_FAILURE;
                    }
                }
            } while (response != 0 &&
                     !validateReply(recv_buf + IP_HDR_SZ, newSeqNum));

            auto end = std::chrono::steady_clock::now(); // stop the count!

            if (response == 0) { // response timed out
                std::cout << "* ";
                continue;
            }

            // check if we got an echo reply
            auto icmp_hdr =
                reinterpret_cast<const struct icmphdr*>(recv_buf + IP_HDR_SZ);

            if (icmp_hdr->type == 0) {
                destReached = true;
                INFO << "Received ICMP Echo Reply from destination" << ENDL;
            }

            // copy last IP address
            char ip_cpy[INET_ADDRSTRLEN];
            strncpy(ip_cpy, respondent_ip, INET_ADDRSTRLEN);

            // convert an address structure to a dotted decimal string.
            inet_ntop(AF_INET, &recv_addr.sin_addr, respondent_ip,
                      INET_ADDRSTRLEN);

            // reprint address if it changed
            if (!addrPrinted ||
                strncmp(ip_cpy, respondent_ip, INET_ADDRSTRLEN) != 0) {
                std::cout << respondent_ip << "  ";
                addrPrinted = true;
            }

            std::chrono::duration<double, std::milli> diff = end - start;
            std::cout << std::fixed << std::setprecision(3) << diff.count()
                      << " ms ";
        }

        std::cout << std::endl; // always attempt to flush the buffer
    }

    // *************************************************************************
    // * Time to clean up
    // *************************************************************************

    // close socket descriptors
    DEBUG << "Calling close(" << sendFD << ")" << ENDL;

    if (close(sendFD) == -1) {
        FATAL << strerror(errno) << " [close]" << ENDL;
        return EXIT_FAILURE;
    }

    DEBUG << "Calling close(" << recvFD << ")" << ENDL;

    if (close(recvFD) == -1) {
        FATAL << strerror(errno) << " [close]" << ENDL;
        return EXIT_FAILURE;
    }

    // clean up yer gotdam memry
    delete[] datagram;
    datagram = nullptr;
    delete[] recv_buf;
    recv_buf = nullptr;

    return EXIT_SUCCESS;
}

uint16_t checksum(const uint16_t* buffer, int size) {
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }

    if (size == 1) {
        sum += *(unsigned char*)buffer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

uint8_t* buildDatagram(const std::string DADDR_DOTTED) {
    TRACE << "Building custom datagam" << ENDL;

    auto datagram = new uint8_t[PKT_SZ];

    fill_in_IP_header(datagram, DADDR_DOTTED);

    fill_in_ICMP_header(datagram + IP_HDR_SZ);

    memset(datagram + IP_HDR_SZ + ICMP_HDR_SZ, 0, PAYLOAD_SZ);

    return datagram;
}

void fill_in_IP_header(uint8_t* const datagram,
                       const std::string DADDR_DOTTED) {
    TRACE << "Filling in IP header fields" << ENDL;

    // treat buffer as struct for convenience
    auto const ip_hdr = reinterpret_cast<struct iphdr*>(datagram);

    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = PKT_SZ;
    ip_hdr->id = 0; /* kernel will fill this in */
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = INIT_TTL;
    ip_hdr->protocol = 1;
    ip_hdr->check = 0; /* kernel will fill this in */
    ip_hdr->saddr = 0; /* kernel will fill this in */
    ip_hdr->daddr = inet_addr(DADDR_DOTTED.c_str());

    INFO << "Destination address set to " << ip_hdr->daddr << " in IP header"
         << ENDL;
}

void fill_in_ICMP_header(uint8_t* const datagram) {
    TRACE << "Filling in ICMP header fields" << ENDL;

    // treat buffer as struct for convenience
    auto const icmp_hdr = reinterpret_cast<struct icmphdr*>(datagram);

    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;

    // use pid for identification (lower word for id to appease Google)
    uint32_t pid = getpid();
    uint16_t lower_word = (uint16_t)(pid & 0xFFFFUL);
    uint16_t upper_word = (uint16_t)((pid >> 16) & 0xFFFFUL);
    icmp_hdr->un.echo.id = lower_word;
    icmp_hdr->un.echo.sequence = upper_word;

    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = checksum(reinterpret_cast<uint16_t*>(icmp_hdr),
                                  static_cast<int>(ICMP_HDR_SZ + PAYLOAD_SZ));

    INFO << "Checksum set to " << icmp_hdr->checksum << " in ICMP header"
         << ENDL;
}

int waitForResponse(const int SOCK_FD) {
    int selectReturned = 0;
    fd_set readFdSet;
    struct timeval timeout;

    timeout.tv_sec = TIME_TO_WAIT; // set timeout interval
    timeout.tv_usec = 0;

    // set the bit in the set corresponding to file descriptor SOCK_FD
    FD_ZERO(&readFdSet);
    FD_SET(SOCK_FD, &readFdSet);

    // poll the socket for available data
    INFO << "Waiting up to " << TIME_TO_WAIT
         << " seconds to see if data becomes avalable" << ENDL;

    if ((selectReturned =
             select(SOCK_FD + 1, &readFdSet, NULL, NULL, &timeout)) == -1) {
        FATAL << strerror(errno) << " [select]" << ENDL;
        return -1;
    }

    DEBUG << "select returned " << selectReturned << ENDL;

    // confirm that select returned because our FD is set, not because of a
    // timeout.
    if (FD_ISSET(SOCK_FD, &readFdSet)) {
        DEBUG << "Bit #" << SOCK_FD << " is set" << ENDL;
        return 1;
    }

    return 0;
}

void IP_set_TTL(uint8_t* const datagram, const uint8_t TTL) {
    // treat buffer as struct for convenience
    auto const ip_hdr = reinterpret_cast<struct iphdr*>(datagram);

    ip_hdr->ttl = TTL;

    // force kernel to re-calculate checksum
    ip_hdr->saddr = 0;
    ip_hdr->check = 0;
}

uint16_t ICMP_update_sequence(uint8_t* const datagram) {
    // treat buffer as struct for convenience
    auto const icmp_hdr = reinterpret_cast<struct icmphdr*>(datagram);

    // checksum is part of checksum (I am idiot, finding this took me 2 hours)
    icmp_hdr->checksum = 0;

    ++icmp_hdr->un.echo.sequence;
    icmp_hdr->checksum = checksum(reinterpret_cast<uint16_t*>(icmp_hdr),
                                  static_cast<int>(ICMP_HDR_SZ + PAYLOAD_SZ));

    INFO << "Echo sequence number set to " << icmp_hdr->un.echo.sequence
         << " in ICMP header" << ENDL;
    INFO << "Checksum set to " << icmp_hdr->checksum << " in ICMP header"
         << ENDL;

    return icmp_hdr->un.echo.sequence;
}

bool validateReply(const uint8_t* const REPLY, const uint16_t SEQ) {
    // treat buffer as struct for convenience
    auto icmp_hdr = reinterpret_cast<const struct icmphdr*>(REPLY);

    // if it's a TTL exceeded message, headers are nested for some reason???
    if (icmp_hdr->type == 11 && icmp_hdr->code == 0) {
        INFO << "Received TTL Exceeded datagram" << ENDL;
        icmp_hdr = reinterpret_cast<const struct icmphdr*>(REPLY + 28);
    }

    uint32_t pid = getpid();
    uint16_t lower_word = (uint16_t)(pid & 0xFFFFUL);

    return icmp_hdr->un.echo.id == lower_word &&
           icmp_hdr->un.echo.sequence == SEQ;
}
