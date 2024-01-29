/**
 * @file traceroute.h
 * @author Dr. Philip Romig <promig3@mines.edu>
 * @author Vincent Marias <vmarias@mines.edu>
 * @date 12/03/2023
 *
 * @brief CSCI 471 - Computer Networks I (Fall 2023)
 *        Traceroute: Utility to follow a packet's hops through a network
 */

#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <iostream> // for std::cout, std::cerr, std::endl
#include <string>   // for std::string

#include <cstddef> // for std::size_t
#include <cstdint> // for uint16_t, uint8_t

static constexpr std::size_t PKT_SZ{64}, IP_HDR_SZ{20}, ICMP_HDR_SZ{8},
    PAYLOAD_SZ{36};
static constexpr std::size_t RECV_BUF_SZ{64};
static constexpr uint8_t INIT_TTL{2}, MAX_HOPS{31};
static constexpr int TIME_TO_WAIT{5};

static int LOG_LEVEL = 0;
#define TRACE                                                                  \
    if (LOG_LEVEL > 5) {                                                       \
    std::cout << "TRACE: "
#define DEBUG                                                                  \
    if (LOG_LEVEL > 4) {                                                       \
    std::cout << "DEBUG: "
#define INFO                                                                   \
    if (LOG_LEVEL > 3) {                                                       \
    std::cout << "INFO: "
#define WARNING                                                                \
    if (LOG_LEVEL > 2) {                                                       \
    std::cout << "WARNING: "
#define ERROR                                                                  \
    if (LOG_LEVEL > 1) {                                                       \
    std::cerr << "ERROR: "
#define FATAL                                                                  \
    if (LOG_LEVEL > 0) {                                                       \
    std::cerr << "FATAL: "
#define ENDL                                                                   \
    " (" << __FILE__ << ":" << __LINE__ << ")" << std::endl;                   \
    }

/**
 * @brief Compute the Internet Checksum over an arbitrary buffer.
 * @param[in] buffer arbitrary buffer to sum over
 * @param[in] size the size of the buffer, in bytes
 *
 * @return Internet Checksum
 * @note Written with the help of ChapGPT 3.5 (for some godforsaken reason).
 */
uint16_t checksum(const uint16_t* buffer, int size);

/**
 * @brief Builds a datagram appropriate for initial traceroute send. Contains an
 * IPv4 header with TTL=INIT_TTL, an ICMP header with an echo request, and an
 * empty payload.
 *
 * @return uint8_t* byte buffer containing the complete datagram
 */
uint8_t* buildDatagram(const std::string DADDR_DOTTED);

/**
 * @brief Modifies datagram's IP header by filling in all the fields with
 * appropriate values for sending over IPv4 to provided destination address.
 * Ensures that kernel will automatically fill in the source address and
 * checksum fields.
 * @param[in,out] datagram pointer to the start of IP header in datagram
 * @param[in] DADDR_DOTTED destination address to put in IP header
 */
void fill_in_IP_header(uint8_t* const datagram, const std::string DADDR_DOTTED);

/**
 * @brief Modifies datagram's ICMP header by filling in all the fields with
 * appropriate values for an ICMP echo request.
 * @param[in,out] pointer to the start of the ICMP header in datagram
 *
 * @note Usees the running process id as echo id and 0 as initial echo sequence
 * number.
 */
void fill_in_ICMP_header(uint8_t* const datagram);

/**
 * @brief Polls provided socket descriptor for up to TIME_TO_WAIT seconds
 * without blocking.
 * @param[in] SOCK_FD open socket descriptor to poll
 *
 * @return -1 select call failed
 * @return 0 no response on SOCK_FD
 * @return 1 data is waiting to be read on SOCK_FD
 */
int waitForResponse(const int SOCK_FD);

/**
 * @brief Modifies datagram's IP header by setting ttl to value provided.
 * Ensures that kernel will automatically fill in source address and checksum
 * fields.
 * @param[in,out] datagram pointer to the start of the IP header in datagram
 * @param[in] TTL new time-to-live value for this datagram
 */
void IP_set_TTL(uint8_t* const datagram, const uint8_t TTL);

/**
 * @brief Modifies datagram's ICMP header by incrementing echo sequence number
 * and recalculating checksum.
 * @param[in,out] datagram pointer to the start of the ICMP header in datagram
 *
 * @return uint16_t new sequence number placed in ICMP header
 */
uint16_t ICMP_update_sequence(uint8_t* const datagram);

/**
 * @brief Determines if a given datagram is an ICMP reply to a request from this
 * process, sent with given sequence number.
 * @param[in] REPLY pointer to the start of the ICMP header in datagram
 * @param[in] SEQ expected sequence number
 *
 * @return true datagram is expected ICMP reply
 * @return false datagram is not the expected ICMP reply
 */
bool validateReply(const uint8_t* const REPLY, const uint16_t SEQ);

#endif // TRACEROUTE_H
