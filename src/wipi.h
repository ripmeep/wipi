/*    wipi.h    */

/*
 * Author: ripmeep
 * GitHub: https://github.com/ripmeep/
 * Date  : 20/03/2023
 */

/* Library declarations for WiPi.
 * See wipi.c for source definitions.
 *
 * Requires:
 *   - libiw-dev
 */

#ifndef _WIPI_H_
#define _WIPI_H_

#define _GNU_SOURCE

/*    INCLUDES    */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <iwlib.h>

/*    MACRO DEFS    */
#define WIPI_MAX_SSID   32
#define WIPI_MAX_BSSID  32
#define WIPI_MAX_FREQ   32
#define WIPI_MAX_STATS  64

/*    TYPEDEFS    */
typedef enum
{
    WIPI_ERR_OK,
    WIPI_ERR_RANGE,
    WIPI_ERR_SOCKFD,
    WIPI_ERR_SCAN,
    WIPI_ERR_NOMON,
    WIPI_ERR_SEND
} WIPI_STATUS;

typedef struct __wipi_beacon_t
{
    struct __wipi_beacon_t* head;
    struct __wipi_beacon_t* next;

    char                    ssid[WIPI_MAX_SSID];
    char                    bssid[WIPI_MAX_BSSID];
    char                    cfreq[WIPI_MAX_FREQ];
    char                    stats[WIPI_MAX_STATS];

    double                  freq;
    float                   qual;
    int8_t                  db;
    int                     channel;

    uint8_t                 valid;
} wipi_beacon_t;

typedef struct __wipi_interface_t
{
    struct __wipi_interface_t*  head;
    struct __wipi_interface_t*  next;

    char*                       if_name;
    char*                       if_addr;
    char*                       if_mask;

    unsigned int                if_flags;
    uint8_t                     if_mon;
} wipi_interface_t;

typedef struct __wipi_scanner_t
{
    iwrange             iwr;

    wireless_scan_head  wsh;
    wireless_scan*      res;

    int                 sockets;

    char*               iface;

    WIPI_STATUS         status;
} wipi_scanner_t;

/*    STATIC DEFS    */
extern WIPI_STATUS WIPI_ERRNO;

static const char* WIPI_STRERRS[] = {
    "WIPI_ERR_OK",
    "WIPI_ERR_RANGE",
    "WIPI_ERR_SOCKFD",
    "WIPI_ERR_SCAN",
    "WIPI_ERR_NOMON",
    "WIPI_ERR_SEND"
};

/*    FUNCTION DECLS    */
#define WIPI_PERROR() fprintf(stderr, \
                              "%s#%d -> %s()\n%s (%d): %s\n", \
                              __FILE__, \
                              __LINE__, \
                              __FUNCTION__, \
                              WIPI_STRERRS[WIPI_ERRNO], \
                              WIPI_ERRNO, \
                              strerror(errno))

__attribute__((__pure__))
__wur
struct __wipi_interface_t* wipi_get_interfaces(uint32_t sa_family);

__attribute__((__pure__))
__wur
struct __wipi_interface_t* wipi_interface_get(struct __wipi_interface_t* wi,
                                              const char* __restrict__ iface);

__attribute__((__pure__))
__wur
struct __wipi_beacon_t* wipi_beacon_get(struct __wipi_beacon_t* wb,
                                        const char* __restrict__ bssid);

__wur
struct __wipi_scanner_t* wipi_scanner_init(const char* __restrict__ iface);

__wur
struct __wipi_beacon_t* wipi_scanner_scan(struct __wipi_scanner_t* ws);

uint8_t wipi_interface_monitor_mode(struct __wipi_interface_t* wi);

int wipi_mon_socket(struct __wipi_interface_t* wi);

int wipi_deauth(struct __wipi_interface_t* wi,
                const char* __restrict__ bssid,
                int packets,
                int delay);

void wipi_scanner_free(struct __wipi_scanner_t* ws);

#endif
