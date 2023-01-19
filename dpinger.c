
//
// Copyright (c) 2015-2023, Denny Page
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


// Silly that this is required for accept4 on Linux
#define _GNU_SOURCE


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>

#include <netdb.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <syslog.h>


// Who we are
static const char *             progname;

// Process ID file
static unsigned int             foreground = 0;
static const char *             pidfile_name = NULL;

// Flags
static unsigned int             flag_rewind = 0;
static unsigned int             flag_syslog = 0;
static unsigned int             flag_priority = 0;

// String representation of target
#define ADDR_STR_MAX            (INET6_ADDRSTRLEN + IF_NAMESIZE + 1)
static char                     dest_str[ADDR_STR_MAX];

// Time period over which we are averaging results in ms
static unsigned long            time_period_msec = 60000;

// Interval between sends in ms
static unsigned long            send_interval_msec = 500;

// Interval before a sequence is initially treated as lost
// Input from command line in ms and used in us
static unsigned long            loss_interval_msec = 0;
static unsigned long            loss_interval_usec = 0;

// Interval between reports in ms
static unsigned long            report_interval_msec = 1000;

// Interval between alert checks in ms
static unsigned long            alert_interval_msec = 1000;

// Threshold for triggering alarms based on latency
// Input from command line in ms and used in us
static unsigned long            latency_alarm_threshold_msec = 0;
static unsigned long            latency_alarm_threshold_usec = 0;

// Threshold for triggering alarms based on loss percentage
static unsigned long            loss_alarm_threshold_percent = 0;

// Command to invoke for alerts
static char *                   alert_cmd = NULL;
static size_t                   alert_cmd_offset;

// Interval before an alarm is cleared (hold time)
static unsigned long            alarm_hold_msec = 0;
#define DEFAULT_HOLD_PERIODS    10

// Report file
static const char *             report_name = NULL;
static int                      report_fd;

// Unix socket
static const char *             usocket_name = NULL;
static int                      usocket_fd;

static char                     identifier[64] = "\0";

// Length of maximum output (dest_str alarm_flag average_latency_usec latency_deviation average_loss_percent)
#define OUTPUT_MAX              (sizeof(identifier) + sizeof(dest_str) + sizeof(" 1 999999999999 999999999999 100\0"))


// Main ping status array
typedef struct
{
    enum
    {
        PACKET_STATUS_EMPTY     = 0,
        PACKET_STATUS_SENT      = 1,
        PACKET_STATUS_RECEIVED  = 2
    } status;

    struct timespec             time_sent;
    unsigned long               latency_usec;
} ping_entry_t;

static ping_entry_t *           array;
static unsigned int             array_size;
static unsigned int             next_slot = 0;


// Sockets used to send and receive
static int                      send_sock;
static int                      recv_sock;

// IPv4 / IPv6 parameters
static uint16_t                 af_family = AF_INET;                    // IPv6: AF_INET6
static uint8_t                  echo_request_type = ICMP_ECHO;          // IPv6: ICMP6_ECHO_REQUEST
static uint8_t                  echo_reply_type = ICMP_ECHOREPLY;       // IPv6: ICMP6_ECHO_REPLY
static int                      ip_proto = IPPROTO_ICMP;                // IPv6: IPPROTO_ICMPV6

// Destination address
static struct sockaddr_storage  dest_addr;
static socklen_t                dest_addr_len;

// Source (bind) address
static struct sockaddr_storage  bind_addr;
static socklen_t                bind_addr_len = 0;

// ICMP echo request/reply header
//
// The physical layout of the ICMP is the same between IPv4 and IPv6 so we define our
// own type for convenience
typedef struct
{
    uint8_t                     type;
    uint8_t                     code;
    uint16_t                    cksum;
    uint16_t                    id;
    uint16_t                    sequence;
} icmphdr_t;

// Echo request/reply packet buffers
#define IPV4_ICMP_DATA_MAX      (IP_MAXPACKET - sizeof(struct ip) - sizeof(icmphdr_t))
#define IPV6_ICMP_DATA_MAX      (IP_MAXPACKET - sizeof(icmphdr_t))
#define PACKET_BUFLEN           (IP_MAXPACKET + 256)

static unsigned long            echo_data_len = 0;
static unsigned int             echo_request_len = sizeof(icmphdr_t);
static unsigned int             echo_reply_len = IP_MAXPACKET;
static icmphdr_t *              echo_request;
static void *                   echo_reply;

// Echo id and Sequence information
static uint16_t                 echo_id;
static uint16_t                 next_sequence = 0;
static uint16_t                 sequence_limit;

// Receive thread ready
static unsigned int             recv_ready = 0;


//
// Log for abnormal events
//
__attribute__ ((format (printf, 1, 2)))
static void
logger(
    const char *                format,
    ...)
{
    va_list                     args;

    va_start(args, format);
    if (flag_syslog)
    {
        vsyslog(LOG_WARNING, format, args);
    }
    else
    {
        vfprintf(stderr, format, args);
    }
    va_end(args);
}


//
// Termination handler
//
__attribute__ ((noreturn))
static void
term_handler(
    int                         signum)
{
    // NB: This function may be simultaneously invoked by multiple threads
    if (usocket_name)
    {
        (void) unlink(usocket_name);
    }
    if (pidfile_name)
    {
        (void) unlink(pidfile_name);
    }
    logger("exiting on signal %d\n", signum);
    exit(0);
}


//
// Compute checksum for ICMP
//
static uint16_t
cksum(
    const uint16_t *            p,
    int                         len)
{
    uint32_t                    sum = 0;

    while (len > 1)
    {
        sum += *p++;
        len -= sizeof(*p);
    }

    if (len == 1)
    {
        sum += (uint16_t) *((const uint8_t *) p);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t) ~sum;
}


//
// sqrt function for standard deviation
//
static unsigned long
llsqrt(
    unsigned long long          x)
{
    unsigned long long          prev;
    unsigned long long          s;

    s = x;
    if (s)
    {
        prev = ~((unsigned long long) 1 << 63);

        while (s < prev)
        {
            prev = s;
            s = (s + (x / s)) / 2;
        }
    }

    return (unsigned long) s;
}


//
// Compute delta between old time and new time in microseconds
//
static unsigned long
ts_elapsed_usec(
    const struct timespec *     old,
    const struct timespec *     new)
{
    long                        r_usec;

    // Note that we are using monotonic clock and time cannot run backwards
    if (new->tv_nsec >= old->tv_nsec)
    {
        r_usec = (new->tv_sec - old->tv_sec) * 1000000 + (new->tv_nsec - old->tv_nsec) / 1000;
    }
    else
    {
        r_usec = (new->tv_sec - old->tv_sec - 1) * 1000000 + (1000000000 + new->tv_nsec - old->tv_nsec) / 1000;
    }

    return (unsigned long) r_usec;
}


//
// Send thread
//
__attribute__ ((noreturn))
static void *
send_thread(
    __attribute__ ((unused))
    void *                      arg)
{
    struct timespec             sleeptime;
    ssize_t                     len;
    int                         r;

    // Set up our echo request packet
    memset(echo_request, 0, echo_request_len);
    echo_request->type = echo_request_type;
    echo_request->code = 0;
    echo_request->id = echo_id;

    // Give the recv thread a moment to initialize
    sleeptime.tv_sec = 0;
    sleeptime.tv_nsec = 10000; // 10us
    do {
        r = nanosleep(&sleeptime, NULL);
        if (r == -1)
        {
            logger("nanosleep error in send thread waiting for recv thread: %d\n", errno);
        }
    } while (recv_ready == 0);

    // Set up the timespec for nanosleep
    sleeptime.tv_sec = send_interval_msec / 1000;
    sleeptime.tv_nsec = (send_interval_msec % 1000) * 1000000;

    while (1)
    {
        // Set sequence number and checksum
        echo_request->sequence = htons(next_sequence);
        echo_request->cksum = 0;
        echo_request->cksum = cksum((uint16_t *) echo_request, sizeof(icmphdr_t));

        array[next_slot].status = PACKET_STATUS_EMPTY;
        sched_yield();

        clock_gettime(CLOCK_MONOTONIC, &array[next_slot].time_sent);
        array[next_slot].status = PACKET_STATUS_SENT;
        len = sendto(send_sock, echo_request, echo_request_len, 0, (struct sockaddr *) &dest_addr, dest_addr_len);
        if (len == -1)
        {
            logger("%s%s: sendto error: %d\n", identifier, dest_str, errno);
        }

        next_slot = (next_slot + 1) % array_size;
        next_sequence = (next_sequence + 1) % sequence_limit;

        r = nanosleep(&sleeptime, NULL);
        if (r == -1)
        {
            logger("nanosleep error in send thread: %d\n", errno);
        }
    }
}


//
// Receive thread
//
__attribute__ ((noreturn))
static void *
recv_thread(
    __attribute__ ((unused))
    void *                      arg)
{
    struct sockaddr_storage     src_addr;
    socklen_t                   src_addr_len;
    ssize_t                     len;
    icmphdr_t *                 icmp;
    struct timespec             now;
    unsigned int                array_slot;

    // Thread startup complete
    recv_ready = 1;

    while (1)
    {
        src_addr_len = sizeof(src_addr);
        len = recvfrom(recv_sock, echo_reply, echo_reply_len, 0, (struct sockaddr *) &src_addr, &src_addr_len);
        if (len == -1)
        {
            logger("%s%s: recvfrom error: %d\n", identifier, dest_str, errno);
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);

        if (af_family == AF_INET)
        {
            struct ip *         ip;
            size_t              ip_len;

            // With IPv4, we get the entire IP packet
            if (len < (ssize_t) sizeof(struct ip))
            {
                logger("%s%s: received packet too small for IP header\n", identifier, dest_str);
                continue;
            }
            ip = echo_reply;
            ip_len = (size_t) ip->ip_hl << 2;

            icmp = (void *) ((char *) ip + ip_len);
            len -= ip_len;
        }
        else
        {
            // With IPv6, we just get the ICMP payload
            icmp = echo_reply;
        }

        // This should never happen
        if (len < (ssize_t) sizeof(icmphdr_t))
        {
            logger("%s%s: received packet too small for ICMP header\n", identifier, dest_str);
            continue;
        }

        // If it's not an echo reply for us, skip the packet
        if (icmp->type != echo_reply_type || icmp->id != echo_id)
        {
            continue;
        }

        array_slot = ntohs(icmp->sequence) % array_size;
        if (array[array_slot].status == PACKET_STATUS_RECEIVED)
        {
            logger("%s%s: duplicate echo reply received\n", identifier, dest_str);
            continue;
        }

        array[array_slot].latency_usec = ts_elapsed_usec(&array[array_slot].time_sent, &now);
        array[array_slot].status = PACKET_STATUS_RECEIVED;
    }
}


//
// Generate a report
//
static void
report(
    unsigned long               *average_latency_usec,
    unsigned long               *latency_deviation,
    unsigned long               *average_loss_percent)
{
    struct timespec             now;
    unsigned long               packets_received = 0;
    unsigned long               packets_lost = 0;
    unsigned long               latency_usec = 0;
    unsigned long               total_latency_usec = 0;
    unsigned long long          total_latency_usec2 = 0;
    unsigned int                slot;
    unsigned int                i;

    clock_gettime(CLOCK_MONOTONIC, &now);

    slot = next_slot;
    for (i = 0; i < array_size; i++)
    {
        if (array[slot].status == PACKET_STATUS_RECEIVED)
        {
            packets_received++;
            latency_usec = array[slot].latency_usec;
            total_latency_usec += latency_usec;
            total_latency_usec2 += (unsigned long long) latency_usec * latency_usec;
        }
        else if (array[slot].status == PACKET_STATUS_SENT &&
                 ts_elapsed_usec(&array[slot].time_sent, &now) > loss_interval_usec)
        {
            packets_lost++;
        }

        slot = (slot + 1) % array_size;
    }

    if (packets_received)
    {
        unsigned long           avg = total_latency_usec / packets_received;
        unsigned long long      avg2 = total_latency_usec2 / packets_received;

        // stddev = sqrt((sum(rtt^2) / packets) - (sum(rtt) / packets)^2)
        *average_latency_usec = avg;
        *latency_deviation = llsqrt(avg2 - ((unsigned long long) avg * avg));
    }
    else
    {
        *average_latency_usec = 0;
        *latency_deviation = 0;
    }

    if (packets_lost)
    {
        *average_loss_percent = packets_lost * 100 / (packets_received + packets_lost);
    }
    else
    {
        *average_loss_percent = 0;
    }
}


//
// Report thread
//
__attribute__ ((noreturn))
static void *
report_thread(
    __attribute__ ((unused))
    void *                      arg)
{
    char                        buf[OUTPUT_MAX];
    struct timespec             sleeptime;
    unsigned long               average_latency_usec;
    unsigned long               latency_deviation;
    unsigned long               average_loss_percent;
    ssize_t                     len;
    ssize_t                     rs;
    int                         r;

    // Set up the timespec for nanosleep
    sleeptime.tv_sec = report_interval_msec / 1000;
    sleeptime.tv_nsec = (report_interval_msec % 1000) * 1000000;

    while (1)
    {
        r = nanosleep(&sleeptime, NULL);
        if (r == -1)
        {
            logger("nanosleep error in report thread: %d\n", errno);
        }

        report(&average_latency_usec, &latency_deviation, &average_loss_percent);

        len = snprintf(buf, sizeof(buf), "%s%lu %lu %lu\n", identifier, average_latency_usec, latency_deviation, average_loss_percent);
        if (len < 0 || (size_t) len > sizeof(buf))
        {
            logger("error formatting output in report thread\n");
        }

        rs = write(report_fd, buf, (size_t) len);
        if (rs == -1)
        {
            logger("write error in report thread: %d\n", errno);
        }
        else if (rs != len)
        {
            logger("short write in report thread: %zd/%zd\n", rs, len);
        }

        if (flag_rewind)
        {
            (void) ftruncate(report_fd, len);
            (void) lseek(report_fd, SEEK_SET, 0);
        }
    }
}


//
// Alert thread
//
__attribute__ ((noreturn))
static void *
alert_thread(
    __attribute__ ((unused))
    void *                      arg)
{
    struct timespec             sleeptime;
    unsigned long               average_latency_usec;
    unsigned long               latency_deviation;
    unsigned long               average_loss_percent;
    unsigned int                alarm_hold_periods;
    unsigned int                latency_alarm_decay = 0;
    unsigned int                loss_alarm_decay = 0;
    unsigned int                alert = 0;
    unsigned int                alarm_on;
    int                         r;

    // Set up the timespec for nanosleep
    sleeptime.tv_sec = alert_interval_msec / 1000;
    sleeptime.tv_nsec = (alert_interval_msec % 1000) * 1000000;

    // Set number of alarm hold periods
    alarm_hold_periods = (alarm_hold_msec + alert_interval_msec - 1) / alert_interval_msec;

    while (1)
    {
        r = nanosleep(&sleeptime, NULL);
        if (r == -1)
        {
            logger("nanosleep error in alert thread: %d\n", errno);
        }

        report(&average_latency_usec, &latency_deviation, &average_loss_percent);

        if (latency_alarm_threshold_usec)
        {
            if (average_latency_usec > latency_alarm_threshold_usec)
            {
                if (latency_alarm_decay == 0)
                {
                    alert = 1;
                }

                latency_alarm_decay = alarm_hold_periods;
            }
            else if (latency_alarm_decay)
            {
                latency_alarm_decay--;
                if (latency_alarm_decay == 0)
                {
                    alert = 1;
                }
            }
        }

        if (loss_alarm_threshold_percent)
        {
            if (average_loss_percent > loss_alarm_threshold_percent)
            {
                if (loss_alarm_decay == 0)
                {
                    alert = 1;
                }

                loss_alarm_decay = alarm_hold_periods;
            }
            else if (loss_alarm_decay)
            {
                loss_alarm_decay--;
                if (loss_alarm_decay == 0)
                {
                    alert = 1;
                }
            }
        }

        if (alert)
        {
            alert = 0;

            alarm_on = latency_alarm_decay || loss_alarm_decay;
            logger("%s%s: %s latency %luus stddev %luus loss %lu%%\n", identifier, dest_str, alarm_on ? "Alarm" : "Clear", average_latency_usec, latency_deviation, average_loss_percent);

            if (alert_cmd)
            {
                r = snprintf(alert_cmd + alert_cmd_offset, OUTPUT_MAX, " %s%s %u %lu %lu %lu", identifier, dest_str, alarm_on, average_latency_usec, latency_deviation, average_loss_percent);
                if (r < 0 || (size_t) r >= OUTPUT_MAX)
                {
                    logger("error formatting command in alert thread\n");
                    continue;
                }

                // Note that system waits for the alert command to finish before returning
                r = system(alert_cmd);
                if (r == -1)
                {
                    logger("error executing command in alert thread\n");
                }
            }
        }
    }
}

//
// Unix socket thread
//
__attribute__ ((noreturn))
static void *
usocket_thread(
    __attribute__ ((unused))
    void *                      arg)
{
    char                        buf[OUTPUT_MAX];
    unsigned long               average_latency_usec;
    unsigned long               latency_deviation;
    unsigned long               average_loss_percent;
    int                         sock_fd;
    ssize_t                     len;
    ssize_t                     rs;
    int                         r;

    while (1)
    {
#if defined(DISABLE_ACCEPT4)
        // Legacy
        sock_fd = accept(usocket_fd, NULL, NULL);
        (void) fcntl(sock_fd, F_SETFL, FD_CLOEXEC);
        (void) fcntl(sock_fd, F_SETFL, fcntl(sock_fd, F_GETFL, 0) | O_NONBLOCK);
#else
        sock_fd = accept4(usocket_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
#endif

        report(&average_latency_usec, &latency_deviation, &average_loss_percent);

        len = snprintf(buf, sizeof(buf), "%s%lu %lu %lu\n", identifier, average_latency_usec, latency_deviation, average_loss_percent);
        if (len < 0 || (size_t) len > sizeof(buf))
        {
            logger("error formatting output in usocket thread\n");
        }

        rs = write(sock_fd, buf, (size_t) len);
        if (rs == -1)
        {
            logger("write error in usocket thread: %d\n", errno);
        }
        else if (rs != len)
        {
            logger("short write in usocket thread: %zd/%zd\n", rs, len);
        }

        r = close(sock_fd);
        if (r == -1)
        {
            logger("close error in usocket thread: %d\n", errno);
        }
    }
}



//
// Decode a time argument
//
static int
get_time_arg_msec(
    const char *                arg,
    unsigned long *             value)
{
    long                        t;
    char *                      suffix;

    t = strtol(arg, &suffix, 10);
    if (*suffix == 'm')
    {
        // Milliseconds
        suffix++;
    }
    else if (*suffix == 's')
    {
        // Seconds
        t *= 1000;
        suffix++;
    }

    // Invalid specification?
    if (t < 0 || *suffix != 0)
    {
        return 1;
    }

    *value = (unsigned long) t;
    return 0;
}


//
// Decode a percent argument
//
static int
get_percent_arg(
    const char *                arg,
    unsigned long *             value)
{
    long                        t;
    char *                      suffix;

    t = strtol(arg, &suffix, 10);
    if (*suffix == '%')
    {
        suffix++;
    }

    // Invalid specification?
    if (t < 0 || t > 100 || *suffix != 0)
    {
        return 1;
    }

    *value = (unsigned long) t;
    return 0;
}


//
// Decode a byte length argument
//
static int
get_length_arg(
    const char *                arg,
    unsigned long *             value)
{
    long                        t;
    char *                      suffix;

    t = strtol(arg, &suffix, 10);
    if (*suffix == 'b')
    {
        // Bytes
        suffix++;
    }
    else if (*suffix == 'k')
    {
        // Kilobytes
        t *= 1024;
        suffix++;
    }

    // Invalid specification?
    if (t < 0 || *suffix != 0)
    {
        return 1;
    }

    *value = (unsigned long) t;
    return 0;
}


//
// Output usage
//
static void
usage(void)
{
    fprintf(stderr, "Dpinger version 3.2\n\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [-f] [-R] [-S] [-P] [-B bind_addr] [-s send_interval] [-l loss_interval] [-t time_period] [-r report_interval] [-d data_length] [-o output_file] [-A alert_interval] [-D latency_alarm] [-L loss_alarm] [-H hold_interval] [-C alert_cmd] [-i identifier] [-u usocket] [-p pidfile] dest_addr\n\n", progname);
    fprintf(stderr, "  options:\n");
    fprintf(stderr, "    -f run in foreground\n");
    fprintf(stderr, "    -R rewind output file between reports\n");
    fprintf(stderr, "    -S log warnings via syslog\n");
    fprintf(stderr, "    -P priority scheduling for receive thread (requires root)\n");
    fprintf(stderr, "    -B bind (source) address\n");
    fprintf(stderr, "    -s time interval between echo requests (default 500ms)\n");
    fprintf(stderr, "    -l time interval before packets are treated as lost (default 4x send interval)\n");
    fprintf(stderr, "    -t time period over which results are averaged (default 60s)\n");
    fprintf(stderr, "    -r time interval between reports (default 1s)\n");
    fprintf(stderr, "    -d data length (default 0)\n");
    fprintf(stderr, "    -o output file for reports (default stdout)\n");
    fprintf(stderr, "    -A time interval between alerts (default 1s)\n");
    fprintf(stderr, "    -D time threshold for latency alarm (default none)\n");
    fprintf(stderr, "    -L percent threshold for loss alarm (default none)\n");
    fprintf(stderr, "    -H time interval to hold an alarm before clearing it (default 10x alert interval)\n");
    fprintf(stderr, "    -C optional command to be invoked via system() for alerts\n");
    fprintf(stderr, "    -i identifier text to include in output\n");
    fprintf(stderr, "    -u unix socket name for polling\n");
    fprintf(stderr, "    -p process id file name\n\n");
    fprintf(stderr, "  notes:\n");
    fprintf(stderr, "    IP addresses can be in either IPv4 or IPv6 format\n\n");
    fprintf(stderr, "    time values can be expressed with a suffix of 'm' (milliseconds) or 's' (seconds)\n");
    fprintf(stderr, "    if no suffix is specified, milliseconds is the default\n\n");
    fprintf(stderr, "    the output format is \"latency_avg latency_stddev loss_pct\"\n");
    fprintf(stderr, "    latency values are output in microseconds\n");
    fprintf(stderr, "    loss percentage is reported in whole numbers of 0-100\n");
    fprintf(stderr, "    resolution of loss calculation is: 100 * send_interval / (time_period - loss_interval)\n\n");
    fprintf(stderr, "    the alert_cmd is invoked as \"alert_cmd dest_addr alarm_flag latency_avg loss_avg\"\n");
    fprintf(stderr, "    alarm_flag is set to 1 if either latency or loss is in alarm state\n");
    fprintf(stderr, "    alarm_flag will return to 0 when both have have cleared alarm state\n");
    fprintf(stderr, "    alarm hold time begins when the source of the alarm retruns to normal\n\n");
}


//
// Fatal error
//
__attribute__ ((noreturn, format (printf, 1, 2)))
static void
fatal(
    const char *                format,
    ...)
{
    va_list                 args;

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    exit(EXIT_FAILURE);
}


//
// Parse command line arguments
//
static void
parse_args(
    int                         argc,
    char * const                argv[])
{
    struct addrinfo             hint;
    struct addrinfo *           addr_info;
    const char *                dest_arg;
    const char *                bind_arg = NULL;
    size_t                      len;
    int                         opt;
    int                         r;

    progname = argv[0];

    while((opt = getopt(argc, argv, "fRSPB:s:l:t:r:d:o:A:D:L:H:C:i:u:p:")) != -1)
    {
        switch (opt)
        {
        case 'f':
            foreground = 1;
            break;

        case 'R':
            flag_rewind = 1;
            break;

        case 'S':
            flag_syslog = 1;
            break;

        case 'P':
            flag_priority = 1;
            break;

        case 'B':
            bind_arg = optarg;
            break;

        case 's':
            r = get_time_arg_msec(optarg, &send_interval_msec);
            if (r || send_interval_msec == 0)
            {
                fatal("invalid send interval %s\n", optarg);
            }
            break;

        case 'l':
            r = get_time_arg_msec(optarg, &loss_interval_msec);
            if (r || loss_interval_msec == 0)
            {
                fatal("invalid loss interval %s\n", optarg);
            }
            break;

        case 't':
            r = get_time_arg_msec(optarg, &time_period_msec);
            if (r || time_period_msec == 0)
            {
                fatal("invalid averaging time period %s\n", optarg);
            }
            break;

        case 'r':
            r = get_time_arg_msec(optarg, &report_interval_msec);
            if (r)
            {
                fatal("invalid report interval %s\n", optarg);
            }
            break;

        case 'd':
            r = get_length_arg(optarg, &echo_data_len);
            if (r)
            {
                fatal("invalid data length %s\n", optarg);
            }
            break;

        case 'o':
            report_name = optarg;
            break;

        case 'A':
            r = get_time_arg_msec(optarg, &alert_interval_msec);
            if (r || alert_interval_msec == 0)
            {
                fatal("invalid alert interval %s\n", optarg);
            }
            break;

        case 'D':
            r = get_time_arg_msec(optarg, &latency_alarm_threshold_msec);
            if (r)
            {
                fatal("invalid latency alarm threshold %s\n", optarg);
            }
            latency_alarm_threshold_usec = latency_alarm_threshold_msec * 1000;
            break;

        case 'L':
            r = get_percent_arg(optarg, &loss_alarm_threshold_percent);
            if (r)
            {
                fatal("invalid loss alarm threshold %s\n", optarg);
            }
            break;

        case 'H':
            r = get_time_arg_msec(optarg, &alarm_hold_msec);
            if (r)
            {
                fatal("invalid alarm hold interval %s\n", optarg);
            }
            break;

        case 'C':
            alert_cmd_offset = strlen(optarg);
            alert_cmd = malloc(alert_cmd_offset + OUTPUT_MAX);
            if (alert_cmd == NULL)
            {
                fatal("malloc of alert command buffer failed\n");
            }
            memcpy(alert_cmd, optarg, alert_cmd_offset);
            break;

        case 'i':
            len = strlen(optarg);
            if (len >= sizeof(identifier) - 1)
            {
                fatal("identifier argument too large (max %u bytes)\n", (unsigned) sizeof(identifier) - 1);
            }
            // optarg with a space appended
            memcpy(identifier, optarg, len);
            identifier[len] = ' ';
            identifier[len + 1] = '\0';
            break;

        case 'u':
            usocket_name = optarg;
            break;

        case 'p':
            pidfile_name = optarg;
            break;

        default:
            usage();
            exit(EXIT_FAILURE);
        }
    }

    // Ensure we have the correct number of parameters
    if (argc != optind + 1)
    {
        usage();
        exit(EXIT_FAILURE);
    }
    dest_arg = argv[optind];

    // Ensure we have something to do: at least one of alarm, report, socket
    if (report_interval_msec == 0 && latency_alarm_threshold_msec == 0 && loss_alarm_threshold_percent == 0 && usocket_name == NULL)
    {
        fatal("no activity enabled\n");
    }

    // Ensure there is a minimum of one resolved slot at all times
    if (time_period_msec <= send_interval_msec * 2 + loss_interval_msec)
    {
        fatal("the time period must be greater than twice the send interval plus the loss interval\n");
    }

    // Ensure we don't have sequence space issues. This really should only be hit by
    // complete accident. Even a ratio of 16384:1 would be excessive.
    if (time_period_msec / send_interval_msec > 65536)
    {
        fatal("the ratio of time period to send interval cannot exceed 65536:1\n");
    }

    // Check destination address
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_flags = AI_NUMERICHOST;
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_RAW;

    r = getaddrinfo(dest_arg, NULL, &hint, &addr_info);
    if (r != 0)
    {
        fatal("invalid destination IP address %s\n", dest_arg);
    }

    if (addr_info->ai_family == AF_INET6)
    {
        af_family = AF_INET6;
        ip_proto = IPPROTO_ICMPV6;
        echo_request_type = ICMP6_ECHO_REQUEST;
        echo_reply_type = ICMP6_ECHO_REPLY;
    }
    else if (addr_info->ai_family != AF_INET)
    {
        fatal("invalid destination IP address %s\n", dest_arg);
    }


    dest_addr_len = addr_info->ai_addrlen;
    memcpy(&dest_addr, addr_info->ai_addr, dest_addr_len);
    freeaddrinfo(addr_info);

    // Check bind address
    if (bind_arg)
    {
        // Address family must match
        hint.ai_family = af_family;

        r = getaddrinfo(bind_arg, NULL, &hint, &addr_info);
        if (r != 0)
        {
           fatal("invalid bind IP address %s\n", bind_arg);
        }

        bind_addr_len = addr_info->ai_addrlen;
        memcpy(&bind_addr, addr_info->ai_addr, bind_addr_len);
        freeaddrinfo(addr_info);
    }

    // Check requested data length
    if (echo_data_len)
    {
        if (af_family == AF_INET)
        {
            if (echo_data_len > IPV4_ICMP_DATA_MAX)
            {
                fatal("data length too large for IPv4 - maximum is %u bytes\n", (unsigned) IPV4_ICMP_DATA_MAX);
            }
        }
        else
        {
            if (echo_data_len > IPV6_ICMP_DATA_MAX)
            {
                fatal("data length too large for IPv6 - maximum is %u bytes\n", (unsigned) IPV6_ICMP_DATA_MAX);
            }
        }

        echo_request_len += echo_data_len;
    }
}


//
// Main
//
int
main(
    int                         argc,
    char                        *argv[])
{
    char                        bind_str[ADDR_STR_MAX] = "(none)";
    char                        pidbuf[64];
    int                         pidfile_fd = -1;
    pid_t                       pid;
    pthread_t                   thread;
    struct                      sigaction act;
    int                         buflen = PACKET_BUFLEN;
    ssize_t                     len;
    ssize_t                     rs;
    int                         r;

    // Handle command line args
    parse_args(argc, argv);

    // Set up our sockets
    send_sock = socket(af_family, SOCK_RAW, ip_proto);
    if (send_sock == -1)
    {
        perror("socket");
        fatal("cannot create send socket\n");
    }
    (void) fcntl(send_sock, F_SETFL, FD_CLOEXEC);
    (void) setsockopt(send_sock, SOL_SOCKET, SO_SNDBUF, &buflen, sizeof(buflen));

    recv_sock = socket(af_family, SOCK_RAW, ip_proto);
    if (recv_sock == -1)
    {
        perror("socket");
        fatal("cannot create recv socket\n");
    }
    (void) fcntl(recv_sock, F_SETFL, FD_CLOEXEC);
    (void) setsockopt(recv_sock, SOL_SOCKET, SO_RCVBUF, &buflen, sizeof(buflen));

    // Bind our sockets to an address if requested
    if (bind_addr_len)
    {
        r = bind(send_sock, (struct sockaddr *) &bind_addr, bind_addr_len);
        if (r == -1)
        {
            perror("bind");
            fatal("cannot bind send socket\n");
        }
        r = bind(recv_sock, (struct sockaddr *) &bind_addr, bind_addr_len);
        if (r == -1)
        {
            perror("bind");
            fatal("cannot bind recv socket\n");
        }
    }

    // Drop privileges
    (void) setgid(getgid());
    (void) setuid(getuid());

    // Create pid file
    if (pidfile_name)
    {
        pidfile_fd = open(pidfile_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
        if (pidfile_fd != -1)
        {
            // Lock the pid file
            r = flock(pidfile_fd, LOCK_EX | LOCK_NB);
            if (r == -1)
            {
                perror("flock");
                fatal("error locking pid file\n");
            }
        }
        else
        {
            // Pid file already exists?
            pidfile_fd = open(pidfile_name, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
            if (pidfile_fd == -1)
            {
                perror("open");
                fatal("cannot create/open pid file %s\n", pidfile_name);
            }

            // Lock the pid file
            r = flock(pidfile_fd, LOCK_EX | LOCK_NB);
            if (r == -1)
            {
                fatal("pid file %s is in use by another process\n", pidfile_name);
            }

            // Check for existing pid
            rs = read(pidfile_fd, pidbuf, sizeof(pidbuf) - 1);
            if (rs > 0)
            {
                pidbuf[rs] = 0;

                pid = (pid_t) strtol(pidbuf, NULL, 10);
                if (pid > 0)
                {
                    // Is the pid still alive?
                    r = kill(pid, 0);
                    if (r == 0)
                    {
                        fatal("pid file %s is in use by process %u\n", pidfile_name, (unsigned int) pid);
                    }
                }
            }

            // Reset the pid file
            (void) lseek(pidfile_fd, 0, 0);
            r = ftruncate(pidfile_fd, 0);
            if (r == -1)
            {
                perror("ftruncate");
                fatal("cannot write pid file %s\n", pidfile_name);
            }
        }
    }

    // Create report file
    if (report_name)
    {
        report_fd = open(report_name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (report_fd == -1)
        {
            perror("open");
            fatal("cannot open/create report file %s\n", report_name);
        }
    }
    else
    {
        report_fd = fileno(stdout);
    }

    // Create unix socket
    if (usocket_name)
    {
        struct sockaddr_un      uaddr;

        if (strlen(usocket_name) >= sizeof(uaddr.sun_path))
        {
            fatal("socket name too large\n");
        }

        usocket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (usocket_fd == -1)
        {
            perror("socket");
            fatal("cannot create unix domain socket\n");
        }
        (void) fcntl(usocket_fd, F_SETFL, FD_CLOEXEC);
        (void) unlink(usocket_name);

        memset(&uaddr, 0, sizeof(uaddr));
        uaddr.sun_family = AF_UNIX;
        strcpy(uaddr.sun_path, usocket_name);
        r = bind(usocket_fd, (struct sockaddr *) &uaddr, sizeof(uaddr));
        if (r == -1)
        {
             perror("bind");
             fatal("cannot bind unix domain socket\n");
        }

        r = chmod(usocket_name, 0666);
        if (r == -1)
        {
             perror("fchmod");
             fatal("cannot fchmod unix domain socket\n");
        }

        r = listen(usocket_fd, 5);
        if (r == -1)
        {
             perror("listen");
             fatal("cannot listen on unix domain socket\n");
        }
    }

    // End of general errors from command line options

    // Self background
    if (foreground == 0)
    {
        pid = fork();

        if (pid == -1)
        {
            perror("fork");
            fatal("cannot background\n");
        }

        if (pid)
        {
            _exit(EXIT_SUCCESS);
        }

        (void) setsid();
    }

    // Termination handler
    memset(&act, 0, sizeof(act));
    act.sa_handler = (void (*)(int)) term_handler;
    (void) sigaction(SIGTERM, &act, NULL);
    (void) sigaction(SIGINT, &act, NULL);

    // Write pid file
    if (pidfile_fd != -1)
    {
        len = snprintf(pidbuf, sizeof(pidbuf), "%u\n", (unsigned) getpid());
        if (len < 0 || (size_t) len > sizeof(pidbuf))
        {
            fatal("error formatting pidfile\n");
        }

        rs = write(pidfile_fd, pidbuf, (size_t) len);
        if (rs == -1)
        {
            perror("write");
            fatal("error writing pidfile\n");
        }

        r = close(pidfile_fd);
        if (r == -1)
        {
            perror("close");
            fatal("error writing pidfile\n");
        }
    }

    // Create the array
    array_size = (unsigned int) (time_period_msec / send_interval_msec);
    array = calloc(array_size, sizeof(*array));
    if (array == NULL)
    {
        fatal("calloc of packet array failed\n");
    }

    // Allocate the echo request/reply packet buffers
    echo_request = (icmphdr_t *) malloc(echo_request_len);
    echo_reply = malloc(echo_reply_len);
    if (echo_request == NULL || echo_reply == NULL)
    {
        fatal("malloc of packet buffers failed\n");
    }

    // Set the default loss interval
    if (loss_interval_msec == 0)
    {
        loss_interval_msec = send_interval_msec * 4;
    }
    loss_interval_usec = loss_interval_msec * 1000;

    // Log our general parameters
    r = getnameinfo((struct sockaddr *) &dest_addr, dest_addr_len, dest_str, sizeof(dest_str), NULL, 0, NI_NUMERICHOST);
    if (r != 0)
    {
        fatal("getnameinfo of destination address failed\n");
    }

    // Default alarm hold if not explicitly set
    if (alarm_hold_msec == 0)
    {
        alarm_hold_msec = alert_interval_msec * DEFAULT_HOLD_PERIODS;
    }

    if (bind_addr_len)
    {
        r = getnameinfo((struct sockaddr *) &bind_addr, bind_addr_len, bind_str, sizeof(bind_str), NULL, 0, NI_NUMERICHOST);
        if (r != 0)
        {
            fatal("getnameinfo of bind address failed\n");
        }
    }

    logger("send_interval %lums  loss_interval %lums  time_period %lums  report_interval %lums  data_len %lu  alert_interval %lums  latency_alarm %lums  loss_alarm %lu%%  alarm_hold %lums  dest_addr %s  bind_addr %s  identifier \"%s\"\n",
           send_interval_msec, loss_interval_msec, time_period_msec, report_interval_msec, echo_data_len,
           alert_interval_msec, latency_alarm_threshold_msec, loss_alarm_threshold_percent, alarm_hold_msec,
           dest_str, bind_str, identifier);

    // Set my echo id
    echo_id = htons((uint16_t) getpid());

    // Set the limit for sequence number to ensure a multiple of array size
    sequence_limit = (uint16_t) array_size;
    while ((sequence_limit & 0x8000) == 0)
    {
        sequence_limit <<= 1;
    }

    // Create recv thread
    r = pthread_create(&thread, NULL, &recv_thread, NULL);
    if (r != 0)
    {
        perror("pthread_create");
        fatal("cannot create recv thread\n");
    }

    // Set priority on recv thread if requested
    if (flag_priority)
    {
        struct sched_param          thread_sched_param;

        r = sched_get_priority_min(SCHED_RR);
        if (r == -1)
        {
            perror("sched_get_priority_min");
            fatal("cannot determin minimum shceduling priority for SCHED_RR\n");
        }
        thread_sched_param.sched_priority = r;

        r = pthread_setschedparam(thread, SCHED_RR, &thread_sched_param);
        if (r != 0)
        {
            perror("pthread_setschedparam");
            fatal("cannot set receive thread priority\n");
        }
    }

    // Create send thread
    r = pthread_create(&thread, NULL, &send_thread, NULL);
    if (r != 0)
    {
        perror("pthread_create");
        fatal("cannot create send thread\n");
    }

    // Report thread
    if (report_interval_msec)
    {
        r = pthread_create(&thread, NULL, &report_thread, NULL);
        if (r != 0)
        {
            perror("pthread_create");
            fatal("cannot create report thread\n");
        }
    }

    // Create alert thread
    if (latency_alarm_threshold_msec || loss_alarm_threshold_percent)
    {
        r = pthread_create(&thread, NULL, &alert_thread, NULL);
        if (r != 0)
        {
            perror("pthread_create");
            fatal("cannot create alert thread\n");
        }
    }

    // Create usocket thread
    if (usocket_name)
    {
        r = pthread_create(&thread, NULL, &usocket_thread, NULL);
        if (r != 0)
        {
            perror("pthread_create");
            fatal("cannot create usocket thread\n");
        }
    }

    // Wait (forever) for last thread started
    pthread_join(thread, NULL);

    // notreached
    return 0;
}
