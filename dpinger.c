
//
// Copyright (c) 2015, Denny Page
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

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
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

// String representation of target
static char                     dest_str[INET6_ADDRSTRLEN];

// Time period over which we are averaging results in ms
static unsigned long            time_period_msec = 25000;

// Interval between sends in ms
static unsigned long            send_interval_msec = 250;

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

// Number of periods to wait to declare an alarm as cleared
#define ALARM_DECAY_PERIODS     10

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
static uint16_t                 echo_request_type = ICMP_ECHO;          // IPv6: ICMP6_ECHO_REQUEST
static uint16_t                 echo_reply_type = ICMP_ECHOREPLY;       // IPv6: ICMP6_ECHO_REPLY
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

// Echo request header for sendto
static icmphdr_t                echo_request;

// Echo id and Sequence information
static uint16_t                 echo_id;
static uint16_t                 next_sequence = 0;
static uint16_t                 sequence_limit;


//
// Termination handler
//
static void
term_handler(void)
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
    exit(0);
}


//
// Log for abnormal events
//
#ifdef __GNUC__
static void logger(const char * format, ...) __attribute__ ((format (printf, 1, 2)));
#endif

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

    return ~sum;
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

    return s;
}


//
// Compute delta between old time and new time in microseconds
//
static unsigned long
ts_elapsed_usec(
    const struct timespec *     old,
    const struct timespec *     new)
{
    unsigned long               r_usec;

    // Note that we are using monotonic clock and time cannot run backwards
    if (new->tv_nsec >= old->tv_nsec)
    {
        r_usec = (new->tv_sec - old->tv_sec) * 1000000 + (new->tv_nsec - old->tv_nsec) / 1000;
    }
    else
    {
        r_usec = (new->tv_sec - old->tv_sec - 1) * 1000000 + (1000000000 + new->tv_nsec - old->tv_nsec) / 1000;
    }

    return r_usec;
}


//
// Send thread
//
static void *
send_thread(
    void *                      arg)
{
    struct timespec             sleeptime;
    int                         r;

    // Set up our echo request packet
    echo_request.type = echo_request_type;
    echo_request.code = 0;
    echo_request.id = echo_id;

    // Set up the timespec for nanosleep
    sleeptime.tv_sec = send_interval_msec / 1000;
    sleeptime.tv_nsec = (send_interval_msec % 1000) * 1000000;

    while (1)
    {
        r = nanosleep(&sleeptime, NULL);
        if (r == -1)
        {
            logger("%s%s: nanosleep error in send thread: %d\n", identifier, dest_str, errno);
        }

        // Set sequence number and checksum
        echo_request.sequence = htons(next_sequence);
        echo_request.cksum = 0;
        echo_request.cksum = cksum((uint16_t *) &echo_request, sizeof(icmphdr_t));

        array[next_slot].status = PACKET_STATUS_EMPTY;
        sched_yield();
        clock_gettime(CLOCK_MONOTONIC, &array[next_slot].time_sent);
        array[next_slot].status = PACKET_STATUS_SENT;

        r = sendto(send_sock, &echo_request, sizeof(icmphdr_t), 0, (struct sockaddr *) &dest_addr, dest_addr_len);
        if (r == -1)
        {
            logger("%s%s: sendto error: %d\n", identifier, dest_str, errno);
        }

        next_slot = (next_slot + 1) % array_size;
        next_sequence = (next_sequence + 1) % sequence_limit;
    }

    // notreached
    return arg;
}


//
// Receive thread
//
static void *
recv_thread(
    void *                      arg)
{
    char                        packet[1024];
    unsigned int                packet_len;
    struct sockaddr_storage     src_addr;
    socklen_t                   src_addr_len;
    icmphdr_t *                 icmp;
    struct timespec             now;
    unsigned int                array_slot;

    while (1)
    {
        src_addr_len = sizeof(src_addr);
        packet_len = recvfrom(recv_sock, &packet, sizeof(packet), 0, (struct sockaddr *) &src_addr, &src_addr_len);
        if (packet_len == (unsigned int) -1)
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
            if (packet_len < sizeof(struct ip))
            {
                logger("%s%s: received packet too small for IP header\n", identifier, dest_str);
                continue;
            }
            ip = (void *) packet;
            ip_len = ip->ip_hl << 2;

            icmp = (void *) (packet + ip_len);
            packet_len -= ip_len;
        }
        else
        {
            // With IPv6, we just get the ICMP payload
            icmp = (void *) (packet);
        }

        // This should never happen
        if (packet_len < sizeof(icmphdr_t))
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

    // notreached
    return arg;
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
            total_latency_usec += array[slot].latency_usec;
            total_latency_usec2 += array[slot].latency_usec * array[slot].latency_usec;
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
        *average_latency_usec = total_latency_usec / packets_received;

        // sqrt( (sum(rtt^2) / packets) - (sum(rtt) / packets)^2)
        *latency_deviation = llsqrt((total_latency_usec2 / packets_received) - (total_latency_usec / packets_received) * (total_latency_usec / packets_received));
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
static void *
report_thread(
    void *                      arg)
{
    char                        buf[OUTPUT_MAX];
    struct timespec             sleeptime;
    unsigned long               average_latency_usec;
    unsigned long               latency_deviation;
    unsigned long               average_loss_percent;
    int                         len;
    int                         r;

    // Set up the timespec for nanosleep
    sleeptime.tv_sec = report_interval_msec / 1000;
    sleeptime.tv_nsec = (report_interval_msec % 1000) * 1000000;

    while (1)
    {
        r = nanosleep(&sleeptime, NULL);
        if (r == -1)
        {
            logger("%s%s: nanosleep error in report thread: %d\n", identifier, dest_str, errno);
        }

        report(&average_latency_usec, &latency_deviation, &average_loss_percent);

        len = snprintf(buf, sizeof(buf), "%s%lu %lu %lu\n", identifier, average_latency_usec, latency_deviation, average_loss_percent);
        if (len < 0 || (size_t) len > sizeof(buf))
        {
            logger("%s%s: error formatting output in report thread\n", identifier, dest_str);
        }

        r = write(report_fd, buf, len);
        if (r == -1)
        {
            logger("%s%s: write error in report thread: %d\n", identifier, dest_str, errno);
        }
        else if (r != len)
        {
            logger("%s%s: short write in report thread: %d/%d\n", identifier, dest_str, r, len);
        }

        if (flag_rewind)
        {
            ftruncate(report_fd, len);
            lseek(report_fd, SEEK_SET, 0);
        }
    }

    // notreached
    return arg;
}


//
// Alert thread
//
static void *
alert_thread(
    void *                      arg)
{
    struct timespec             sleeptime;
    unsigned long               average_latency_usec;
    unsigned long               latency_deviation;
    unsigned long               average_loss_percent;
    unsigned int                latency_alarm_decay = 0;
    unsigned int                loss_alarm_decay = 0;
    unsigned int                alert = 0;
    unsigned int                alarm_on;
    int                         r;

    // Set up the timespec for nanosleep
    sleeptime.tv_sec = alert_interval_msec / 1000;
    sleeptime.tv_nsec = (alert_interval_msec % 1000) * 1000000;

    while (1)
    {
        r = nanosleep(&sleeptime, NULL);
        if (r == -1)
        {
            logger("%s%s: nanosleep error in alert thread: %d\n", identifier, dest_str, errno);
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

                latency_alarm_decay = ALARM_DECAY_PERIODS;
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

                loss_alarm_decay = ALARM_DECAY_PERIODS;
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
                    logger("%s%s: error formatting command in alert thread\n", identifier, dest_str);
                    continue;
                }

                // Note that system waits for the alert command to finish before returning
                r = system(alert_cmd);
                if (r == -1)
                {
                    logger("%s%s: error executing command in alert thread\n", identifier, dest_str);
                }
            }
        }
    }

    // notreached
    return arg;
}

//
// Unix socket thread
//
static void *
usocket_thread(
    void *                      arg)
{
    char                        buf[OUTPUT_MAX];
    unsigned long               average_latency_usec;
    unsigned long               latency_deviation;
    unsigned long               average_loss_percent;
    int                         sock_fd;
    int                         len;
    int                         r;

    while (1)
    {
        sock_fd = accept(usocket_fd, NULL, NULL);
        (void) fcntl(sock_fd, F_SETFL, fcntl(sock_fd, F_GETFL, 0) | O_NONBLOCK);

        report(&average_latency_usec, &latency_deviation, &average_loss_percent);

        len = snprintf(buf, sizeof(buf), "%s%lu %lu %lu\n", identifier, average_latency_usec, latency_deviation, average_loss_percent);
        if (len < 0 || (size_t) len > sizeof(buf))
        {
            logger("%s%s: error formatting output in usocket thread\n", identifier, dest_str);
        }

        r = write(sock_fd, buf, len);
        if (r == -1)
        {
            logger("%s%s: write error in usocket thread: %d\n", identifier, dest_str, errno);
        }
        else if (r != len)
        {
            logger("%s%s: short write in usocket thread: %d/%d\n", identifier, dest_str, r, len);
        }

        r = close(sock_fd);
        if (r == -1)
        {
            logger("%s%s: close error in usocket thread: %d\n", identifier, dest_str, errno);
        }
    }

    // notreached
    return arg;
}



//
// Decode a time argument
//
static int
get_time_arg_msec(
    const char *                arg,
    unsigned long *             value)
{
    unsigned long               t;
    char *                      suffix;

    t = strtoul(arg, &suffix, 10);
    if (*suffix == 'm')
    {
        // Milliseconds
        suffix++;
    }
    else if (*suffix == 's')
    {
        // Seconds
        *value *= 1000;
        suffix++;
    }

    // Garbage in the number?
    if (*suffix != 0)
    {
        return 1;
    }

    *value = t;
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
    unsigned long               t;
    char *                      suffix;

    t = strtoul(arg, &suffix, 10);
    if (*suffix == '%')
    {
        suffix++;
    }

    // Garbage in the number?
    if (*suffix != 0 || t > 100)
    {
        return 1;
    }

    *value = t;
    return 0;
}


//
// Output usage
//
static void
usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [-f] [-R] [-S] [-B bind_addr] [-s send_interval] [-l loss_interval] [-t time_period] [-r report_interval] [-o output_file] [-A alert_interval] [-D latency_alarm] [-L loss_alarm] [-C alert_cmd] [-i identifier] [-u usocket] [-p pidfile] dest_addr\n\n", progname);
    fprintf(stderr, "  options:\n");
    fprintf(stderr, "    -f run in foreground\n");
    fprintf(stderr, "    -R rewind output file between reports\n");
    fprintf(stderr, "    -S log warnings via syslog\n");
    fprintf(stderr, "    -B bind (source) address\n");
    fprintf(stderr, "    -s time interval between echo requests (default 250ms)\n");
    fprintf(stderr, "    -l time interval before packets are treated as lost (default 2x send interval)\n");
    fprintf(stderr, "    -t time period over which results are averaged (default 25s)\n");
    fprintf(stderr, "    -r time interval between reports (default 1s)\n");
    fprintf(stderr, "    -o output file for reports (default stdout)\n");
    fprintf(stderr, "    -A time interval between alerts (default 1s)\n");
    fprintf(stderr, "    -D time threshold for latency alarm (default none)\n");
    fprintf(stderr, "    -L percent threshold for loss alarm (default none)\n");
    fprintf(stderr, "    -C optional command to be invoked via system() for alerts\n");
    fprintf(stderr, "    -i identifier text to include in output\n");
    fprintf(stderr, "    -u unix socket name for polling\n");
    fprintf(stderr, "    -p process id file name\n\n");
    fprintf(stderr, "  notes:\n");
    fprintf(stderr, "    time values can be expressed with a suffix of 'm' (milliseconds) or 's' (seconds)\n");
    fprintf(stderr, "    if no suffix is specified, milliseconds is the default\n\n");
    fprintf(stderr, "    IP addresses can be in either IPv4 or IPv6 format\n\n");
    fprintf(stderr, "    the output format is \"latency_avg latency_stddev loss_pct\"\n");
    fprintf(stderr, "    latency values are output in microseconds\n\n");
    fprintf(stderr, "    the alert_cmd is invoked as \"alert_cmd dest_addr alarm_flag latency_avg loss_avg\"\n");
    fprintf(stderr, "    alarm_flag is set to 1 if either latency or loss is in alarm state\n");
    fprintf(stderr, "    alarm_flag will return to 0 when both have have cleared alarm state\n\n");
}


//
// Fatal error
//
static void
fatal(
    const char *                format,
    ...)
{
    if (format)
    {
        va_list                 args;

        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
    }

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
    struct in_addr              addr;
    struct in6_addr             addr6;
    const char *                dest_arg;
    const char *                bind_arg = NULL;
    size_t                      len;
    int                         opt;
    int                         r;

    progname = argv[0];

    while((opt = getopt(argc, argv, "fRSB:s:l:t:r:o:A:D:L:C:i:u:p:")) != -1)
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
            if (r || latency_alarm_threshold_msec == 0)
            {
                fatal("invalid latency alarm threshold %s\n", optarg);
            }
            break;

        case 'L':
            r = get_percent_arg(optarg, &loss_alarm_threshold_percent);
            if (r || loss_alarm_threshold_percent == 0)
            {
                fatal("invalid loss alarm threshold %s\n", optarg);
            }
            break;

        case 'C':
            alert_cmd_offset = strlen(optarg);
            alert_cmd = malloc (alert_cmd_offset + OUTPUT_MAX);
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
                fatal("identifier argument too large (max %u bytes)\n", sizeof(identifier) - 1);
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
            fatal(NULL);
        }
    }

    // Ensure we have the correct number of parameters
    if (argc != optind + 1)
    {
        usage();
        fatal(NULL);
    }

    // Ensure we have something to do: at least one of alarm, report, socket
    if (report_interval_msec == 0 && latency_alarm_threshold_msec == 0 && loss_alarm_threshold_percent == 0 && usocket_name == NULL)
    {
        fatal("no activity enabled\n");
    }

    // Destination address
    dest_arg = argv[optind];

    // Ensure we have something to average over
    if (time_period_msec < send_interval_msec)
    {
        fatal("time period cannot be less than send interval\n");
    }

    // Ensure we don't have sequence space issues. This really should only be hit by
    // complete accident. Even a ratio of 16384:1 would be excessive.
    if (time_period_msec / send_interval_msec > 65536)
    {
        fatal("ratio of time period to send interval cannot exceed 65536:1\n");
    }

    // Check for an IPv4 address
    r = inet_pton(AF_INET, dest_arg, &addr);
    if (r)
    {
        struct sockaddr_in * dest = (struct sockaddr_in *) &dest_addr;
        dest->sin_family = AF_INET;
        dest->sin_addr = addr;
        dest_addr_len = sizeof(struct sockaddr_in);

        if (bind_arg)
        {
            r = inet_pton(AF_INET, bind_arg, &addr);
            if (r == 0)
            {
                fatal("Invalid bind IP address %s\n", bind_arg);
            }

            struct sockaddr_in * bind4 = (struct sockaddr_in *) &bind_addr;
            bind4->sin_family = AF_INET;
            bind4->sin_addr = addr;
            bind_addr_len = sizeof(struct sockaddr_in);
        }
    }
    else
    {
        // Perhaps it's an IPv6 address?
        r = inet_pton(AF_INET6, dest_arg, &addr6);
        if (r == 0)
        {
            fatal("Invalid destination IP address %s\n", dest_arg);
        }

        struct sockaddr_in6 * dest6 = (struct sockaddr_in6 *) &dest_addr;
        dest6->sin6_family = AF_INET6;
        dest6->sin6_addr = addr6;
        dest_addr_len = sizeof(struct sockaddr_in6);

        af_family = AF_INET6;
        ip_proto = IPPROTO_ICMPV6;
        echo_request_type = ICMP6_ECHO_REQUEST;
        echo_reply_type = ICMP6_ECHO_REPLY;

        if (bind_arg)
        {
            r = inet_pton(AF_INET6, bind_arg, &addr6);
            if (r == 0)
            {
                fatal("Invalid source IP address %s\n", bind_arg);
            }

            struct sockaddr_in6 * bind6 = (struct sockaddr_in6 *) &bind_addr;
            bind6->sin6_family = AF_INET6;
            bind6->sin6_addr = addr6;
            bind_addr_len = sizeof(struct sockaddr_in6);
        }
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
    char                        bind_str[INET6_ADDRSTRLEN] = "(none)";
    const void *                addr;
    const char *                p;
    int                         pidfile_fd;
    pthread_t                   thread;
    struct                      sigaction act;
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
    recv_sock = socket(af_family, SOCK_RAW, ip_proto);
    if (recv_sock == -1)
    {
        perror("socket");
        fatal("cannot create recv socket\n");
    }

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
    r = setgid(getgid());
    r = setuid(getuid());

    // Create report file
    if (report_name)
    {
        report_fd = open(report_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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

        usocket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (usocket_fd == -1)
        {
            perror("socket");
            fatal("cannot create unix domain socket\n");
        }

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

    // Create pid file
    if (pidfile_name)
    {
        pidfile_fd = open(pidfile_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (pidfile_fd == -1)
        {
            perror("open");
            fatal("cannot open/create pid file %s\n", pidfile_name);
        }
    }

    // End of general errors from command line options

    // Self background
    if (foreground == 0)
    {
        r = fork();

        if (r == -1)
        {
            perror("fork");
            fatal("cannot background\n");
        }

        if (r)
        {
            _exit(EXIT_SUCCESS);
        }

        (void) setsid();
    }

    // Termination handler
    memset(&act, 0, sizeof(act));
    act.sa_handler = (void (*)(int)) term_handler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);

    // Write pid file
    if (pidfile_name)
    {
        char                    buf[64];
        int                     len;

        len = snprintf(buf, sizeof(buf), "%u\n", (unsigned) getpid());
        if (len < 0 || (size_t) len > sizeof(buf))
        {
            fatal("error formatting pidfile\n");
        }

        r = write(pidfile_fd, buf, len);
        if (r == -1)
        {
            perror("write");
            fatal("error writing pidfile\n");
        }

        r= close(pidfile_fd);
        if (r == -1)
        {
            perror("close");
            fatal("error writing pidfile\n");
        }
    }

    // Create the array
    array_size = time_period_msec / send_interval_msec;
    array = calloc(array_size, sizeof(*array));
    if (array == NULL)
    {
        fatal("calloc of packet array failed\n");
    }

    // Set the default loss interval
    if (loss_interval_msec == 0)
    {
        loss_interval_msec = send_interval_msec * 2;
    }

    // Log our parameters
    if (af_family == AF_INET)
    {
        addr = (const void *) &((struct sockaddr_in *) &dest_addr)->sin_addr;
    }
    else
    {
        addr = (const void *) &((struct sockaddr_in6 *) &dest_addr)->sin6_addr;
    }
    p = inet_ntop(af_family, addr, dest_str, sizeof(dest_str));
    if (p == NULL)
    {
        fatal("inet_ntop of destination address failed\n");
    }

    if (bind_addr_len)
    {
        if (af_family == AF_INET)
        {
            addr = (const void *) &((struct sockaddr_in *) &bind_addr)->sin_addr;
        }
        else
        {
            addr = (const void *) &((struct sockaddr_in6 *) &bind_addr)->sin6_addr;
        }
        p = inet_ntop(af_family, addr, bind_str, sizeof(bind_str));
        if (p == NULL)
        {
            fatal("inet_ntop of bind address failed\n");
        }
    }

    // Log our general parameters
    logger("send_interval %lums  loss_interval %lums  time_period %lums  report_interval %lums  alert_interval %lums  latency_alarm %lums  loss_alarm %lu%%  dest_addr %s  bind_addr %s  identifier \"%s\"\n",
           send_interval_msec, loss_interval_msec, time_period_msec, report_interval_msec,
           alert_interval_msec, latency_alarm_threshold_msec, loss_alarm_threshold_percent,
           dest_str, bind_str, identifier);

    // Convert loss interval and alarm threshold to microseconds
    loss_interval_usec = loss_interval_msec * 1000;
    latency_alarm_threshold_usec = latency_alarm_threshold_msec * 1000;

    // Set my echo id
    echo_id = htons(getpid());

    // Set the limit for sequence number to ensure a multiple of array size
    sequence_limit = array_size;
    while ((sequence_limit & 0x8000) == 0)
    {
        sequence_limit = sequence_limit << 1;
    }

    // Create recv thread
    r = pthread_create(&thread, NULL, &recv_thread, NULL);
    if (r != 0)
    {
        perror("pthread_create");
        fatal("cannot create recv thread\n");
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
