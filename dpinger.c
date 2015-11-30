
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <syslog.h>

// Who we are
static const char *		progname;

// Process ID file
static const char *		pidfile_name = NULL;

// Flags
static unsigned int		flag_rewind = 0;
static unsigned int		flag_syslog = 0;

// Time period over which we are averaging results in ms
static unsigned long		time_period = 25000;

// Interval between sends in ms
static unsigned long		send_interval = 250;

// Interval between reports in ms
static unsigned long		report_interval = 1000;

// Interval between alarm checks in ms
static unsigned long		alert_interval = 1000;

// Interval before a sequence is initially treated as lost in us
static unsigned long		loss_interval = 0;


// Command to invoke for alerts
#define ALERT_CMD_OUTPUT_MAX	sizeof("1 1000000000000 100\0")
static char *			alert_cmd = NULL;
static size_t			alert_cmd_offset;

// Threshold for triggering alarms based on latency in us
static unsigned long		latency_alarm_threshold	= 0;

// Threshold for triggering alarms based on loss percentage
static unsigned long		loss_alarm_threshold = 0;

#define ALARM_DECAY_PERIODS	10


// Main ping status array
typedef struct
{
    enum
    {
	PACKET_STATUS_EMPTY	= 0,
	PACKET_STATUS_SENT	= 1,
	PACKET_STATUS_RECEIVED	= 2
    } status;

    struct timespec		time_sent;
    unsigned long		latency;
} ping_entry_t;

static ping_entry_t *		array;
static unsigned int		array_size;
static unsigned int		next_slot = 0;


// Sockets used to send and receive
static int			send_sock;
static int			recv_sock;

// IPv4 / IPv6 parameters
static uint16_t			af_family = AF_INET;			// IPv6: AF_INET6
static uint16_t			echo_request_type = ICMP_ECHO;		// IPv6: ICMP6_ECHO_REQUEST
static uint16_t			echo_reply_type = ICMP_ECHOREPLY;	// IPv6: ICMP6_ECHO_REPLY
static int			ip_proto = IPPROTO_ICMP;		// IPv6: IPPROTO_ICMPV6

// Destination address
static struct sockaddr_storage	dest_addr;
static socklen_t		dest_addr_len;

// Source (bind) address
static struct sockaddr_storage	bind_addr;
static socklen_t		bind_addr_len = 0;

// ICMP echo request/reply header
//
// NB: The physical layout of the ICMP is the same between IPv4 and IPv6 so we define our
//     own type for convenience
typedef struct
{
    uint8_t			type;
    uint8_t			code;
    uint16_t			cksum;
    uint16_t			id;
    uint16_t			sequence;
} icmphdr_t;

// Echo request header for sendto
static icmphdr_t		echo_request;

// Identifier and Sequence information
static uint16_t			identifier;
static uint16_t			next_sequence = 0;
static uint16_t			sequence_limit;


//
// Log for abnormal events
//

#ifdef __GNUC__
static void logger(const char * format, ...) __attribute__ ((format (printf, 1, 2)));
#endif

static void
logger(
    const char *		format,
    ...)
{
    va_list args;

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
    const uint16_t *		 p,
    int				len)
{
    uint32_t sum = 0;

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
    unsigned long long		x)
{
    unsigned long long		prev;
    unsigned long long		s;

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
ts_elapsed(
    const struct timespec *	old,
    const struct timespec *	new)
{
    unsigned long r;

    //
    // Note that we are using monotonic clock and time cannot run backwards
    //
    if (new->tv_nsec >= old->tv_nsec)
    {
	r = (new->tv_sec - old->tv_sec) * 1000000 + (new->tv_nsec - old->tv_nsec) / 1000;
    }
    else
    {
	r = (new->tv_sec - old->tv_sec - 1) * 1000000 + (1000000000 + new->tv_nsec - old->tv_nsec) / 1000;
    }

    return r;
}


//
// Send thead
//
static void *
send_thread(
    void *			arg)
{
    struct timespec		sleeptime;
    int				r;

    // Set up our echo request packet
    echo_request.type = echo_request_type;
    echo_request.code = 0;
    echo_request.id = identifier;

    // Set up the timespec for nanosleep
    sleeptime.tv_sec = send_interval / 1000;
    sleeptime.tv_nsec = (send_interval % 1000) * 1000000;

    (void) nanosleep(&sleeptime, NULL);

    while (1)
    {
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
	    logger("sendto error: %d\n", errno);
	}

	next_slot = (next_slot + 1) % array_size;
	next_sequence = (next_sequence + 1) % sequence_limit;

	r = nanosleep(&sleeptime, NULL);
	if (r == -1)
	{
	    logger("nanosleep error in send thread: %d", errno);
	}
    }

    // notreached
    return arg;
}


//
// Receive thread
//
static void *
recv_thread(
    void *			arg)
{
    char			packet[1024];
    unsigned int		packet_len;
    struct sockaddr_storage	src_addr;
    socklen_t			src_addr_len;
    icmphdr_t *			icmp;
    struct timespec		now;
    unsigned int		array_slot;

    while (1)
    {
	src_addr_len = sizeof(src_addr);
	packet_len = recvfrom(recv_sock, &packet, sizeof(packet), 0, (struct sockaddr *) &src_addr, &src_addr_len);
	if (packet_len == (unsigned int) -1)
	{
	    logger("recvfrom error: %d\n", errno);
	    continue;
	}
	clock_gettime(CLOCK_MONOTONIC, &now);

	if (af_family == AF_INET)
	{
	    struct ip *		ip;
	    size_t		ip_len;

	    // With IPv4, we get the entire IP packet
	    if (packet_len < sizeof(struct ip))
	    {
		logger("received packet too small for IP header\n");
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
	    logger("received packet too small for ICMP header\n");
	    continue;
	}

	// If it's not an echo reply for us, skip the packet
	if (icmp->type != echo_reply_type || icmp->id != identifier)
	{
	    continue;
	}

	array_slot = ntohs(icmp->sequence) % array_size;
	if (array[array_slot].status == PACKET_STATUS_RECEIVED)
	{
	    logger("duplicate echo reply received!\n");
	    continue;
	}

	array[array_slot].latency = ts_elapsed(&array[array_slot].time_sent, &now);
	array[array_slot].status = PACKET_STATUS_RECEIVED;
    }

    // notreached
    return arg;
}


//
// Report thread
//
static void *
report_thread(
    void *			arg)
{
    struct timespec		now;
    struct timespec		sleeptime;
    unsigned long		packets_received;
    unsigned long		packets_lost;
    unsigned long		total_latency;
    unsigned long long		total_latency2;
    unsigned long		average_latency;
    unsigned long		latency_deviation;
    unsigned long		average_loss;
    unsigned int		slot;
    unsigned int		i;
    int				r;

    // Set up the timespec for nanosleep
    sleeptime.tv_sec = report_interval / 1000;
    sleeptime.tv_nsec = (report_interval % 1000) * 1000000;

    while (1)
    {
	packets_received	= 0;
	packets_lost		= 0;
	total_latency		= 0;
	total_latency2		= 0;

	r = nanosleep(&sleeptime, NULL);
	if (r == -1)
	{
	    logger("nanosleep error in report thread: %d\n", errno);
	}

	clock_gettime(CLOCK_MONOTONIC, &now);

	slot = next_slot;
	for (i = 0; i < array_size; i++)
	{
	    if (array[slot].status == PACKET_STATUS_RECEIVED)
	    {
		packets_received++;
		total_latency += array[slot].latency;
		total_latency2 += array[slot].latency * array[slot].latency;
	    }
	    else if (array[slot].status == PACKET_STATUS_SENT &&
		     ts_elapsed(&array[slot].time_sent, &now) > loss_interval)
	    {
		    packets_lost++;
	    }

	    slot = (slot + 1) % array_size;
	}

	if (packets_received)
	{
	    average_latency = (double) total_latency / packets_received;

	    // sqrt( (sum(rtt^2) / packets) - (sum(rtt) / packets)^2)
	    latency_deviation = llsqrt((total_latency2 / packets_received) - (total_latency / packets_received) * (total_latency / packets_received));
	}
	else
	{
	    average_latency = 0;
	    latency_deviation = 0;
	}

	if (packets_lost)
	{
	    average_loss = packets_lost * 100 / (packets_received + packets_lost);
	}
	else
	{
	    average_loss = 0;
	}

	printf("%lu %lu %lu\n", average_latency, latency_deviation, average_loss);
	if (flag_rewind)
	{
	    ftruncate(fileno(stdout), ftell(stdout));
	    rewind(stdout);
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
    void *			arg)
{
    struct timespec		now;
    struct timespec		sleeptime;
    unsigned long		packets_received;
    unsigned long		packets_lost;
    unsigned long		total_latency;
    unsigned long		average_latency;
    unsigned long		average_loss;
    unsigned int		slot;
    unsigned int		i;
    unsigned int		latency_alarm_decay = 0;
    unsigned int		loss_alarm_decay = 0;
    unsigned int		alert = 0;
    unsigned int		alarm;
    int				r;

    // Set up the timespec for nanosleep
    sleeptime.tv_sec = alert_interval / 1000;
    sleeptime.tv_nsec = (alert_interval % 1000) * 1000000;

    while (1)
    {
	packets_received	= 0;
	packets_lost		= 0;
	total_latency		= 0;

	r = nanosleep(&sleeptime, NULL);
	if (r == -1)
	{
	    logger("nanosleep error in alert thread: %d\n", errno);
	}

	clock_gettime(CLOCK_MONOTONIC, &now);

	slot = next_slot;
	for (i = 0; i < array_size; i++)
	{
	    if (array[slot].status == PACKET_STATUS_RECEIVED)
	    {
		packets_received++;
		total_latency += array[slot].latency;
	    }
	    else if (array[slot].status == PACKET_STATUS_SENT &&
		     ts_elapsed(&array[slot].time_sent, &now) > loss_interval)
	    {
		    packets_lost++;
	    }

	    slot = (slot + 1) % array_size;
	}

	if (packets_received)
	{
	    average_latency = (double) total_latency / packets_received;
	}
	else
	{
	    average_latency = 0;
	}

	if (packets_lost)
	{
	    average_loss = packets_lost * 100 / (packets_received + packets_lost);
	}
	else
	{
	    average_loss = 0;
	}

	if (latency_alarm_threshold)
	{
	    if (average_latency > latency_alarm_threshold)
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

	if (loss_alarm_threshold)
	{
	    if (average_loss > loss_alarm_threshold)
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

	    alarm = latency_alarm_decay || loss_alarm_decay;
	    logger("%s: latency %luus loss %lus\n", alarm ? "Alarm" : "Clear", average_latency, average_loss);

	    if (alert_cmd)
	    {
		r = snprintf(alert_cmd + alert_cmd_offset, ALERT_CMD_OUTPUT_MAX, " %u %lu %lu", alarm, average_latency, average_loss);
		if (r < 0 || r >= (int) ALERT_CMD_OUTPUT_MAX)
		{
		    logger("error formatting alert command\n");
		    continue;
		}

		// NB system waits for the alert command to return
		r = system(alert_cmd);
		if (r == -1)
		{
		    logger("error executing alert command\n");
		}
	    }
	}
    }

    // notreached
    return arg;
}


//
// Decode a time argument
//
static unsigned long
get_time_arg(
    const char *		arg)
{
    unsigned long		value;
    char *			suffix;

    value = strtoul(arg, &suffix, 10);
    if (value)
    {
	if (*suffix == 'm')
	{
	    // Milliseconds
	    suffix++;
	}
	else if (*suffix == 's')
	{
	    // Seconds
	    value *= 1000;
	    suffix++;
	}

	// Garbage in the number?
	if (*suffix != 0)
	{
	    value = 0;
	}
    }
    return value;
}


//
// Decode a percent argument
//
static unsigned long
get_percent_arg(
    const char *		arg)
{
    unsigned long		value;
    char *			suffix;

    value = strtoul(arg, &suffix, 10);
    if (value)
    {
	if (*suffix == '%')
	{
	    suffix++;
	}

	// Garbage in the number?
	if (*suffix != 0 || value > 100)
	{
	    value = 0;
	}
    }
    return value;
}


//
// Output usage
//
static void
usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [-R] [-S] [-B bind_addr] [-s send_interval] [-r report_interval] [-l loss_interval] [-t time_period] [-A alert_interval] [-D latency_alarm] [-L loss_alarm] [-C alert_cmd] dest_addr\n\n", progname);
    fprintf(stderr, "  options:\n");
    fprintf(stderr, "    -R rewind output file between reports\n");
    fprintf(stderr, "    -S log warnings via syslog\n");
    fprintf(stderr, "    -B bind (source) address\n");
    fprintf(stderr, "    -s time interval between echo requests (default 250m)\n");
    fprintf(stderr, "    -r time interval between reports (default 1s)\n");
    fprintf(stderr, "    -l time interval before packets are treated as lost (default 2x send interval)\n");
    fprintf(stderr, "    -t time period over which results are averaged (default 25s)\n");
    fprintf(stderr, "    -A time interval between alerts (default 1s)\n");
    fprintf(stderr, "    -D time threshold for latency alarm (default none)\n");
    fprintf(stderr, "    -L percent threshold for loss alarm (default none)\n");
    fprintf(stderr, "    -C optional command to be invoked via system() for alerts\n\n");
    fprintf(stderr, "  notes:\n");
    fprintf(stderr, "    time values can be expressed with a suffix of 'm' (milliseconds) or 's' (seconds)\n");
    fprintf(stderr, "    if no suffix is specified, milliseconds is the default\n\n");
    fprintf(stderr, "    IP addresses can be in either IPv4 or IPv6 format\n\n");
    fprintf(stderr, "    the output format is \"latency_avg latency_stddev loss_pct\"\n");
    fprintf(stderr, "    latency values are output in microseconds\n\n");
    fprintf(stderr, "    the alert_cmd is invoked as \"alert_cmd alarm_flag latency_avg loss_avg\"\n");
    fprintf(stderr, "    alarm_flag is set to 1 if either latency or loss is in alarm state\n");
    fprintf(stderr, "    alarm_flag will return to 0 when both have have cleared alarm state\n\n");
}


//
// Fatal error
//
static void
fatal(
    const char *		format,
    ...)
{
    if (format)
    {
	va_list args;

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
    int				argc,
    char * const		argv[])
{
    struct in_addr		addr;
    struct in6_addr		addr6;
    const char *		dest_arg;
    const char *		bind_arg = NULL;
    int				opt;
    int				r;

    progname = argv[0];

    while((opt = getopt(argc, argv, "RSB:s:r:l:t:A:D:L:C:p:")) != -1)
    {
	switch (opt)
	{
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
	    send_interval = get_time_arg(optarg);
	    if (send_interval == 0)
	    {
		fatal("invalid send interval %s\n", optarg);
	    }
	    break;

	case 'r':
	    report_interval = get_time_arg(optarg);
	    if (report_interval == 0)
	    {
		fatal("invalid report interval %s\n", optarg);
	    }
	    break;

	case 'l':
	    loss_interval = get_time_arg(optarg);
	    if (loss_interval == 0)
	    {
		fatal("invalid loss interval %s\n", optarg);
	    }
	    break;

	case 't':
	    time_period = get_time_arg(optarg);
	    if (time_period == 0)
	    {
		fatal("invalid averaging time period %s\n", optarg);
	    }
	    break;

	case 'A':
	    alert_interval = get_time_arg(optarg);
	    if (alert_interval == 0)
	    {
		fatal("invalid alert interval %s\n", optarg);
	    }
	    break;

	case 'D':
	    latency_alarm_threshold = get_time_arg(optarg);
	    if (latency_alarm_threshold == 0)
	    {
		fatal("invalid latency alarm threshold %s\n", optarg);
	    }
	    break;

	case 'L':
	    loss_alarm_threshold = get_percent_arg(optarg);
	    if (loss_alarm_threshold == 0)
	    {
		fatal("invalid loss alarm threshold %s\n", optarg);
	    }
	    break;

	case 'C':
	    alert_cmd_offset = strlen(optarg);
	    alert_cmd = malloc (alert_cmd_offset + ALERT_CMD_OUTPUT_MAX);
	    if (alert_cmd == NULL)
	    {
		fatal("malloc of alert command buffer failed\n");
	    }
	    strcpy(alert_cmd, optarg);
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

    // Destination address
    dest_arg = argv[optind];

    // Ensure we have something to average over
    if (time_period < send_interval)
    {
	fatal("time period cannot be less than send interval\n");
    }

    // Ensure we don't have sequence space issues. This really should only be hit by
    // complete accident. Even a ratio of 16384:1 would be excessive.
    if (time_period / send_interval > 65536)
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

	    struct sockaddr_in * bind = (struct sockaddr_in *) &bind_addr;
	    bind->sin_family = AF_INET;
	    bind->sin_addr = addr;
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
    int				argc,
    char			*argv[])
{
    char			dest_str[INET6_ADDRSTRLEN];
    char			bind_str[INET6_ADDRSTRLEN] = "(none)";
    const void *		addr;
    const char *		p;
    int				pidfile_fd;
    FILE *			pidfile_file;
    pthread_t			thread;
    int				r;

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

    // Create pid file
    if (pidfile_name)
    {
	pidfile_fd = open(pidfile_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (pidfile_fd == -1)
	{
	    perror("open");
	    fatal("cannot open/create pid file %s\n", pidfile_name);
	}
	pidfile_file = fdopen(pidfile_fd, "w"); 
	if (pidfile_file == NULL)
	{
            perror("fdopen");
	    fatal("cannot open pid file %s\n", pidfile_name);
	}

	fprintf(pidfile_file, "%d\n", getpid());

	r = fclose(pidfile_file);
	if (r == -1)
	{
	    perror("fclose");
	    fatal("cannot write pid file %s\n", pidfile_name);
	}
    }

    // Drop privledges
    r = setgid(getgid());
    r = setuid(getuid());

    // Create the array
    array_size = time_period / send_interval;
    array = calloc(array_size, sizeof(*array));
    if (array == NULL)
    {
	fatal("calloc of packet array failed\n");
    }

    // Set the default loss interval
    if (loss_interval == 0)
    {
	loss_interval = send_interval * 2;
    }

    // Unbuffer output
    (void) setvbuf(stdout, NULL, _IOLBF, 0);

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

    // Log our parameters (sans pidfile)
    logger("send_interval %lums  report_interval %lums  loss_interval %lums  time_period %lums  alert_interval %lums  latency_alarm %lums  loss_alarm %lu%%  dest_addr %s  bind_addr %s  alert_cmd \"%s\"\n", 
	   send_interval, report_interval, loss_interval, time_period, 
	   alert_interval, latency_alarm_threshold, loss_alarm_threshold,
	   dest_str, bind_str, alert_cmd ? alert_cmd : "(none)");

    // Convert loss interval and alarm threshold to microseconds
    loss_interval *= 1000;
    latency_alarm_threshold *= 1000;

    // Set my identifier
    identifier = htons(getpid());

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

    // Create alert thread
    if (latency_alarm_threshold || loss_alarm_threshold)
    {
	r = pthread_create(&thread, NULL, &alert_thread, NULL);
	if (r != 0)
	{
	    perror("pthread_create");
	    fatal("cannot create alert thread\n");
	}
    }

    // Report thread
    report_thread(NULL);

    // notreached
    return 0;
}
