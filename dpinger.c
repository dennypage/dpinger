
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <syslog.h>


// Flags
unsigned int flag_rewind	= 0;
unsigned int flag_syslog	= 0;

// Time period over which we are averaging results in ms
unsigned long time_period	= 10000;

// Interval between sends in ms
unsigned long send_interval	= 250;

// Interval between reports in ms
unsigned long report_interval	= 1000;

// Interval before a sequence is initially treated as lost in us
unsigned long loss_interval	= 0;


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

ping_entry_t *			array;
unsigned int			array_size;
unsigned int			next_slot = 0;


// Sockets used to send and receive
int				send_sock;
int				recv_sock;

// IPv4 / IPv6 parameters
uint16_t			af_family = AF_INET;			// IPv6: AF_INET6
uint16_t			echo_request_type = ICMP_ECHO;		// IPv6: ICMP6_ECHO_REQUEST
uint16_t			echo_reply_type = ICMP_ECHOREPLY;	// IPv6: ICMP6_ECHO_REPLY
int				ip_proto = IPPROTO_ICMP;		// IPv6: IPPROTO_ICMPV6

// Destination address
struct sockaddr_storage		dest_addr = { 0 };
socklen_t			dest_addr_len;

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
icmphdr_t			echo_request;

// Identifier and Sequence information
uint16_t			identifier;
uint16_t			next_sequence = 0;
uint16_t			sequence_limit;


//
// Log for abnormal events
//
void
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
uint16_t
cksum(
    const uint16_t *		 p,
    int len)
{
    uint32_t sum = 0;

    while (len > 1)
    {
    	sum += *p++;
	len -= sizeof(*p);
    }

    if (len == 1)
    {
        sum += (uint16_t) *((uint8_t *) p);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}


//
// sqrt function for standard deviation
//
unsigned long
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
unsigned long
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
void *
send_thread(void *arg)
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
            logger("sendto error: %n\n", errno);
        }

	next_slot = (next_slot + 1) % array_size;
	next_sequence = (next_sequence + 1) % sequence_limit;

	r = nanosleep(&sleeptime, NULL);
        if (r == -1)
        {
            logger("nanosleep error in send thread: %d", errno);
        }
    }
}


//
// Receive thread
//
void *
recv_thread(void *arg)
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
	    struct iphdr *	ip;
	    size_t		ip_len;

	    // With IPv4, we get the entire IP packet
            if (packet_len < sizeof(struct iphdr))
	    {
	        logger("received packet too small for IP header\n");
	        continue;
	    }
            ip = (struct iphdr *) packet;
            ip_len = ip->ihl << 2;

            icmp = (icmphdr_t *) (packet + ip_len);
	    packet_len -= ip_len;
	}
	else
	{
	    // With IPv6, we just get the ICMP payload
            icmp = (icmphdr_t *) (packet);
	}

	// This should never happen
	if (packet_len < sizeof(icmphdr_t))
	{
	    logger("recieved packet too small for ICMP header\n");
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
}


//
// Report thread
//
void *
report_thread(void *arg)
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
}



//
// Decode a time value
//
unsigned long
get_interval_arg(
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

	// Garbage in the number
        if (*suffix != 0)
	{
	    value = 0;
	}
    }
    return value;
}


//
// Output usage
//
void
usage(
    const char *		progname)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [-R] [-S] [-s send_interval] [-r report_interval] [-l loss_interval] [-t time_period] ip_address\n\n", progname);
    fprintf(stderr, "  options:\n");
    fprintf(stderr, "    -R rewind output file between reports\n");
    fprintf(stderr, "    -S log warnings via syslog\n");
    fprintf(stderr, "    -s interval between echo requests (default 250m)\n");
    fprintf(stderr, "    -r interval between reports (detault 1s)\n");
    fprintf(stderr, "    -l interval before packets are treated as lost (default 2x send interval)\n");
    fprintf(stderr, "    -t time period over which results are averaged (default 10s)\n\n");
    fprintf(stderr, "    time intervals/periods can be expressed with a suffix of 's' (seconds) or 'm' (millseonds)\n");
    fprintf(stderr, "    if no suffix is specificied, millseconds is the default\n\n");
    fprintf(stderr, "    ip addreess can be in either IPv4 or IPv6 format\n\n");
}


//
// Fatal error
//
void
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
// Parse command line arguents
//
void
parse_args(
    int				argc,
    char * const		argv[])
{
    struct in_addr		addr;
    struct in6_addr		addr6;
    int				opt;
    int				r;

    while((opt = getopt(argc, argv, "RSs:r:l:t:")) != -1)
    {
        switch (opt)
	{
	case 'R':
	    flag_rewind = 1;
	    break;

	case 'S':
	    flag_syslog = 1;
	    break;

	case 's':
	    send_interval = get_interval_arg(optarg);
	    if (send_interval == 0)
	    {
	        fatal("invalid send interval %s\n", optarg);
	    }
	    break;

	case 'r':
	    report_interval = get_interval_arg(optarg);
	    if (report_interval == 0)
	    {
	        fatal("invalid report interval %s\n", optarg);
	    }
	    break;

	case 'l':
	    loss_interval = get_interval_arg(optarg);
	    if (loss_interval == 0)
	    {
	        fatal("invalid loss interval %s\n", optarg);
	    }
	    break;

	case 't':
	    time_period = get_interval_arg(optarg);
	    if (time_period == 0)
	    {
	        fatal("invalid averaging time period %s\n", optarg);
	    }
	    break;

	default:
	    usage(argv[0]);
	    fatal(NULL);
	}
    }

    if (optind != argc - 1)
    {
	usage(argv[0]);
	fatal(NULL);
    }

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

    // Check for IPv4 address
    r = inet_pton(AF_INET, argv[optind], &addr);
    if (r)
    {
        struct sockaddr_in * dest = (struct sockaddr_in *) &dest_addr;
        dest->sin_family = AF_INET;
        dest->sin_addr = addr;
	dest_addr_len = sizeof(struct sockaddr_in);
    }
    else
    {
	// Perhaps it's an IPv6 address?
	r = inet_pton(AF_INET6, argv[optind], &addr6);
	if (r == 0)
	{
            fatal("Invalid destination IP address %s\n", argv[optind]);
	}

        struct sockaddr_in6 * dest6 = (struct sockaddr_in6 *) &dest_addr;
        dest6->sin6_family = AF_INET6;
        dest6->sin6_addr = addr6;
	dest_addr_len = sizeof(struct sockaddr_in6);

	af_family = AF_INET6;
	ip_proto = IPPROTO_ICMPV6;
        echo_request_type = ICMP6_ECHO_REQUEST;
        echo_reply_type = ICMP6_ECHO_REPLY;
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
    const void *		addr;
    const char *		p;
    pthread_t			thread;
    int				r;

    // Handle command line args
    parse_args(argc, argv);

    // Set up our sockets
    send_sock = socket(af_family, SOCK_RAW, ip_proto);
    if (send_sock == -1)
    {
        perror("socket");
        fatal("cannot create send socket");
    }
    recv_sock = socket(af_family, SOCK_RAW, ip_proto);
    if (recv_sock == -1)
    {
        perror("socket");
        fatal("cannot create recv socket");
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
    logger("send_interval %lums  report_interval %lums  loss_interval %lums  time_period %lums  ipaddr %s\n", 
    	   send_interval, report_interval, loss_interval, time_period, dest_str);

    // Convert loss_interval to microseconds
    loss_interval *= 1000;

    // Set my identifier
    identifier = htons(getpid());

    // Set the limit for sequence number to ensure a mutiple of array size
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
        fatal("cannot create recv thread");
    }

    // Create send thread
    r = pthread_create(&thread, NULL, &send_thread, NULL);
    if (r != 0)
    {
        perror("pthread_create");
        fatal("cannot create send thread");
    }

    // Report thread
    report_thread(NULL);

    // notreached
    return 0;
}
