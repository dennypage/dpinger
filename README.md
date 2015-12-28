# dpinger

dpinger is a daemon for continuous monitoring of latency and loss on a network connection. It is
intended for use by firewalls to monitor link health, as well as for providing information to
various monitoring systems such as Cacti, Nagios, Zabbix, etc. 

The output of dpinger can either be file or socket based, and consists of three numbers:
  
    <Average Latency in μs> <Standard Deviation in μs> <Percentage of Loss>
    
dpinger also provides for invocation of a command based upon threshold values
for Average Latency or Percentage of Loss. Arguments to the command are:

    <Target IP> <Alarm on/off> <Average Latency> <Standard Deviation> <Percentage of Loss>

In addition to command invocation, dpinger can also log alerts via syslog. 

If several instances of dpinger are being used to monitor different targets, or the same target
with different source addresses, etc., an Identifier can be added to the output to identify
which instance of dpinger is the source. This is particularly useful with syslog.

<br>

Usage examples:

    dpinger -t 300s -r 60s 192.168.0.1 >> /tmp/dpinger.out

Monitor IP address 192.168.0.1 for latency and loss. Average results over 5 minutes.
Produce a report every 60 seconds and append it to /tmp/dpinger.out.

    dpinger -r 0 -S -D 250m -L 20 -p /run/dpinger 192.168.0.1

  Monitor IP address 192.168.0.1 for latency and loss. Log alerts via syslog if latency
  exceeds 250 milliseconds or loss exceeds 20 percent. Record process id in /run/dpinger.

    dpinger -f -B 192.168.0.50 -r 10s 192.168.0.1

  Monitor IP address 192.168.0.1 for latency and loss. Use 192.168.0.50 as the address
  for sending and receiving ICMP packets. Run in the foreground and report status via
  stdout every 10 seconds.

    dpinger -R -o /tmp/gw.status fe80::1 -L 35% -C "/var/etc/alert igb1"

  Monitor IP address fe80::1 for latency and loss. Maintain a status file in
  /tmp/gw.status with the current status. If packet loss exceeds 35% invoke the following
  command:
  
        /var/etc/alert igb1 fe80::1 <alarm> <latency> <deviation> <loss>
  
  the command will be invoked with an alarm value of 1 when loss exceeds 35%, and again
  with an alarm value of 0 when loss returns to below 35%.
  
    dpinger -r 0 -s 200m -u /tmp/igb1.status -p /run/dpinger fe80::1

  Monitor IP address fe80::1 for latency and loss. Send echo requests every 200 milliseconds.
  Make current status available on demand via a Unix domain socket /tmp/igb1.status. Record
  process id in /run/dpinger.

    dpinger -S -i Comcast -s 5s -t 600s -r 0 -L 10% -p /run/dpinger 8.8.8.8

  Monitor IP address 8.8.8.8 for latency and loss. Send echo requests every five seconds and
  average results over 10 minutes. Log alerts via syslog including identifier string "Comcast"
  if average loss exceeds 10 percent. Record process id in /run/dpinger.
