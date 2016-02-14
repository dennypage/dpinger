Example scripts for creating RRD graphs with dpinger

<br>

Files and Usage:

    dpinger_rrd_create <name>

Create the rrd initial file.

    dpinger_rrd_update <name> <target> <additional dpinger options>

Daemon updater script. Runs dpinger and feeds the rrd file.

    dpinger_rrd_gencgi <name>

Generate a cgi script that displays graphs.

    dpinger_rrd_graph <name>

Generate png files for use with static html

    sample.html

Sample static html to display graphs.
