#!/bin/sh

INFLUX_URL="http://myinfluxhost:8086"
export INFLUX_USER="dpinger"
export INFLUX_PASS="myinfluxpass"

exec /usr/local/dpinger_influx_logger $INFLUX_URL dpinger `hostname` wan 8.8.8.8
