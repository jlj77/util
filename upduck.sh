#!/bin/bash
# Simple script to update the IP address that a Duck DNS domain name resolves to.
#
#####
#
#  Available environment variables*:
#    - $DUCKDNS_DOMAIN: The domain you want to update
#    - $DUCKDNS_TOKEN: The token to use to authenticate the request
#
#  *All other Duck DNS API options are optional; I may implement them later.
#
#  NOTE: command line options override environment variables.
#
#####
#
#  Error codes:
#
#  1 = invalid arguments
#  2 = failure to find wget on the system
#  3 = no domain provided, by command option or environment variable
#  4 = no token provided, by command option or...
#  5 = Duck DNS returned a 'normal' bad response (check inputs)
#  6 = Duck DNS returned an unexpected error / response
#
#####
#
# wget required; check whether it's available in the environment
if ! [ -x "$(command -v wget)" ]; then
  echo "Error: wget required, and not found (or installed?)" >&2
  exit 2
fi

# Tell wget to (succinctly) write to stdout
wgetopt="-qO -"

# Reset arguments, including getopts index
OPTIND=1
dn=""
tkn=""

while getopts "d:h?t:" flag; do
  case "$flag" in
  d)
    dn=${OPTARG}
    ;;
  t)
    tkn=${OPTARG}
    ;;
  h)
    echo "Usage: $0 [-d domain] [-t token]"
    exit 0
    ;;
  \?)
    echo "Usage: $0 [-d domain] [-t token]" >&2
    exit 1
    ;;
  esac
done

# Check that a domain has been provided
if [[ -z $dn ]]; then
  if [[ -z $DUCKDNS_DOMAIN ]]; then
    echo "Error: no domain provided. Use -d or \$DUCKDNS_DOMAIN." >&2
    exit 3
  else
    dn=$DUCKDNS_DOMAIN
  fi
fi

# Check that a token has been provided
if [[ -z $tkn ]]; then
  if [[ -z $DUCKDNS_TOKEN ]]; then
    echo "Error: no Duck DNS token provided. Use -t or \$DUCKDNS_TOKEN." >&2
    exit 4
  else
    tkn=$DUCKDNS_TOKEN
  fi
fi

resp=$(wget $wgetopt "https://www.duckdns.org/update?domains=$dn&token=$tkn")
if [ "$resp" == "OK" ]; then
  echo "Success! Domain $dn is up-to-date."
elif [ "$resp" == "KO" ]; then
  echo "Error: update failed :( Try a different domain or token." >&2
  exit 5
else
  echo "Error: DuckDNS response: $resp." >&2
  exit 6
fi
