#!/bin/bash
# Simple script to update the IP address that a Duck DNS domain name resolves to.
#
#####
#
#  Available environment variables*:
#    - $DUCKDNS_DOMAIN: The domain you want to update
#    - $DUCKDNS_TOKEN: The token to use to authenticate the request
#    - $DUCKDNS_IP: (Optional) The IP address that the provided domain
#                    should resolve to — Duck DNS will detect and use
#                    the source IP otherwise
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

# Strip the script's path, for usage message
name=$(basename "$0")

# Reset arguments, including getopts index
OPTIND=1
dn=""
tkn=""
ip_a=""

while getopts "d:hi:?t:" flag; do
  case "$flag" in
  d)
    dn=${OPTARG}
    ;;
  t)
    tkn=${OPTARG}
    ;;
  i)
    ip_a=${OPTARG}
    ;;
  h)
    printf "Usage: %s [-d domain] [-t token] [-i]\n\t-i\tIP address (detected, if not specified)\n" "$name"
    exit 0
    ;;
  \?)
    echo "Usage: $name [-d domain] [-t token] [-i IP address]" >&2
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

# Check whether an IP address has been provided
if [[ -z $ip_a ]]; then
  if [[ -n $DUCKDNS_IP ]]; then
    ip_a=$DUCKDNS_IP
  fi
fi

# Include an IP address in the API call, if available
if [[ -z $ip_a ]]; then
  # shellcheck disable=SC2086
  resp=$(wget $wgetopt "https://www.duckdns.org/update?domains=$dn&token=$tkn")
else
  # shellcheck disable=SC2086
  resp=$(wget $wgetopt "https://www.duckdns.org/update?domains=$dn&token=$tkn&ip=$ip_a")
fi

# Parse the response from Duck DNS
if [ "$resp" == "OK" ] && [ -n "$ip_a" ]; then
  echo "Success! Domain $dn now resolves to $ip_a."
elif [ "$resp" == "OK" ]; then
  echo "Success! Domain $dn is up-to-date."
elif [ "$resp" == "KO" ]; then
  echo "Error: update failed :( Try a different domain or token." >&2
  exit 5
else
  echo "Error: Duck DNS response: $resp." >&2
  exit 6
fi
