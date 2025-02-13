# util
Some simple scripts. For fun / personal use.

## Upduck
 A simple script to update the IP address that a Duck DNS domain name
 resolves to.

### Available environment variables*
- $DUCKDNS_DOMAIN: The domain you want to update
- $DUCKDNS_TOKEN: The token to use to authenticate the request
- $DUCKDNS_IP: (Optional) The IP address that the provided domain
                should resolve to — Duck DNS will detect and use
                the source IP otherwise

*All other [Duck DNS API](https://www.duckdns.org/spec.jsp) options
are optional; I'm aiming for feature parity in the future.

_NOTE: command line options override environment variables._

###  Error codes:
1. Invalid arguments
2. Failure to find `wget` on the system
3. No domain provided, by command option or environment variable
4. No token provided, by command option or...
5. Duck DNS returned a 'normal' bad response (check inputs)
6. Duck DNS returned an unexpected error / response

### Thank you!
Thanks to the folks at [Duck DNS](https://www.duckdns.org/) for
offering such a great service!