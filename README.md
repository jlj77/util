# util
Some simple scripts. For fun / personal use.

## Scripts

### Image Conversion Scripts
Simple bash scripts for batch image format conversion:

- **`jpg_png.sh`** - Convert JPG files to PNG format
- **`png_jpg.sh`** - Convert PNG files to JPG format  
- **`webp_png.sh`** - Convert WebP files to PNG format

**Usage:** `./script_name.sh file1.jpg file2.jpg file3.jpg`

### File Management
- **`rename.sh`** - Batch rename files with a common prefix
  - Prompts for prefix and renames all provided files
  - Usage: `./rename.sh file1.txt file2.txt file3.txt`

### Network Analysis
- **`pcap_activity_analyser.py`** - Analyse PCAP files for network activity patterns
  - Groups PCAP files by 24-hour periods based on timestamps in filenames
  - Reports on network activity patterns and file sizes
  - Can filter for files with unencrypted traffic (requires `tshark`)
  - Supports recursive directory scanning and ZIP creation
  - Usage: `python3 pcap_activity_analyser.py [options]`

### DNS Management
- **`upduck.sh`** - Update Duck DNS domain IP addresses

## Upduck
A simple script to update the IP address that a Duck DNS domain name resolves to.

### Available environment variables*
- $DUCKDNS_DOMAIN: The domain you want to update
- $DUCKDNS_TOKEN: The token to use to authenticate the request
- $DUCKDNS_IP: (Optional) The IP address that the provided domain
                should resolve to — Duck DNS will detect and use
                the source IP otherwise

*All other [Duck DNS API](https://www.duckdns.org/spec.jsp) options
are optional; I'm aiming for feature parity in the future.

_NOTE: command line options override environment variables._

### Error codes:
1. Invalid arguments
2. Failure to find `wget` on the system
3. No domain provided, by command option or environment variable
4. No token provided, by command option or environment variable
5. Duck DNS returned a 'normal' bad response (check inputs)
6. Duck DNS returned an unexpected error / response

### Thank you!
Thanks to the folks at [Duck DNS](https://www.duckdns.org/) for
offering such a great service!