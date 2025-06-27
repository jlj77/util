#!/usr/bin/env python3
"""
PCAP Activity Analyser

This script analyses pcap files and reports on network activity patterns by counting 
files generated in 24-hour periods. It extracts timestamps from filenames to identify 
periods of high network activity.

Key Features:
- Group files by 24-hour periods and identify peak activity times
- Filter for unencrypted traffic only (requires tshark)
- Show top N most active files with configurable sorting
- Create zip files for specific periods
- Recursive directory searching

Unencrypted Traffic Analysis:
When using --unencrypted-only, the script:
1. Analyses each pcap file using tshark to determine encryption levels
2. Filters to files with ≥N% unencrypted traffic (default: 10%)
3. Includes files with failed analysis (conservative approach)
4. Automatically sorts top files by unencrypted percentage (not file size)
5. All subsequent analysis (periods, zipping, etc.) uses the filtered subset

Sorting Options for Top Files:
- 'size': Sort by file size (default for regular analysis)
- 'frequency': Sort by files created in the same hour
- 'unencrypted_pct': Sort by unencrypted traffic percentage (auto-selected with --unencrypted-only)

Dependencies:
- Python 3.6+
- tshark (Wireshark CLI tools) for unencrypted traffic analysis
  - Ubuntu/Debian: sudo apt-get install tshark
  - CentOS/RHEL: sudo yum install wireshark-cli
  - macOS: brew install wireshark
"""

import os
import re
import zipfile
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
import argparse
from pathlib import Path


def extract_timestamp_from_filename(filename):
    """
    Extract timestamp from pcap filename.
    Expected format: output_fm_18apr_00019_20250419120917.pcapng
    Returns datetime object or None if parsing fails.
    """
    # Pattern to match timestamp in format: 20250419120917 (YYYYMMDDHHMMSS)
    pattern = r'_(\d{14})\.pcapng$'
    match = re.search(pattern, filename)
    
    if match:
        timestamp_str = match.group(1)
        try:
            # Parse YYYYMMDDHHMMSS format
            return datetime.strptime(timestamp_str, '%Y%m%d%H%M%S')
        except ValueError:
            return None
    return None


def check_tshark_available():
    """
    Check if tshark is available on the system.
    
    Returns:
        Boolean: True if tshark is available, False otherwise
    """
    try:
        result = subprocess.run(['tshark', '--version'], 
                              capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def analyse_pcap_encryption(pcap_file):
    """
    Analyse a pcap file to determine the percentage of unencrypted traffic.
    
    Args:
        pcap_file: Path to the pcap file
    
    Returns:
        Dictionary with encryption analysis results or None if analysis fails
    """
    if not check_tshark_available():
        return None
    
    try:
        # Use tshark to analyse the pcap file
        cmd = [
            'tshark', '-r', str(pcap_file), 
            '-q', '-z', 'io,stat,0,ip,ipv6,tcp,udp,icmp,http,ftp,telnet,ssh,ssl,tls'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return None
        
        lines = result.stdout.split('\n')
        
        # Find the data line that contains the actual statistics
        data_line = None
        for line in lines:
            # Look for the line that contains the interval data (starts with "|     0.0 <>")
            if '|     0.0 <>' in line and '|' in line:
                data_line = line
                break
        
        if not data_line:
            return None
        
        # Parse the data line - split by '|' and extract the frame counts
        parts = [p.strip() for p in data_line.split('|')]
        
        # The columns are: Interval | ip_frames | ip_bytes | ipv6_frames | ipv6_bytes | tcp_frames | tcp_bytes | udp_frames | udp_bytes | icmp_frames | icmp_bytes | http_frames | http_bytes | ftp_frames | ftp_bytes | telnet_frames | telnet_bytes | ssh_frames | ssh_bytes | ssl_frames | ssl_bytes | tls_frames | tls_bytes
        # We want the frame counts (odd-numbered indices after the interval)
        
        try:
            # Extract frame counts (every other field starting from index 1)
            ip_frames = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            ipv6_frames = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
            tcp_frames = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0
            udp_frames = int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else 0
            icmp_frames = int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0
            http_frames = int(parts[11]) if len(parts) > 11 and parts[11].isdigit() else 0
            ftp_frames = int(parts[13]) if len(parts) > 13 and parts[13].isdigit() else 0
            telnet_frames = int(parts[15]) if len(parts) > 15 and parts[15].isdigit() else 0
            ssh_frames = int(parts[17]) if len(parts) > 17 and parts[17].isdigit() else 0
            ssl_frames = int(parts[19]) if len(parts) > 19 and parts[19].isdigit() else 0
            tls_frames = int(parts[21]) if len(parts) > 21 and parts[21].isdigit() else 0
            
            # Calculate totals
            total_packets = ip_frames + ipv6_frames
            unencrypted_packets = http_frames + ftp_frames + telnet_frames
            encrypted_packets = ssh_frames + ssl_frames + tls_frames
            
            if total_packets == 0:
                return {'total_packets': 0, 'unencrypted_packets': 0, 'unencrypted_pct': 0}
            
            unencrypted_pct = (unencrypted_packets / total_packets) * 100
            
            return {
                'total_packets': total_packets,
                'unencrypted_packets': unencrypted_packets,
                'encrypted_packets': encrypted_packets,
                'unencrypted_pct': unencrypted_pct
            }
            
        except (IndexError, ValueError) as e:
            # Debug: print the problematic line
            print(f"DEBUG: Failed to parse line: {data_line}")
            print(f"DEBUG: Parts: {parts}")
            return None
        
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return None


def filter_unencrypted_files(file_info_list, min_unencrypted_pct=10):
    """
    Filter file list to only include files with sufficient unencrypted traffic.
    
    Args:
        file_info_list: List of file info tuples
        min_unencrypted_pct: Minimum percentage of unencrypted traffic required
    
    Returns:
        Tuple of (filtered_file_info_list, encryption_data_dict)
        where encryption_data_dict maps filepath -> encryption_analysis
    """
    if not check_tshark_available():
        print("Error: tshark is not available but required for unencrypted traffic analysis.")
        print("Please install tshark (Wireshark CLI tools) to use the --unencrypted-only option.")
        print("Installation commands:")
        print("  Ubuntu/Debian: sudo apt-get install tshark")
        print("  CentOS/RHEL: sudo yum install wireshark-cli")
        print("  macOS: brew install wireshark")
        raise SystemExit(1)
    
    filtered_files = []
    encryption_data = {}  # Store encryption analysis for each file
    total_files = len(file_info_list)
    
    print(f"🔍 Analysing {total_files} pcap files for unencrypted traffic...")
    print(f"   Threshold: ≥{min_unencrypted_pct}% unencrypted traffic required")
    print()
    
    # Running statistics
    total_packets_analysed = 0
    total_unencrypted_packets = 0
    files_with_traffic = 0
    files_above_threshold = 0
    files_below_threshold = 0
    files_failed_analysis = 0
    
    for i, file_info in enumerate(file_info_list, 1):
        timestamp, size, filepath = file_info
        filename = Path(filepath).name
        
        # Show progress every 5 files or on the last file
        if i % 5 == 0 or i == total_files:
            progress_pct = (i / total_files) * 100
            avg_unencrypted = (total_unencrypted_packets / total_packets_analysed * 100) if total_packets_analysed > 0 else 0
            print(f"   Progress: {i}/{total_files} ({progress_pct:.1f}%) - "
                  f"Avg unencrypted: {avg_unencrypted:.1f}% - "
                  f"Above threshold: {files_above_threshold}, Below: {files_below_threshold}, Failed: {files_failed_analysis}")
        
        # Analyse encryption in the pcap file
        encryption_analysis = analyse_pcap_encryption(filepath)
        
        if encryption_analysis is None:
            # If analysis fails, include the file (conservative approach)
            filtered_files.append(file_info)
            files_failed_analysis += 1
            # Store failed analysis data with 0% unencrypted for sorting purposes
            encryption_data[filepath] = {
                'unencrypted_pct': 0.0,
                'total_packets': 0,
                'unencrypted_packets': 0,
                'analysis_failed': True
            }
            print(f"   ⚠️  {filename}: Analysis failed (included)")
            continue
        
        total_packets = encryption_analysis['total_packets']
        unencrypted_packets = encryption_analysis['unencrypted_packets']
        unencrypted_pct = encryption_analysis['unencrypted_pct']
        
        # Store encryption data for this file
        encryption_data[filepath] = encryption_analysis
        
        # Update running statistics
        if total_packets > 0:
            total_packets_analysed += total_packets
            total_unencrypted_packets += unencrypted_packets
            files_with_traffic += 1
        
        if unencrypted_pct >= min_unencrypted_pct:
            filtered_files.append(file_info)
            files_above_threshold += 1
            print(f"   ✅ {filename}: {unencrypted_pct:.1f}% unencrypted ({unencrypted_packets}/{total_packets} packets)")
        else:
            files_below_threshold += 1
            print(f"   ❌ {filename}: {unencrypted_pct:.1f}% unencrypted ({unencrypted_packets}/{total_packets} packets) - SKIPPED")
    
    # Final summary
    print()
    print("📊 ENCRYPTION ANALYSIS SUMMARY:")
    print(f"   Files analysed: {total_files}")
    print(f"   Files with traffic: {files_with_traffic}")
    print(f"   Files above threshold (≥{min_unencrypted_pct}%): {files_above_threshold}")
    print(f"   Files below threshold: {files_below_threshold}")
    print(f"   Files with failed analysis: {files_failed_analysis}")
    
    if total_packets_analysed > 0:
        overall_unencrypted_pct = (total_unencrypted_packets / total_packets_analysed) * 100
        print(f"   Total packets analysed: {total_packets_analysed:,}")
        print(f"   Total unencrypted packets: {total_unencrypted_packets:,}")
        print(f"   Overall unencrypted percentage: {overall_unencrypted_pct:.1f}%")
    
    print(f"✅ Filtered to {len(filtered_files)} files with ≥{min_unencrypted_pct}% unencrypted traffic")
    
    return filtered_files, encryption_data


def get_file_info(filepath, include_path=False):
    """
    Get file information including size and timestamp.
    Returns tuple of (timestamp, size_in_mb, filepath) or None if not a pcap file.
    
    Args:
        filepath: Path to the file
        include_path: If True, include full path in the tuple
    """
    if not str(filepath).endswith('.pcapng'):
        return None
    
    # Extract timestamp from filename
    timestamp = extract_timestamp_from_filename(filepath.name)
    if timestamp is None:
        return None
    
    # Get file size
    try:
        size_bytes = os.path.getsize(filepath)
        size_mb = size_bytes / (1024 * 1024)
        return (timestamp, size_mb, str(filepath) if include_path else filepath.name)
    except OSError:
        return None


def find_pcap_files(directory, recursive=False):
    """
    Find all pcap files in the directory (and subdirectories if recursive=True).
    
    Args:
        directory: Directory to search
        recursive: Whether to search subdirectories
    
    Returns:
        List of file info tuples: (timestamp, size_mb, filepath)
    """
    directory_path = Path(directory)
    file_info_list = []
    
    if recursive:
        # Search recursively through all subdirectories
        for filepath in directory_path.rglob('*.pcapng'):
            if filepath.is_file():
                file_info = get_file_info(filepath, include_path=True)
                if file_info:
                    file_info_list.append(file_info)
    else:
        # Search only in the specified directory
        for filepath in directory_path.iterdir():
            if filepath.is_file():
                file_info = get_file_info(filepath, include_path=True)
                if file_info:
                    file_info_list.append(file_info)
    
    return file_info_list


def group_by_24h_periods(file_info_list):
    """
    Group files by 24-hour periods starting from the earliest file.
    Returns a dictionary with date strings as keys and lists of file info as values.
    """
    if not file_info_list:
        return {}
    
    # Sort by timestamp
    sorted_files = sorted(file_info_list, key=lambda x: x[0])
    
    # Find the earliest timestamp and create 24-hour periods
    earliest_time = sorted_files[0][0]
    start_date = earliest_time.replace(hour=0, minute=0, second=0, microsecond=0)
    
    periods = defaultdict(list)
    
    for file_info in sorted_files:
        timestamp = file_info[0]
        # Calculate which 24-hour period this file belongs to
        days_diff = (timestamp - start_date).days
        period_start = start_date + timedelta(days=days_diff)
        period_key = period_start.strftime('%Y-%m-%d')
        periods[period_key].append(file_info)
    
    return dict(periods)


def get_top_active_files(file_info_list, top_n=10, sort_by='size', encryption_data=None):
    """
    Get the top N most active files.
    
    Args:
        file_info_list: List of file info tuples
        top_n: Number of top files to return
        sort_by: 'size', 'frequency', or 'unencrypted_pct' (unencrypted percentage)
        encryption_data: Dictionary mapping filepath -> encryption analysis (required for 'unencrypted_pct' sort)
    
    Returns:
        List of top file info tuples
    """
    if not file_info_list:
        return []
    
    if sort_by == 'size':
        # Sort by file size (descending)
        sorted_files = sorted(file_info_list, key=lambda x: x[1], reverse=True)
        return sorted_files[:top_n]
    
    elif sort_by == 'frequency':
        # Group files by timestamp pattern (hour) and sort by frequency
        hour_groups = defaultdict(list)
        for file_info in file_info_list:
            timestamp = file_info[0]
            hour_key = timestamp.strftime('%Y-%m-%d %H')
            hour_groups[hour_key].append(file_info)
        
        # Sort hours by number of files (descending)
        sorted_hours = sorted(hour_groups.items(), key=lambda x: len(x[1]), reverse=True)
        
        # Flatten the top N hours
        top_files = []
        for hour, files in sorted_hours[:top_n]:
            top_files.extend(files)
        
        return top_files[:top_n]
    
    elif sort_by == 'unencrypted_pct':
        # Sort by unencrypted traffic percentage (descending)
        if encryption_data is None:
            print("Warning: encryption_data required for 'unencrypted_pct' sorting, falling back to 'size'")
            return get_top_active_files(file_info_list, top_n, 'size')
        
        def get_unencrypted_pct(file_info):
            filepath = file_info[2]  # filepath is the third element
            if filepath in encryption_data:
                return encryption_data[filepath].get('unencrypted_pct', 0.0)
            return 0.0
        
        sorted_files = sorted(file_info_list, key=get_unencrypted_pct, reverse=True)
        return sorted_files[:top_n]
    
    else:
        return file_info_list[:top_n]


def check_file_permissions(periods):
    """
    Check file permissions for all files in the periods to be zipped.
    
    Args:
        periods: Dictionary with date strings as keys and lists of file info as values
    
    Returns:
        Dictionary with permission issues: {date: {'accessible': [], 'inaccessible': []}}
    """
    permission_issues = {}
    
    for date, files in periods.items():
        accessible_files = []
        inaccessible_files = []
        
        for timestamp, size, filepath in files:
            file_path = Path(filepath)
            
            # Check if file exists and is readable
            if file_path.exists():
                try:
                    # Try to open the file for reading
                    with open(file_path, 'rb') as f:
                        f.read(1)  # Read 1 byte to test access
                    accessible_files.append((timestamp, size, filepath))
                except (PermissionError, OSError):
                    inaccessible_files.append((timestamp, size, filepath))
            else:
                inaccessible_files.append((timestamp, size, filepath))
        
        permission_issues[date] = {
            'accessible': accessible_files,
            'inaccessible': inaccessible_files
        }
    
    return permission_issues


def report_permission_issues(permission_issues):
    """
    Report permission issues found during the check.
    
    Args:
        permission_issues: Dictionary with permission issues from check_file_permissions
    
    Returns:
        Boolean: True if there are any inaccessible files, False otherwise
    """
    has_issues = False
    
    for date, issues in permission_issues.items():
        accessible_count = len(issues['accessible'])
        inaccessible_count = len(issues['inaccessible'])
        
        if inaccessible_count > 0:
            has_issues = True
            print(f"\n⚠️  PERMISSION ISSUES for {date}:")
            print(f"   Accessible files: {accessible_count}")
            print(f"   Inaccessible files: {inaccessible_count}")
            
            # Show first few inaccessible files
            for i, (timestamp, size, filepath) in enumerate(issues['inaccessible'][:3]):
                print(f"     {i+1}. {filepath} ({format_size(size)})")
            if len(issues['inaccessible']) > 3:
                print(f"     ... and {len(issues['inaccessible']) - 3} more files")
            
            print(f"   Suggestion: Check file permissions with 'ls -la {Path(filepath).parent}'")
    
    if has_issues:
        print("\n💡 To fix permission issues, try:")
        print("   chmod -R 644 /path/to/pcap/files/*.pcapng")
        print("   or run the script with sudo if you have admin privileges")
    
    return has_issues


def zip_period_files(periods, output_dir=".", zip_prefix="pcap_period"):
    """
    Create zip files for specified periods.
    
    Args:
        periods: Dictionary with date strings as keys and lists of file info as values
        output_dir: Directory to save zip files
        zip_prefix: Prefix for zip file names
    
    Returns:
        List of created zip file paths
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    created_zips = []
    
    for date, files in periods.items():
        if not files:
            continue
            
        # Create zip filename
        zip_filename = f"{zip_prefix}_{date}.zip"
        zip_path = output_path / zip_filename
        
        print(f"Creating zip: {zip_path}")
        print(f"  Period {date} has {len(files)} files")
        
        files_added = 0
        files_skipped = 0
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for timestamp, size, filepath in files:
                # Ensure we have a proper Path object
                file_path = Path(filepath)
                
                # Check if file exists
                if not file_path.exists():
                    print(f"  Warning: File not found: {filepath}")
                    files_skipped += 1
                    continue
                
                # Determine archive name (how it appears in the zip)
                if file_path.is_absolute():
                    # For absolute paths, use just the filename to avoid path issues
                    arcname = file_path.name
                else:
                    # For relative paths, use the path as is
                    arcname = str(file_path)
                
                try:
                    zipf.write(file_path, arcname)
                    print(f"  Added: {filepath} ({format_size(size)}) -> {arcname}")
                    files_added += 1
                except PermissionError:
                    print(f"  Permission denied: {filepath}")
                    files_skipped += 1
                except FileNotFoundError:
                    print(f"  Warning: File not found: {filepath}")
                    files_skipped += 1
                except Exception as e:
                    print(f"  Error adding {filepath}: {e}")
                    files_skipped += 1
        
        # Get zip file size
        zip_size = zip_path.stat().st_size / (1024 * 1024)
        print(f"  Created: {zip_path} ({format_size(zip_size)}) with {files_added} files")
        
        if files_added == 0:
            print(f"  Warning: No files were added to {zip_path}")
        elif files_skipped > 0:
            print(f"  Note: {files_skipped} files were skipped due to permission/access issues")
        
        created_zips.append(str(zip_path))
    
    return created_zips


def check_unencrypted_zipping_viability(analysis_results, periods_to_zip):
    """
    Check if there are enough unencrypted files in periods to make zipping useful.
    
    Args:
        analysis_results: Analysis results dictionary
        periods_to_zip: Dictionary of periods to zip
    
    Returns:
        Tuple of (is_viable, warning_message)
    """
    if not analysis_results.get('unencrypted_only', False):
        return True, None
    
    # Check if any period has a reasonable number of files
    max_files_in_period = max(len(files) for files in periods_to_zip.values()) if periods_to_zip else 0
    
    if max_files_in_period < 5:
        warning = (
            f"⚠️  WARNING: Unencrypted traffic analysis found only {max_files_in_period} files "
            f"in the largest period to zip.\n"
            f"   This may not provide enough data for meaningful analysis.\n"
            f"   Consider:\n"
            f"   - Lowering the --min-unencrypted-pct threshold (currently {analysis_results['min_unencrypted_pct']}%)\n"
            f"   - Using --top-files to identify specific files of interest\n"
            f"   - Running without --unencrypted-only to see all traffic patterns"
        )
        return False, warning
    
    return True, None


def get_periods_to_zip(analysis_results, zip_periods_arg):
    """
    Determine which periods to zip based on the zip_periods argument.
    
    Args:
        analysis_results: Analysis results dictionary
        zip_periods_arg: String specifying which periods to zip
    
    Returns:
        Dictionary of periods to zip
    """
    if not analysis_results or not analysis_results['sorted_periods']:
        return {}
    
    periods = analysis_results['periods']
    
    if zip_periods_arg == 'all':
        # Zip all periods
        return periods
    
    elif zip_periods_arg == 'active':
        # Zip only active periods (those with files >= threshold)
        return analysis_results['active_periods']
    
    elif zip_periods_arg.startswith('top'):
        # Zip top N most active periods
        try:
            n = int(zip_periods_arg[3:])  # Extract number from "topN"
            top_periods = {}
            for date, files in analysis_results['sorted_periods'][:n]:
                top_periods[date] = files
            return top_periods
        except (ValueError, IndexError):
            print(f"Warning: Invalid top N format '{zip_periods_arg}'. Using top 3.")
            top_periods = {}
            for date, files in analysis_results['sorted_periods'][:3]:
                top_periods[date] = files
            return top_periods
    
    elif zip_periods_arg in periods:
        # Zip specific date
        return {zip_periods_arg: periods[zip_periods_arg]}
    
    else:
        # Try to parse as date format
        try:
            # Try different date formats
            for date_format in ['%Y-%m-%d', '%Y%m%d', '%Y/%m/%d']:
                try:
                    parsed_date = datetime.strptime(zip_periods_arg, date_format)
                    date_key = parsed_date.strftime('%Y-%m-%d')
                    if date_key in periods:
                        return {date_key: periods[date_key]}
                except ValueError:
                    continue
        except (ValueError, TypeError):
            pass
        
        print(f"Warning: Could not find period '{zip_periods_arg}'. Available periods:")
        for date in sorted(periods.keys()):
            print(f"  {date} ({len(periods[date])} files)")
        return {}


def format_size(size_mb):
    """Format size in MB with 2 decimal places."""
    return f"{size_mb:.2f} MB"


def analyse_pcap_activity(directory=".", min_files_threshold=1, recursive=False, unencrypted_only=False, min_unencrypted_pct=10):
    """
    Analyse pcap files in the specified directory and report on activity patterns.
    
    Args:
        directory: Directory to analyse (default: current directory)
        min_files_threshold: Minimum number of files to consider a period "active"
        recursive: Whether to search subdirectories
        unencrypted_only: Whether to filter for unencrypted traffic only
        min_unencrypted_pct: Minimum percentage of unencrypted traffic required for file inclusion (default: 10). Only used with --unencrypted-only. Files with failed analysis are included conservatively.
    
    Returns:
        Dictionary with analysis results
    """
    directory_path = Path(directory)
    
    if not directory_path.exists():
        print(f"Error: Directory '{directory}' does not exist.")
        return None
    
    # Find all pcap files
    file_info_list = find_pcap_files(directory_path, recursive=recursive)
    
    if not file_info_list:
        search_type = "recursively" if recursive else "in the directory"
        print(f"No pcap files found {search_type}.")
        return None
    
    # Filter for unencrypted traffic if requested
    original_count = len(file_info_list)
    encryption_data = {}  # Initialize encryption_data
    if unencrypted_only:
        file_info_list, encryption_data = filter_unencrypted_files(file_info_list, min_unencrypted_pct)
        filtered_count = len(file_info_list)
        print(f"📊 Traffic Analysis: {filtered_count}/{original_count} files contain sufficient unencrypted traffic (≥{min_unencrypted_pct}%)")
    
    if not file_info_list:
        if unencrypted_only:
            print("No pcap files with sufficient unencrypted traffic found.")
        else:
            search_type = "recursively" if recursive else "in the directory"
            print(f"No pcap files found {search_type}.")
        return None
    
    # Group files by 24-hour periods
    periods = group_by_24h_periods(file_info_list)
    
    # Calculate statistics
    total_files = len(file_info_list)
    total_size = sum(info[1] for info in file_info_list)
    
    # Find periods with high activity
    active_periods = {
        date: files for date, files in periods.items() 
        if len(files) >= min_files_threshold
    }
    
    # Sort periods by number of files (descending)
    sorted_periods = sorted(
        active_periods.items(), 
        key=lambda x: len(x[1]), 
        reverse=True
    )
    
    return {
        'total_files': total_files,
        'total_size': total_size,
        'periods': periods,
        'active_periods': active_periods,
        'sorted_periods': sorted_periods,
        'file_info_list': file_info_list,
        'recursive': recursive,
        'unencrypted_only': unencrypted_only,
        'min_unencrypted_pct': min_unencrypted_pct,
        'original_count': original_count,
        'encryption_data': encryption_data
    }


def print_analysis_report(analysis_results, min_files_threshold=1, top_files=0, sort_by='size'):
    """Print a formatted analysis report."""
    if not analysis_results:
        return
    
    print("=" * 80)
    print("PCAP ACTIVITY ANALYSIS REPORT")
    if analysis_results.get('unencrypted_only', False):
        print("🔓 UNENCRYPTED TRAFFIC ONLY")
        print("   (All analysis results are based on files with sufficient unencrypted traffic)")
    print("=" * 80)
    print()
    
    # Summary statistics
    search_type = "recursively" if analysis_results['recursive'] else "in directory"
    print(f"Search type: {search_type}")
    
    if analysis_results.get('unencrypted_only', False):
        print(f"Traffic filter: Unencrypted only (≥{analysis_results['min_unencrypted_pct']}% unencrypted)")
        print(f"Original files found: {analysis_results['original_count']}")
        print(f"Files with sufficient unencrypted traffic: {analysis_results['total_files']}")
        print("   → All subsequent analysis (periods, top files, etc.) uses this filtered subset")
    else:
        print(f"Total pcap files found: {analysis_results['total_files']}")
    
    print(f"Total size: {format_size(analysis_results['total_size'])}")
    print(f"Analysis period: {len(analysis_results['periods'])} days")
    print(f"Active periods (≥{min_files_threshold} files): {len(analysis_results['active_periods'])}")
    print()
    
    # Activity by 24-hour periods
    if analysis_results.get('unencrypted_only', False):
        print("NETWORK ACTIVITY BY 24-HOUR PERIODS (UNENCRYPTED TRAFFIC ONLY)")
        print("   (Periods ranked by number of files with sufficient unencrypted traffic)")
    else:
        print("NETWORK ACTIVITY BY 24-HOUR PERIODS")
    print("-" * 50)
    
    if analysis_results['sorted_periods']:
        print(f"{'Date':<12} {'Files':<6} {'Total Size':<12} {'Avg Size':<10} {'Peak Time':<12}")
        print("-" * 60)
        
        for date, files in analysis_results['sorted_periods']:
            file_count = len(files)
            total_size = sum(info[1] for info in files)
            avg_size = total_size / file_count if file_count > 0 else 0
            
            # Find the busiest hour (most files created in a single hour)
            hour_counts = defaultdict(int)
            for timestamp, _, _ in files:
                hour_key = timestamp.strftime('%H')
                hour_counts[hour_key] += 1
            
            peak_hour = max(hour_counts.items(), key=lambda x: x[1])[0] if hour_counts else "N/A"
            
            print(f"{date:<12} {file_count:<6} {format_size(total_size):<12} "
                  f"{format_size(avg_size):<10} {peak_hour}:00")
    else:
        if analysis_results.get('unencrypted_only', False):
            print("No active periods found with sufficient unencrypted traffic.")
        else:
            print("No active periods found.")
    
    print()
    
    # Top active files section
    if top_files > 0:
        if analysis_results.get('unencrypted_only', False):
            print(f"TOP {top_files} MOST ACTIVE FILES (UNENCRYPTED TRAFFIC ONLY, sorted by {sort_by})")
            print("   (Selected from files with sufficient unencrypted traffic)")
            print("   Note: These are individual files, not 24-hour periods")
        else:
            print(f"TOP {top_files} MOST ACTIVE FILES (sorted by {sort_by})")
        print("-" * 50)
        
        top_file_list = get_top_active_files(
            analysis_results['file_info_list'], 
            top_n=top_files, 
            sort_by=sort_by,
            encryption_data=analysis_results['encryption_data']
        )
        
        if top_file_list:
            print(f"{'Timestamp':<20} {'Size':<12} {'File':<50}")
            print("-" * 85)
            
            for timestamp, size, filepath in top_file_list:
                timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                # Truncate long file paths for display
                display_path = filepath if len(filepath) <= 47 else "..." + filepath[-44:]
                print(f"{timestamp_str:<20} {format_size(size):<12} {display_path:<50}")
        else:
            print("No files found.")
        
        print()
    
    # Detailed breakdown for most active periods
    if analysis_results['sorted_periods']:
        if analysis_results.get('unencrypted_only', False):
            print("DETAILED BREAKDOWN OF MOST ACTIVE PERIODS (UNENCRYPTED TRAFFIC ONLY)")
            print("   (Showing files that passed unencrypted traffic filtering)")
        else:
            print("DETAILED BREAKDOWN OF MOST ACTIVE PERIODS")
        print("-" * 50)
        
        for i, (date, files) in enumerate(analysis_results['sorted_periods'][:5], 1):
            print(f"\n{i}. {date} ({len(files)} files)")
            print("   Files:")
            
            # Group files by hour for better readability
            hour_groups = defaultdict(list)
            for timestamp, size, filepath in files:
                hour = timestamp.strftime('%H:%M')
                hour_groups[hour].append((timestamp, size, filepath))
            
            for hour in sorted(hour_groups.keys()):
                hour_files = hour_groups[hour]
                print(f"   {hour}: {len(hour_files)} files")
                for timestamp, size, filepath in hour_files:
                    # Truncate long file paths for display
                    display_path = filepath if len(filepath) <= 50 else "..." + filepath[-47:]
                    print(f"      {timestamp.strftime('%H:%M:%S')} - {format_size(size)} - {display_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyse pcap files and report on network activity patterns"
    )
    parser.add_argument(
        "-d", "--directory", 
        default=".", 
        help="Directory to analyse (default: current directory)"
    )
    parser.add_argument(
        "-t", "--threshold", 
        type=int, 
        default=1, 
        help="Minimum number of files to consider a period 'active' (default: 1)"
    )
    parser.add_argument(
        "-r", "--recursive", 
        action="store_true", 
        help="Search subdirectories recursively"
    )
    parser.add_argument(
        "--top-files", 
        type=int, 
        default=0, 
        help="Show top N most active files (default: 0 = don't show)"
    )
    parser.add_argument(
        "--sort-by", 
        choices=['size', 'frequency', 'unencrypted_pct'], 
        default='size', 
        help="Sort top files by 'size' (file size), 'frequency' (files per hour), or 'unencrypted_pct' (unencrypted traffic percentage). Auto-selected to 'unencrypted_pct' when using --unencrypted-only"
    )
    parser.add_argument(
        "--zip-periods", 
        type=str, 
        help="Create zip files for periods. Options: 'all', 'active', 'topN', or specific date (YYYY-MM-DD). 'topN' zips top N periods by file count."
    )
    parser.add_argument(
        "--zip-output-dir", 
        default=".", 
        help="Directory to save zip files (default: current directory)"
    )
    parser.add_argument(
        "--zip-prefix", 
        default="pcap_period", 
        help="Prefix for zip file names (default: pcap_period)"
    )
    parser.add_argument(
        "--list-files", 
        action="store_true", 
        help="List all pcap files found"
    )
    parser.add_argument(
        "--unencrypted-only", 
        action="store_true", 
        help="Filter for unencrypted traffic only (requires tshark). Analyzes each file and filters to those with ≥N%% unencrypted traffic. Affects ALL analysis (periods, top files, zipping). Auto-selects 'unencrypted_pct' sorting for top files."
    )
    parser.add_argument(
        "--min-unencrypted-pct", 
        type=int, 
        default=10, 
        help="Minimum percentage of unencrypted traffic required for file inclusion (default: 10). Only used with --unencrypted-only. Files with failed analysis are included conservatively."
    )
    
    args = parser.parse_args()
    
    # Auto-select unencrypted_pct sorting when using --unencrypted-only
    if args.unencrypted_only and args.sort_by == 'size':
        args.sort_by = 'unencrypted_pct'
        print("ℹ️  Auto-selected 'unencrypted_pct' sorting for --unencrypted-only analysis")
    
    # Analyse pcap activity
    analysis_results = analyse_pcap_activity(
        args.directory, 
        args.threshold, 
        recursive=args.recursive,
        unencrypted_only=args.unencrypted_only,
        min_unencrypted_pct=args.min_unencrypted_pct
    )
    
    if analysis_results:
        # Print the main report
        print_analysis_report(
            analysis_results, 
            args.threshold, 
            args.top_files, 
            args.sort_by
        )
        
        # Handle zip functionality
        if args.zip_periods:
            print("\n" + "=" * 80)
            print("ZIPPING PCAP PERIODS")
            if analysis_results.get('unencrypted_only', False):
                print("   (Zipping files that passed unencrypted traffic filtering)")
            print("=" * 80)
            
            periods_to_zip = get_periods_to_zip(analysis_results, args.zip_periods)
            
            if periods_to_zip:
                # Check if unencrypted zipping is viable
                is_viable, warning_message = check_unencrypted_zipping_viability(analysis_results, periods_to_zip)
                if warning_message:
                    print(f"\n{warning_message}")
                    if not is_viable:
                        print("\n❓ Continue with zipping anyway? (y/N)")
                        try:
                            response = input().strip().lower()
                            if response not in ['y', 'yes']:
                                print("⏹️  Zipping cancelled by user.")
                                return
                        except KeyboardInterrupt:
                            print("\n⏹️  Zipping cancelled by user.")
                            return
                
                print(f"Found {len(periods_to_zip)} periods to zip:")
                for date, files in periods_to_zip.items():
                    print(f"  {date}: {len(files)} files")
                    # Show first few files for debugging
                    for i, (timestamp, size, filepath) in enumerate(files[:3]):
                        print(f"    {i+1}. {filepath} ({format_size(size)})")
                    if len(files) > 3:
                        print(f"    ... and {len(files) - 3} more files")
                
                # Check permissions before zipping
                print("\n🔍 Checking file permissions...")
                permission_issues = check_file_permissions(periods_to_zip)
                
                if report_permission_issues(permission_issues):
                    print("\n❓ Continue with zipping? (Some files may be skipped)")
                    print("   Press Enter to continue, or Ctrl+C to abort...")
                    try:
                        input()
                    except KeyboardInterrupt:
                        print("\n⏹️  Zipping cancelled by user.")
                        return
                
                # Filter out inaccessible files for zipping
                accessible_periods = {}
                for date, issues in permission_issues.items():
                    if issues['accessible']:
                        accessible_periods[date] = issues['accessible']
                
                if not accessible_periods:
                    print("\n❌ No accessible files found to zip.")
                    return
                
                print("\n📦 Starting zip process...")
                created_zips = zip_period_files(
                    accessible_periods, 
                    args.zip_output_dir, 
                    args.zip_prefix
                )
                
                print(f"\nCreated {len(created_zips)} zip file(s):")
                for zip_path in created_zips:
                    print(f"  {zip_path}")
            else:
                print("No periods to zip.")
        
        # Optionally list all files
        if args.list_files:
            print("\n" + "=" * 80)
            print("ALL PCAP FILES FOUND")
            print("=" * 80)
            for timestamp, size, filepath in sorted(analysis_results['file_info_list'], key=lambda x: x[0]):
                print(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {format_size(size)} - {filepath}")


if __name__ == "__main__":
    main()
