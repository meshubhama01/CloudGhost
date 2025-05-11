#!/usr/bin/env python3

# =============================================================================
# utils.py - Subdomain Takeover Detection Utility Functions and Main
#
# Contains general helper functions and the main script entry point for
# orchestrating reconnaissance and takeover detection.
# =============================================================================

# Standard Library Imports
import argparse
import csv
import os
import subprocess
import time
import sys
# Note: requests, dns.resolver, re, concurrent.futures are used by other modules,
# but needed here for run_command and query_crtsh.
import requests # Needed for query_crtsh
import dns.resolver # Needed for query_crtsh
import re # Needed for query_crtsh (json decoding error check)
import concurrent.futures # Needed for run_command/query_crtsh threading in recon


# Third-Party Imports (Ensure these are installed: pip install requests dnspython)
# Imports specific to other modules will be handled in those files.


# --- Utility Functions ---

def run_command(command, timeout, tool_name):
    """
    Runs an external command using subprocess with a specified timeout.
    Returns output lines, elapsed time, and tool name.

    Args:
        command (list): The command and its arguments as a list of strings.
        timeout (int): The timeout in seconds for the command execution.
        tool_name (str): The name of the tool being run, for logging.

    Returns:
        tuple: A tuple containing:
               - A list of lines from the command's standard output (list of str).
               - The elapsed time in seconds (float).
               - The name of the tool (str).
               Returns ([], timeout, tool_name) on timeout or errors,
               ([], 0, tool_name) if command not found.
    """
    try:
        start = time.time()
        # Use Popen and communicate with timeout for better control
        # Setting close_fds=True is good practice on Unix-like systems
        # Use text=True for Python 3.7+ to handle encoding automatically
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, close_fds=sys.platform != "win32")
        stdout, stderr = process.communicate(timeout=timeout)
        elapsed = time.time() - start

        error_output = stderr.strip()
        if error_output:
           # Only print stderr if it's not empty or just whitespace
           if error_output:
               print(f"[-] stderr from {tool_name} command '{' '.join(command)}': {error_output}", file=sys.stderr)

        # Return output lines, excluding empty lines
        return [line for line in stdout.splitlines() if line.strip()], elapsed, tool_name

    except FileNotFoundError:
        print(f"[-] Error: {tool_name} command not found. Make sure it's in your PATH.", file=sys.stderr)
        # Indicate command not found with 0 elapsed time
        return [], 0, tool_name
    except subprocess.TimeoutExpired:
        print(f"[-] {tool_name} command timed out after {timeout}s: {' '.join(command)}", file=sys.stderr)
        # Terminate and wait to avoid zombie processes
        try:
            process.kill()
            process.wait()
        except OSError: # Process might have already finished or couldn't be killed
             pass
        # Indicate timeout with the timeout value as elapsed time
        return [], timeout, tool_name
    except Exception as e:
        print(f"[-] An unexpected error occurred while running {tool_name} command '{' '.join(command)}': {e}", file=sys.stderr)
        # Indicate other errors with 0 elapsed time
        return [], 0, tool_name


def query_crtsh(domain, tool_name="crt.sh"):
    """
    Queries crt.sh for subdomains of a given domain using the API.
    Returns list of subdomains and tool name.

    Args:
        domain (str): The root domain to query.
        tool_name (str): The name "crt.sh" for consistent return format.

    Returns:
        tuple: A list of unique subdomain names (list of str), and the tool name (str).
               Returns ([], tool_name) on failure.
    """
    # URL for crt.sh API query, %25 is URL encoding for '%'
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set() # Use a set to automatically handle duplicates
    try:
        # crt.sh can sometimes return large responses, use a reasonable timeout
        # Also set a User-Agent as some servers block default requests UA
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SubdomainTakeoverScanner/1.0)'}
        # Verify SSL certs but set a higher timeout
        response = requests.get(url, timeout=45, headers=headers, verify=True) # Increased timeout slightly
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        # crt.sh might return an empty body or non-JSON on error/no results
        if not response.text.strip():
             # print(f"[-] crt.sh returned empty or whitespace response for {domain}", file=sys.stderr) # Too verbose
             return [], tool_name

        try:
            data = response.json()
            # crt.sh API returns a list even if empty
            if not isinstance(data, list):
                 print(f"[-] Unexpected response format from crt.sh for {domain}. Not a list.", file=sys.stderr)
                 return [], tool_name

        except requests.exceptions.JSONDecodeError:
            # Handle cases where response is not valid JSON
            print(f"[-] Failed to decode JSON from crt.sh for {domain}. Response starts with: {response.text[:100]}...", file=sys.stderr)
            return [], tool_name


        for entry in data:
            # 'name_value' contains the domain/subdomain name from the certificate
            name = entry.get('name_value')
            if name:
                 # Clean up potential extra whitespace or wildcards from crt.sh
                 name = name.strip().lstrip('*.')
                 # crt.sh might return the root domain or wildcard entries like *.domain.com
                 # We are primarily interested in specific subdomains.
                 # A simple check: ensure it ends with the target domain.
                 if name.endswith(f".{domain}") or name == domain:
                     subdomains.add(name)
                 # Optional: add other checks if you want to filter more (e.g., exclude *. entries)


    except requests.exceptions.RequestException as e:
        # Catch other potential requests errors during the API call
        print(f"[-] Error querying crt.sh for {domain}: {e}", file=sys.stderr)
        return [], tool_name
    except Exception as e:
        # Catch any other unexpected errors
        print(f"[-] An unexpected error occurred during crt.sh query for {domain}: {e}", file=sys.stderr)
        return [], tool_name


    # Convert set to list for consistent return type
    return list(subdomains), tool_name

def export_to_csv(results, filename="subdomains_takeover_status.csv"):
    """
    Exports the subdomain takeover detection results to a CSV file.

    Creates a CSV file with headers: 'subdomain', 'cname', 'service',
    'takeover_possible', and writes each result dictionary as a row.

    Args:
        results (list): A list of dictionaries, where each dictionary
                        represents the scan result for a subdomain.
                        Expected keys: 'subdomain', 'cname', 'service', 'takeover_possible'.
        filename (str): The name of the CSV file to export the results to.
                        Defaults to "subdomains_takeover_status.csv".
    """
    if not results:
        print("[+] No results to export.")
        return

    # Define the fieldnames for the CSV header - match the keys returned by check_single_subdomain
    fieldnames = ["subdomain", "cname", "service", "status_code", "takeover_possible"] # Include status_code in CSV

    try:
        # Use 'w' mode for writing, newline='' to prevent extra blank rows
        with open(filename, "w", newline="", encoding="utf-8") as csvfile:
            # Use DictWriter for easy writing from dictionaries
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Write the header row
            writer.writeheader()

            # Write the data rows
            for r in results:
                # Ensure all fieldnames are present in the dictionary to avoid errors
                # Provide default empty string for missing keys
                row_data = {fieldname: r.get(fieldname, "") for fieldname in fieldnames}
                writer.writerow(row_data)

        print(f"[+] Exported {len(results)} results to {filename}")
    except IOError as e:
        print(f"[-] Error writing to CSV file {filename}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[-] An unexpected error occurred during CSV export: {e}", file=sys.stderr)


# --- Main Execution Logic ---

def main():
    """
    Main function to parse command-line arguments, initiate the scan process
    (reconnaissance and takeover detection), and export the results.
    Orchestrates calls to recon and takeover modules.
    """
    parser = argparse.ArgumentParser(
        description="Subdomain Takeover Detection Script\n\n"
                    "This tool performs reconnaissance to find subdomains using Subfinder,\n"
                    "crt.sh, Assetfinder (in deep mode), and optionally AzSubEnum (if --azure-base\n"
                    "is provided). It then checks found subdomains concurrently for potential\n"
                    "subdomain takeover vulnerabilities using known fingerprints.\n"
                    "Results are categorized for clarity.",
        formatter_class=argparse.RawTextHelpFormatter # Helps preserve formatting in help text
    )
    # Define command-line arguments
    parser.add_argument(
        "--domain",
        help="Root domain to scan (e.g., example.com). Performs reconnaissance to find subdomains."
    )
    parser.add_argument(
        "--input",
        help="Input file containing a list of subdomains (one per line). Skips the reconnaissance phase."
    )
    # Added new optional argument for Azure base name
    parser.add_argument(
        "--azure-base",
        help="Optional: Base name for Azure enumeration (e.g., tenant name). "
             "Required for AzSubEnum. If not provided, AzSubEnum is skipped.",
    )
    parser.add_argument(
        "--depth",
        choices=["light", "medium", "heavy"],
        default="medium",
        help="Depth of reconnaissance when --domain is used (light, medium, heavy).\n(Note: Only '--mode' currently affects external tool execution in this script)."
    )
    parser.add_argument(
        "--mode",
        choices=["quick", "deep"],
        default="quick",
        help="Scanning mode. 'quick' (default) uses Subfinder + crt.sh.\n'deep' adds Assetfinder (requires Assetfinder installation)."
    )
    # Timeout arguments for external tools
    parser.add_argument(
        "--subfinder-timeout",
        type=int,
        default=120,
        help="Timeout in seconds for the Subfinder command (default: 120)."
    )
    parser.add_argument(
        "--assetfinder-timeout",
        type=int,
        default=180,
        help="Timeout in seconds for the Assetfinder command (default: 180)."
    )
    # Added timeout argument for AzSubEnum
    parser.add_argument(
        "--azure-enum-timeout",
        type=int,
        default=180, # Default timeout for AzSubEnum
        help="Timeout in seconds for the AzSubEnum command (default: 180)."
    )


    parser.add_argument(
        "--output",
        default="subdomains_takeover_status.csv",
        help="Output CSV filename for results (default: subdomains_takeover_status.csv)."
    )


    args = parser.parse_args()

    # Validate input: require either --domain or --input
    if not args.domain and not args.input:
        print("[-] Error: You must specify either --domain or --input\n", file=sys.stderr)
        parser.print_help()
        sys.exit(1) # Exit with an error code

    # Validate input file existence if --input is used
    if args.input and not os.path.exists(args.input):
        print(f"[-] Error: Input file '{args.input}' not found.", file=sys.stderr)
        sys.exit(1)

    # --- Import Recon and Takeover Modules ---
    # We import them here because they depend on some functions defined *above* in this file,
    # and main depends on functions *from* them. This avoids circular dependencies
    # at the top level if they were all importing each other.
    try:
        from recon2 import run_recon
        from takeover2 import detect_takeovers
    except ImportError as e:
        print(f"[-] Error importing required modules (recon.py or takeover.py): {e}", file=sys.stderr)
        print("[-] Please ensure recon.py and takeover.py are in the same directory as utils.py.", file=sys.stderr)
        sys.exit(1)


    total_start = time.time()
    subdomains = []

    # --- Subdomain Collection ---
    if args.domain:
        # Run reconnaissance if a root domain is provided
        print(f"[+] Target Domain: {args.domain}")
        subdomains = run_recon(
            domain=args.domain,
            mode=args.mode,
            subfinder_timeout=args.subfinder_timeout,
            assetfinder_timeout=args.assetfinder_timeout,
            azure_base=args.azure_base, # Pass the new argument
            azure_enum_timeout=args.azure_enum_timeout # Pass the new timeout
        )
    elif args.input:
        # Load subdomains from the input file
        print(f"[+] Loading subdomains from input file: {args.input}")
        try:
            with open(args.input, "r", encoding="utf-8") as f:
                subdomains = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(subdomains)} unique subdomains from input.")

            # If using --input with --azure-base, AzSubEnum can still run
            if args.azure_base:
                 print(f"[+] --input is used, but --azure-base '{args.azure_base}' is also provided. Running AzSubEnum separately.")
                 # AzSubEnum doesn't take a domain, only a base. Run it and add results.
                 # Need to check availability and run similarly to how it's done in run_recon.
                 azsubenum_available = False
                 try:
                     # Using check_output to verify python3 exists
                     subprocess.check_output(["python3", "-h"], stderr=subprocess.STDOUT)
                     # Assume azsubenum.py is accessible via PATH or executable directly
                     # If not, you'll need to provide the full path
                     # Check if the file itself exists if not in PATH
                     # import shutil
                     # if shutil.which("azsubenum.py") or os.path.exists("./azsubenum.py"): # Basic check
                     azsubenum_available = True # Basic check assumes accessible if python3 exists


                 except (subprocess.CalledProcessError, FileNotFoundError):
                      print("[-] python3 or azsubenum.py not found/accessible. Cannot run AzSubEnum with --input.", file=sys.stderr)
                      azsubenum_available = False

                 if azsubenum_available:
                     try:
                         print(f"[+] Running AzSubEnum with base '{args.azure_base}' and timeout {args.azure_enum_timeout}s...")
                         # Use run_command from this (utils) file
                         azsubenum_cmd = ["python3", "azsubenum.py", "-b", args.azure_base, "-t", "10"] # Use -t for threads in AzSubEnum
                         az_output, az_elapsed, _ = run_command(azsubenum_cmd, args.azure_enum_timeout, "AzSubEnum (Input Mode)")
                         print(f"[+] AzSubEnum (Input Mode) found {len(az_output)} subdomains in {az_elapsed:.2f}s.")
                         subdomains.extend(az_output)
                         # Deduplicate again after adding AzSubEnum results
                         initial_count = len(subdomains)
                         subdomains = list(set(subdomains))
                         print(f"[+] Deduplicated results after AzSubEnum: {len(subdomains)} unique subdomains.")

                     except Exception as e:
                         print(f"[-] Error running AzSubEnum in input mode: {e}", file=sys.stderr)


        except IOError as e:
            print(f"[-] Error reading input file {args.input}: {e}", file=sys.stderr)
            sys.exit(1)


    # Check if any subdomains were collected/loaded
    if not subdomains:
        print("[-] No subdomains to scan. Exiting.")
        sys.exit(0) # Exit cleanly if no subdomains

    # --- Subdomain Takeover Detection ---
    # Pass the collected/loaded subdomains to the detection function
    takeover_results, detection_time = detect_takeovers(subdomains)

    # --- Export Results ---
    export_to_csv(takeover_results, filename=args.output) # Call the utility function

    # --- Scan Summary ---
    total_time_elapsed = time.time() - total_start
    print("\n--- Scan Complete ---")
    print(f"Total Subdomains Processed for Detection: {len(takeover_results)}")

    # Count categorized results
    yes_count = sum(1 for r in takeover_results if r.get('takeover_possible') == 'YES')
    high_chance_count = sum(1 for r in takeover_results if r.get('takeover_possible') == 'HIGH CHANCE')
    low_chance_count = sum(1 for r in takeover_results if r.get('takeover_possible') == 'LOW CHANCE')
    no_count = sum(1 for r in takeover_results if r.get('takeover_possible') == 'NO')
    error_count = sum(1 for r in takeover_results if r.get('takeover_possible') == 'ERROR')

    # Potential takeovers are YES and HIGH CHANCE
    potential_takeovers_total = yes_count + high_chance_count


    print(f"\nSummary of Findings:")
    print(f"--------------------")
    print(f"Total Potential Takeovers (YES + HIGH CHANCE): {potential_takeovers_total}")
    print(f"  - Confirmed Vulnerable (YES): {yes_count}")
    print(f"  - Dangling CNAME (HIGH CHANCE): {high_chance_count}")
    print(f"Low Chance (No CNAME, Unreachable): {low_chance_count}")
    print(f"No Takeover Possible (No CNAME, Reachable): {no_count}")
    if error_count > 0:
         print(f"Scan Errors (Check logs/CSV for details): {error_count}")


    print(f"\nTiming:")
    print(f"---------")
    print(f"Total Scan Time: {total_time_elapsed:.2f} seconds")
    # Note: Estimating recon time is harder now with concurrent tools.
    # Just show total and detection time for clarity.
    print(f"  - Detection Time (Concurrent Checks): {detection_time:.2f} seconds")

    print(f"\nResults exported to: {args.output}")


# =============================================================================
# Script Entry Point
# This block ensures that the main() function is called when the script
# is executed directly.
# =============================================================================
if __name__ == "__main__":
    main()