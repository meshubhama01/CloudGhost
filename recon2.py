#!/usr/bin/env python3

# =============================================================================
# recon.py - Subdomain Reconnaissance Pipeline
#
# Handles running external tools (Subfinder, Assetfinder, AzSubEnum) and
# querying crt.sh concurrently to find subdomains.
# =============================================================================

# Standard Library Imports
import time
import sys
import subprocess # Needed for tool availability checks
import concurrent.futures # Needed for concurrent execution

# Import utility functions from utils.py
try:
    from utils2 import run_command, query_crtsh
except ImportError:
    print("[-] Error: Could not import run_command or query_crtsh from utils.py.", file=sys.stderr)
    print("[-] Please ensure utils.py is in the same directory as recon.py.", file=sys.stderr)
    sys.exit(1)


# --- Reconnaissance Functions ---

def run_recon(domain, mode="quick", subfinder_timeout=120, assetfinder_timeout=180, azure_base=None, azure_enum_timeout=180):
    """
    Performs subdomain reconnaissance on a given domain and optional Azure base name
    using multiple sources concurrently: Subfinder, Assetfinder (deep mode),
    crt.sh, and AzSubEnum (if azure_base is provided). Deduplicates results.

    Args:
        domain (str): The root domain to scan.
        mode (str): The scanning mode ('quick', 'deep'). 'deep' enables Assetfinder.
        subfinder_timeout (int): Timeout in seconds for the Subfinder command.
        assetfinder_timeout (int): Timeout in seconds for the Assetfinder command.
        azure_base (str, optional): Base name for Azure enumeration (e.g., tenant name).
                                    If provided, AzSubEnum will be run. Defaults to None.
        azure_enum_timeout (int): Timeout in seconds for the AzSubEnum command.

    Returns:
        list: A list of unique subdomains found through reconnaissance (list of str).
    """
    subdomains = set() # Use a set internally for efficient deduplication during collection
    print(f"[+] Starting reconnaissance for {domain} (Mode: {mode})...")

    # List to hold Future objects from concurrent tasks
    futures = []
    # Use a ThreadPoolExecutor specifically for running the recon tools concurrently
    # Set max_workers to the number of tools we *might* run + crt.sh
    max_recon_workers = 4 # Subfinder, Assetfinder, crt.sh, AzSubEnum

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_recon_workers) as executor:

        # --- Run Subfinder ---
        subfinder_available = False
        try:
            # Check if the command runs successfully (basic check)
            subprocess.check_output(["subfinder", "-h"], stderr=subprocess.STDOUT)
            subfinder_available = True
        except (subprocess.CalledProcessError, FileNotFoundError):
             print("[-] Subfinder not found or not in PATH. Skipping Subfinder scan.", file=sys.stderr)

        if subfinder_available:
            print("[+] Submitting Subfinder task...")
            subfinder_cmd = ["subfinder", "-d", domain, "-silent"]
            # Submit the task and add the future to the list
            futures.append(executor.submit(run_command, subfinder_cmd, subfinder_timeout, "Subfinder"))


        # --- Run Assetfinder (only in deep mode) ---
        assetfinder_available = False
        if mode == "deep":
             try:
                subprocess.check_output(["assetfinder", "-h"], stderr=subprocess.STDOUT)
                assetfinder_available = True
             except (subprocess.CalledProcessError, FileNotFoundError):
                  print("[-] Assetfinder not found or not in PATH. Skipping Assetfinder scan.", file=sys.stderr)

             if assetfinder_available:
                print("[+] Submitting Assetfinder task...")
                assetfinder_cmd = ["assetfinder", "--subs-only", domain]
                futures.append(executor.submit(run_command, assetfinder_cmd, assetfinder_timeout, "Assetfinder"))
             else:
                print("[+] Skipping Assetfinder (deep mode requested but tool not available).")
        else:
            print("[+] Skipping Assetfinder (quick mode).")


        # --- Query crt.sh ---
        # Querying crt.sh is an I/O-bound task, suitable for concurrency
        print("[+] Submitting crt.sh query task...")
        # query_crtsh is designed to return (result_list, tool_name)
        futures.append(executor.submit(query_crtsh, domain, "crt.sh"))


        # --- Run AzSubEnum (if azure_base is provided) ---
        azsubenum_available = False
        if azure_base:
             try:
                # Check if python3 exists and assume azsubenum.py is accessible
                # More robust check needed if azsubenum.py is not in PATH or executable
                subprocess.check_output(["python3", "-h"], stderr=subprocess.STDOUT)
                # This doesn't guarantee azsubenum.py is found/executable, but it's a start.
                # You may need more specific checks or require user to provide full path.
                azsubenum_available = True # Basic check


             except (subprocess.CalledProcessError, FileNotFoundError):
                 print("[-] python3 not found or not in PATH. Cannot run AzSubEnum.", file=sys.stderr)
                 azsubenum_available = False


             if azsubenum_available:
                 print(f"[+] Submitting AzSubEnum task for base '{azure_base}'...")
                 # Assuming azsubenum.py is executable and in PATH, or accessible.
                 # If not, adjust command, e.g.: ["python3", "/path/to/azsubenum.py", "-b", azure_base, "-t", "10"]
                 azsubenum_cmd = ["python3", "azsubenum.py", "-b", azure_base, "-t", "10"] # Use -t for threads in AzSubEnum
                 futures.append(executor.submit(run_command, azsubenum_cmd, azure_enum_timeout, "AzSubEnum"))
             else:
                 print("[+] Skipping AzSubEnum (--azure-base not provided or python3/script not accessible).")
        else:
            print("[+] Skipping AzSubEnum (--azure-base not provided).")


        # --- Collect Results from Concurrent Tasks ---
        print("[+] Waiting for reconnaissance tools to complete...")
        # Use as_completed to get results as they become available
        for future in concurrent.futures.as_completed(futures):
            tool_name = "Unknown Tool" # Default for error reporting
            try:
                # Results from run_command are (output_lines, elapsed_time, tool_name)
                # Results from query_crtsh are (output_list, tool_name)
                # Handle the different return formats and extract results
                result = future.result()

                if result and isinstance(result, tuple) and len(result) >= 2:
                    output_data = result[0] # This is the list of subdomains/lines
                    tool_name = result[-1] # The last item is the tool name

                    if isinstance(output_data, list):
                         # Add results to the set for automatic deduplication
                         subdomains.update(output_data)
                         # Progress for command line tools is printed by run_command
                         # query_crtsh prints its count, so don't re-print here

                    if len(result) == 3 and tool_name != "crt.sh": # Check if it's from run_command and not crt.sh
                         # run_command printed its stats, just update the set
                         pass # Already handled by subdomains.update()

                else:
                    print(f"[-] Received unexpected result format from a recon task: {result}", file=sys.stderr)

            except Exception as exc:
                # This catches errors from the future.result() call itself,
                # or issues processing the result format.
                # run_command and query_crtsh have internal try/except, but this is a fallback.
                print(f"[-] A reconnaissance task generated an exception during result retrieval ({tool_name}): {exc}", file=sys.stderr)


    # Convert set to list for final return
    final_subdomains_list = list(subdomains)
    print(f"[+] Reconnaissance complete for {domain}. Found {len(final_subdomains_list)} unique subdomains.")
    return final_subdomains_list

# Note: run_command and query_crtsh are now expected to be in utils.py