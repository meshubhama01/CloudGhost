#!/usr/bin/env python3

# =============================================================================
# takeover.py - Subdomain Takeover Detection Logic
#
# Contains the fingerprint database, matching logic, individual subdomain
# checks, and orchestration for concurrent detection.
# =============================================================================

# Standard Library Imports
import sys
import re # Needed for body regex matching
import concurrent.futures # Needed for concurrent execution
import time

# Third-Party Imports (Ensure these are installed: pip install requests dnspython)
import requests # Needed for query_subdomain
import dns.resolver # Needed for get_cname_record


###############################################################################
# Fingerprint Database and Detection Logic
###############################################################################

# Database of CNAME fingerprints with specific detection indicators
# Streamlined to focus only on Azure, AWS, GitHub, and OCI.
# Each 'detect' entry contains conditions that indicate a potential takeover
# 'status': Expected HTTP status code (e.g., 404, 503). Use None to ignore status.
# 'body_match': String that must be present (case-insensitive) in the response body.
# 'body_regex': Regular expression that must match (case-insensitive) in the response body.
FINGERPRINT_DB = [
    # --- Azure Fingerprints ---
    {
        "cname": "azurewebsites.net",
        "service": "azure - Azure App Service",
        "detect": [
            {"status": 404, "body_match": "Web App is stopped."},
            {"status": 404, "body_match": "The resource you are looking for has been removed, had its name changed, or is temporarily unavailable."},
            {"status": 404, "body_match": "This domain is not configured for an Azure Website"},
            {"status": 404, "body_match": "Error 404 - Web app not found."},
        ]
    },
    {
        "cname": "azure-api.net",
        "service": "azure - API Management",
        "detect": [
            {"status": 404, "body_match": "Invalid ApiRegion."},
             {"status": 404, "body_match": "Page Not Found"}, # Common default 404
        ]
    },
    {
        "cname": "cloudapp.azure.com",
        "service": "azure - CloudApp",
         "detect": [
            {"status": 404, "body_match": "The resource you are looking for has been removed"},
             {"status": 404, "body_match": "Page Not Found"},
        ]
    },
     {
        "cname": "trafficmanager.net",
        "service": "azure - Traffic Manager",
         "detect": [
            {"status": 404, "body_match": "The resource you are looking for has been removed"},
             {"status": 404, "body_match": "Page Not Found"},
        ]
    },
    {
        "cname": "azureedge.net",
        "service": "azure - CDN/Azure Front Door",
         "detect": [
            {"status": 404, "body_match": "Page not found"},
             {"status": 404, "body_match": "The resource you are looking for has been removed"},
        ]
    },
     {
        "cname": "blob.core.windows.net",
        "service": "azure - Blob Storage",
         "detect": [
            {"status": 404, "body_match": "The specified bucket does not exist."},
            {"status": 404, "body_match": "NoSuchBucket"}, # Azure storage also uses S3 compatible APIs sometimes
            {"status": 409, "body_match": "The specified container already exists."}, # Indicates bucket name is taken
        ]
    },
     {
        "cname": "web.core.windows.net",
        "service": "azure - Static Web Apps",
         "detect": [
            {"status": 404, "body_match": "The resource you are looking for has been removed"},
             {"status": 404, "body_match": "Page Not Found"},
        ]
    },
     {
        "cname": "scm.azurewebsites.net",
        "service": "azure - Kudu SCM", # SCM/deployment dashboard
         "detect": [
            # Takeover here means gaining control of the deployment process
            # The indicator might be a default page or an error indicating no app is linked
            {"status": 404, "body_match": "The resource you are looking for has been removed"},
             {"status": 404, "body_match": "Page Not Found"},
        ]
    },
    {"cname": "database.windows.net", "service": "azure - SQL Database", "detect": [
        # Plausible indicators for SQL Database CNAME pointing to non-existent resource
        # These might be less common for non-web services but added based on general patterns
        {"status": 404, "body_match": "Database not found"},
        {"status": 404, "body_match": "The resource you are looking for has been removed"},
        {"status": 400, "body_match": "Invalid Database"},
    ]},
    {"cname": "documents.azure.com", "service": "azure - Cosmos DB", "detect": [
         # Plausible indicators for Cosmos DB
        {"status": 404, "body_match": "Database account not found"},
        {"status": 404, "body_match": "The resource you are looking for has been removed"},
         {"status": 400, "body_match": "Invalid resource"},
    ]},
    {"cname": "redis.cache.windows.net", "service": "azure - Redis Cache", "detect": [
        # Plausible indicators for Redis Cache
        {"status": 404, "body_match": "Cache not found"},
        {"status": 404, "body_match": "The resource you are looking for has been removed"},
         {"status": 400, "body_match": "Invalid Cache Name"},
    ]},
    {"cname": "vault.azure.net", "service": "azure - Key Vault", "detect": [
         # Plausible indicators for Key Vault
        {"status": 404, "body_match": "Vault not found"},
        {"status": 403, "body_match": "Forbidden"}, # Could be 403 if vault exists but access is denied
        {"status": 404, "body_match": "The resource you are looking for has been removed"},
         {"status": 400, "body_match": "Invalid Vault Name"},
    ]},
    {"cname": "search.windows.net", "service": "azure - Cognitive Search", "detect": [
         # Plausible indicators for Cognitive Search
        {"status": 404, "body_match": "Search service not found"},
        {"status": 404, "body_match": "The resource you are looking for has been removed"},
         {"status": 400, "body_match": "Invalid Search Service"},
    ]},
    {"cname": "microsoftcrmportals.com", "service": "azure - Dynamics CRM Portal", "detect": [
         # Plausible indicators for CRM Portal (more web-facing)
        {"status": 404, "body_match": "Portal not found"},
        {"status": 404, "body_match": "The resource you are looking for has been removed"},
        {"status": 404, "body_match": "Page Not Found"},
         {"status": 404, "body_match": "Website Home Page"}, # Default CRM portal 404 title/text
    ]},
    {"cname": "azurecontainer.io", "service": "azure - Container Apps", "detect": [
         # Plausible indicators for Container Apps (web-facing)
        {"status": 404, "body_match": "Container App not found"},
        {"status": 404, "body_match": "The resource you are looking for has been removed"},
        {"status": 404, "body_match": "Page Not Found"},
         {"status": 404, "body_match": "404 Not Found"},
    ]},
    {"cname": "azurefd.net", "service": "azure - Front Door", "detect": [
         {"status": 404, "body_match": "Page not found"},
         {"status": 404, "body_match": "The resource you are looking for has been removed"},
          {"status": 404, "body_match": "The requested URL was not found on the server."},
    ]},
    {"cname": "azure-devices.net", "service": "azure - IoT Hub", "detect": [
         # IoT Hub doesn't usually serve HTTP, but a dangling CNAME might
         # lead to a default Azure error or a different service if misconfigured.
         # Hard to define generic takeover indicators without HTTP response.
         # Leaving empty as per previous version, focuses on web-reachable services.
    ]},
    {"cname": "azurehdinsight.net", "service": "azure - HDInsight", "detect": [
         # Similar to IoT Hub, not primarily web-facing.
    ]},
    {"cname": "servicebus.windows.net", "service": "azure - Service Bus", "detect": [
         # Similar to IoT Hub, not primarily web-facing.
    ]},
    {"cname": "media.azure.net", "service": "azure - Media Services", "detect": [
         # May serve content, but specific takeover indicators might be complex.
         # Focusing on common web-facing ones.
    ]},
    {"cname": "centralus.cloudapp.azure.com", "service": "azure - Regional CloudApp", "detect": [
         {"status": 404, "body_match": "The resource you are looking for has been removed"},
         {"status": 404, "body_match": "Page Not Found"},
    ]},


    # --- AWS Fingerprints ---
    {
        "cname": "github.io", # Although github.io, often listed with cloud takeovers
        "service": "github - GitHub Pages",
        "detect": [
            {"status": 404, "body_match": "There isn't a GitHub Pages site here"},
            {"status": 404, "body_match": "Repository not found"},
            {"status": 404, "body_match": "github.io - Not Found"},
        ]
    },

    # --- AWS Fingerprints ---
    {
        "cname": "s3.amazonaws.com",
        "service": "aws - S3 Bucket",
        "detect": [
            {"status": 404, "body_match": "NoSuchBucket"},
            {"status": 403, "body_match": "AccessDenied"}, # Sometimes indicates a misconfigured bucket available for a different type of takeover
            {"status": 404, "body_regex": r"<Code>NoSuchBucket</Code>.*<Message>The specified bucket does not exist</Message>"}, # More specific XML match
        ]
    },
     {
        "cname": "s3-website", # Partial match for website endpoints like s3-website-us-east-1.amazonaws.com
        "service": "aws - S3 Website",
         "detect": [
            {"status": 404, "body_match": "NoSuchBucket"},
            {"status": 403, "body_match": "AccessDenied"},
            {"status": 404, "body_match": "Not Found"}, # Generic 404
            {"status": 404, "body_match": "The specified bucket does not exist."},
        ]
    },
     {
        "cname": "elasticbeanstalk.com",
        "service": "aws - Elastic Beanstalk",
         "detect": [
            # Common Elastic Beanstalk error pages
            {"status": 404, "body_match": "The resource you are looking for has been removed"},
             {"status": 404, "body_match": "Page Not Found"},
             {"status": 404, "body_match": "404 Not Found"},
        ]
    },
    # Add more AWS services...

    # --- OCI Fingerprints ---
    {
        "cname": "oci.oraclecloud.com",
        "service": "oci - Object Storage", # Represents broader OCI CNAMEs
         "detect": [
            {"status": 404, "body_match": "Not Found"},
            {"status": 404, "body_match": "The specified bucket does not exist."},
             {"status": 404, "body_match": "bucket not found"},
        ]
    },
     {
        "cname": "storage.oraclecloud.com",
        "service": "oci - Storage", # More specific storage pattern
         "detect": [
            {"status": 404, "body_match": "Not Found"},
             {"status": 404, "body_match": "The specified bucket does not exist."},
        ]
    },
    {
        "cname": "objectstorage.", # Partial match for objectstorage.<region>.oraclecloud.com
        "service": "oci - Bucket", # Represents regional object storage buckets
         "detect": [
            {"status": 404, "body_match": "Not Found"},
            {"status": 404, "body_match": "The specified bucket does not exist."},
        ]
    },
     # Add more OCI services...
]


def match_fingerprint(cname):
    """
    Matches the CNAME with the fingerprint database to find a service fingerprint.

    Iterates through the FINGERPRINT_DB and checks if any CNAME pattern
    from the database is present within the provided subdomain CNAME.

    Args:
        cname (str): The CNAME record string for a subdomain.

    Returns:
        dict or None: The matching fingerprint dictionary if found, otherwise None.
    """
    if not cname:
        return None
    # Convert CNAME to lowercase for case-insensitive matching
    cname_lower = cname.lower()
    for fp in FINGERPRINT_DB:
        # Check if the fingerprint CNAME is a substring of the actual CNAME
        # Use .get() for safety, though 'cname' key is expected
        if fp.get("cname", "").lower() in cname_lower:
            return fp # Return the entire fingerprint dictionary
    return None

def is_takeover_possible(fingerprint, cname, response_body, status_code):
    """
    Determines if a subdomain takeover is possible based on the matched
    fingerprint, CNAME, HTTP response body, and status code, using
    service-specific detection rules. This function specifically checks
    if the response matches the *defined vulnerable patterns* for a known service.

    Args:
        fingerprint (dict or None): The matched fingerprint dictionary for the subdomain,
                                    or None if no fingerprint matched.
        cname (str): The CNAME record string.
        response_body (str or None): The HTTP response body as a string, or None if unavailable/error.
        status_code (int or str): The HTTP status code (integer) or "Unavailable".

    Returns:
        bool: True if the response matches a specific takeover indicator defined
              in the fingerprint, False otherwise. Returns False if no fingerprint
              is provided or the service is unreachable or body is missing.
    """
    # Cannot match a specific pattern without a fingerprint, reachable service, and a body
    if not fingerprint or status_code == "Unavailable" or response_body is None:
        return False

    # Ensure status_code is treated as an integer if it's a number
    try:
        status_code_int = int(status_code)
    except (ValueError, TypeError):
        status_code_int = None # Not a valid integer status code

    response_body_lower = response_body.lower()

    # Iterate through the detection patterns defined in the fingerprint
    # Use .get() for safety in case 'detect' key is missing (shouldn't happen with current DB structure)
    for detect_pattern in fingerprint.get("detect", []):
        match_found_for_pattern = True # Assume match for this specific pattern until proven otherwise

        # Check status code if specified in the pattern
        # Only check if pattern has a status AND we have a valid integer status code
        if "status" in detect_pattern and detect_pattern["status"] is not None and status_code_int is not None:
            if status_code_int != detect_pattern["status"]:
                match_found_for_pattern = False # Status does not match this pattern's requirement
                # No need to check body if status doesn't match this pattern
                continue # Check next pattern if status is required and doesn't match


        # Check body match string if specified and previous conditions met
        # Only check if match_found_for_pattern is still True and pattern has body_match
        if match_found_for_pattern and "body_match" in detect_pattern and detect_pattern["body_match"] is not None:
            if detect_pattern["body_match"].lower() not in response_body_lower:
                 match_found_for_pattern = False # Body string not found
                 # No need to check regex if body_match is required and doesn't match
                 continue # Check next pattern if body_match is required and doesn't match

        # Check body regex if specified and previous conditions met
        # Only check if match_found_for_pattern is still True and pattern has body_regex
        if match_found_for_pattern and "body_regex" in detect_pattern and detect_pattern["body_regex"] is not None:
             try:
                 # Use re.search for partial matches anywhere in the body
                 # re.IGNORECASE makes the regex match case-insensitive
                 if not re.search(detect_pattern["body_regex"], response_body_lower, re.IGNORECASE): # Apply regex to lowercased body
                     match_found_for_pattern = False # Regex did not match
             except re.error as e:
                  # Print an error if the regex itself is invalid
                  print(f"[-] Invalid regex in fingerprint for {fingerprint.get('service', 'Unknown Service')}: {detect_pattern['body_regex']} - {e}", file=sys.stderr)
                  # Treat as no match for this pattern if regex is invalid
                  match_found_for_pattern = False


        # If all specified conditions for this specific pattern are met, a takeover is possible for THIS PATTERN
        if match_found_for_pattern:
            # We found at least one matching detection pattern for this service
            return True

    # If no detection patterns for this fingerprint matched the response details
    return False

def get_cname_record(subdomain):
    """
    Retrieves the CNAME record for a given subdomain using dns.resolver.

    Args:
        subdomain (str): The subdomain to query (e.g., "blog.example.com").

    Returns:
        str: The target of the CNAME record as a string (e.g., "example.github.io"),
             without the trailing dot. Returns an empty string if the subdomain
             has no CNAME record or if a DNS error occurs.
    """
    try:
        # Attempt to resolve the CNAME record
        # Setting a timeout for the DNS query
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5 # DNS query timeout in seconds
        resolver.lifetime = 5 # How long to wait for a response
        answers = resolver.resolve(subdomain, 'CNAME')
        # A subdomain can technically have multiple CNAMEs, but usually one relevant one.
        # We return the first one found.
        for rdata in answers:
            # Convert the DNS name object to a string and remove the trailing dot
            return str(rdata.target).rstrip('.')
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers) as e:
        # Catch common DNS errors (no CNAME, domain not found, timeout)
        # print(f"[-] DNS Error for {subdomain}: {type(e).__name__}", file=sys.stderr) # Uncomment for verbose DNS errors
        return "" # Return empty string if no CNAME or error
    except Exception as e:
        print(f"[-] An unexpected DNS error occurred for {subdomain}: {type(e).__name__} - {e}", file=sys.stderr)
        return ""


def query_subdomain(subdomain):
    """
    Sends HTTP/HTTPS requests to a subdomain and returns the response body and status code.

    Tries HTTPS first, then falls back to HTTP. Handles request errors.

    Args:
        subdomain (str): The subdomain to query (e.g., "blog.example.com").

    Returns:
        tuple: A tuple containing:
               - The response body as a string (or None on error).
               - The HTTP status code (integer) or "Unavailable".
               Returns (None, "Unavailable") if requests fail for both schemes.
    """
    # Try HTTPS first for security and common practice
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            # Use a reasonable timeout for HTTP requests
            # Allow redirects, as services might redirect to a different page
            # Set a User-Agent string to avoid potential blocking
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; SubdomainTakeoverScanner/1.0)'}
            response = requests.get(url, timeout=10, allow_redirects=True, headers=headers)
            # Decode response body, handling potential encoding issues
            try:
                # Use response.text which handles encoding automatically most of the time
                response_body = response.text
            except Exception as e:
                # print(f"[-] Could not decode response body for {url}: {e}", file=sys.stderr) # Too verbose
                response_body = None # Indicate body could not be read

            return response_body, response.status_code
        except requests.exceptions.ConnectionError:
            # Specific error for connection issues (DNS resolution failed, host unreachable, etc.)
            # print(f"[-] Connection error for {url}", file=sys.stderr) # Uncomment for verbose connection errors
            last_error = "ConnectionError"
            continue # Try the next scheme (HTTP if HTTPS failed)
        except requests.exceptions.Timeout:
            # Specific error for request timeout
            # print(f"[-] Timeout error for {url}", file=sys.stderr) # Uncomment for verbose timeout errors
            last_error = "Timeout"
            continue
        except requests.exceptions.RequestException as e:
            # Catch other potential requests errors (e.g., SSL errors, invalid URL)
            # print(f"[-] Request error for {url}: {e}", file=sys.stderr) # Uncomment for verbose request errors
            last_error = str(e)
            continue # Try the next scheme

    # If both HTTPS and HTTP requests failed
    return None, "Unavailable" # Indicate that the subdomain was unreachable


# --- Helper Function for Concurrent Checks with Categorization ---
def check_single_subdomain(subdomain):
    """
    Performs takeover detection checks for a single subdomain and categorizes the result
    into YES, HIGH CHANCE, LOW CHANCE, or NO based on CNAME and response.
    Designed to be run concurrently by a ThreadPoolExecutor.

    Args:
        subdomain (str): The subdomain to check.

    Returns:
        dict: A dictionary containing the results for the subdomain.
              Includes subdomain, cname, service, status_code,
              and takeover_possible (category string).
    """
    try:
        cname = get_cname_record(subdomain)
        matched_fingerprint = match_fingerprint(cname)
        # Determine service name based on matched fingerprint, default to "Unknown"
        service_name = matched_fingerprint["service"] if matched_fingerprint else "Unknown"

        # Query the subdomain over HTTP/S
        response_body, status_code = query_subdomain(subdomain) # status_code might be "Unavailable"

        takeover_possible_category = "NO" # Start with the default category

        # Determine the category based on the presence of CNAME and response characteristics
        # Using the refined logic:
        # 1. YES: CNAME exists AND matches a fingerprint AND specific vulnerable pattern matched
        # 2. HIGH CHANCE: CNAME exists AND it was NOT classified as YES (includes dangling CNAMEs to unfingerprinted services or fingerprinted services not showing known vuln patterns)
        # 3. LOW CHANCE: CNAME does NOT exist (empty string) AND status is "Unavailable".
        # 4. NO: CNAME does NOT exist (empty string) AND status is NOT "Unavailable" (i.e., is reachable via A/AAAA or similar).

        if cname: # CNAME record exists
            # Check for the most specific case: YES (known service, known vulnerable state)
            if matched_fingerprint and is_takeover_possible(matched_fingerprint, cname, response_body, status_code):
                takeover_possible_category = "YES"
            else:
                # CNAME exists, but not a confirmed YES -> It's a dangling CNAME
                takeover_possible_category = "HIGH CHANCE"
        else: # No CNAME record found
            # Check based on reachability if there's no CNAME
            if status_code == "Unavailable":
                takeover_possible_category = "LOW CHANCE"
            else:
                # No CNAME and status is available - means it's resolving via A/AAAA and is reachable
                takeover_possible_category = "NO"


        # Return all relevant data including the determined category
        return {
            "subdomain": subdomain,
            "cname": cname if cname else "N/A", # Store "N/A" if no CNAME found for clarity in output/CSV
            "service": service_name,
            "status_code": status_code, # Keep status code for potential debugging/analysis
            "takeover_possible": takeover_possible_category # Use the new category string
        }
    except Exception as e:
        # Catch any unexpected errors during the processing of this single subdomain
        # This helps prevent one bad subdomain from crashing the entire concurrent scan.
        print(f"[-] Error processing subdomain {subdomain}: {e}", file=sys.stderr)
        return {
            "subdomain": subdomain,
            "cname": "ERROR",
            "service": "Scan Error",
            "status_code": "ERROR",
            "takeover_possible": "ERROR" # Use ERROR category for exceptions
        }


def detect_takeovers(subdomains):
    """
    Detects possible subdomain takeovers for a list of subdomains using
    enhanced, service-specific fingerprint matching, executed concurrently
    using a ThreadPoolExecutor. Categorizes results as YES, HIGH CHANCE,
    LOW CHANCE, or NO.

    Args:
        subdomains (list): A list of subdomain strings to check.

    Returns:
        tuple: A tuple containing:
               - takeover_results (list): A list of dictionaries, each
                 containing the scan results for a subdomain.
               - detection_time (float): The total time spent on the detection process in seconds.
    """
    # List to store results for CSV export and final summary
    takeover_results = []
    total_subdomains = len(subdomains)

    print(f"[+] Starting takeover detection for {total_subdomains} subdomains using concurrent threads...")

    # Determine the number of worker threads for detection checks
    # Use a higher number for I/O-bound tasks (network requests)
    max_workers = 100

    detection_start_time = time.time() # Time only the detection phase

    # Use ThreadPoolExecutor for concurrent execution of checks
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit the check_single_subdomain task for each subdomain.
        future_to_subdomain = {executor.submit(check_single_subdomain, subdomain): subdomain for subdomain in subdomains}

        # Process results as they complete using as_completed
        completed_count = 0
        # as_completed yields Future objects as they finish
        for future in concurrent.futures.as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            completed_count += 1
            try:
                # Get the result from the completed Future.
                # check_single_subdomain is designed to return a dictionary even on error,
                # so we append its result directly.
                result = future.result()
                takeover_results.append(result) # Add the full result dictionary

                # Print progress and basic info for the completed subdomain
                # Use "N/A" for status/cname if they were "Unavailable" or empty/ERROR
                display_status = result.get('status_code', 'N/A')
                if display_status in ["Unavailable", "ERROR"]:
                    display_status = "N/A"
                display_cname = result.get('cname', 'N/A')
                if display_cname in ["", "ERROR", "N/A"]:
                     display_cname = "N/A"

                service_name = result.get('service', 'Unknown')
                takeover_category = result.get('takeover_possible', 'ERROR') # Get the category string


                # Print progress message with the category
                print(f"[{completed_count}/{total_subdomains}] Checked {subdomain} (Status: {display_status}, CNAME: {display_cname}, Service: {service_name}, Takeover: {takeover_category})")

            except Exception as exc:
                # This catches errors in retrieving the result from the future,
                # which is less common than errors within the submitted function itself.
                print(f"[-] An unexpected error occurred retrieving result for {subdomain}: {exc}", file=sys.stderr)
                # Add a fallback error result if somehow check_single_subdomain didn't return one
                # Check if a result was already added for this subdomain (unlikely with the internal try/except)
                if not any(r['subdomain'] == subdomain for r in takeover_results):
                     takeover_results.append({
                          "subdomain": subdomain,
                          "cname": "ERROR",
                          "service": "Scan Error",
                          "status_code": "ERROR",
                          "takeover_possible": "ERROR" # Ensure ERROR category is noted
                      })


    detection_time = time.time() - detection_start_time
    print(f"[+] Takeover detection complete.")

    # Return the collected results and detection time
    return takeover_results, detection_time

# Note: The FINGERPRINT_DB, match_fingerprint, is_takeover_possible,
# get_cname_record, query_subdomain, check_single_subdomain functions
# are all self-contained within this file.