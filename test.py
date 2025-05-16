import requests
import time
import csv
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import RequestException, Timeout, TooManyRedirects, SSLError, ConnectionError, HTTPError
from urllib3.exceptions import InsecureRequestWarning
import warnings
from bs4 import BeautifulSoup
from urllib.parse import urlparse
# import whois # For WHOIS lookup - Temporarily removed due to system dependency
import dns.resolver # For DNS lookup
from ipwhois import IPWhois # For ASN lookup
# Corrected Import: Ensure only these exceptions are imported
from ipwhois.exceptions import ASNRegistryError, WhoisLookupError

# Suppress warnings for disabling SSL verification if used (use with caution!)
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

# --- Configuration ---
input_file = 'urls.txt'              # File containing your 7000 URLs, one per line
output_csv_file = 'url_check_results_complete_debug.csv' # Changed output name to avoid overwriting
max_url_check_threads = 20           # Reduced threads - try lower if still failing
max_osint_threads = 10               # Reduced threads - try lower if still failing
request_timeout = 30                 # Increased timeout - give requests more time
max_redirects = 30                   # maximum number of redirects to follow (requests handles this implicitly when allow_redirects=True)
retries = 3                          # Number of times to retry a failed request
retry_delay = 5                      # seconds to wait between retries upon error
verify_ssl = True                    # Set to False to ignore SSL certificate errors (use with caution!)

# --- OSINT Functions ---
def get_unique_domains(urls):
    """Extracts unique domains from a list of URLs."""
    domains = set()
    for url in urls:
        try:
            domain = urlparse(url).netloc
            if domain:
                # Remove port number if present
                if ':' in domain:
                    domain = domain.split(':')[0]
                domains.add(domain)
        except Exception as e:
            print(f"DEBUG: Error parsing URL {url} for domain extraction: {type(e).__name__} - {e}")
            pass # Ignore malformed URLs
    return list(domains)

def get_osint_for_domain(domain):
    """Fetches DNS (A, MX, NS), and ASN information for a domain."""
    osint_data = {
        'whois': 'WHOIS lookup skipped (requires system command).', # Updated message
        'dns_a': 'N/A',
        'dns_mx': 'N/A',
        'dns_ns': 'N/A',
        'asn': 'N/A'
    }

    # Simple check to avoid lookup on IPs or invalid domains
    if not isinstance(domain, str) or '.' not in domain or domain.lower() in ['localhost', '127.0.0.1']:
        print(f"DEBUG OSINT: Skipping OSINT for non-domain format or loopback '{domain}'.")
        # Handle private IPs explicitly for ASN check later if needed
        if re.match(r'^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})$', domain):
             osint_data['asn'] = "Private IP Address"
        return domain, osint_data

    print(f"DEBUG OSINT: Starting OSINT for {domain}")

    # WHOIS Lookup - REMOVED FOR NOW
    # try:
    #     w = whois.query(domain)
    #     if w:
    #         whois_info = f"Registrar: {getattr(w, 'registrar', 'N/A')}, Creation: {getattr(w, 'creation_date', 'N/A')}, Expiration: {getattr(w, 'expiration_date', 'N/A')}"
    #         if getattr(w, 'name_servers', None):
    #              whois_info += f", Name Servers: {', '.join(map(str, w.name_servers))}"
    #         osint_data['whois'] = whois_info
    #     else:
    #          osint_data['whois'] = "WHOIS data not found or private"
    #     print(f"DEBUG OSINT: WHOIS success for {domain}")
    # except Exception as e:
    #     osint_data['whois'] = f"WHOIS Error: {type(e).__name__} - {e}"
    #     print(f"DEBUG OSINT: WHOIS Error for {domain}: {e}")


    # DNS Lookups
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10 # Increased DNS timeout
        resolver.lifetime = 10

        # A Records
        try:
            a_records = [str(r) for r in resolver.resolve(domain, 'A')]
            osint_data['dns_a'] = ', '.join(a_records)
            print(f"DEBUG OSINT: DNS A success for {domain}: {osint_data['dns_a']}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
             osint_data['dns_a'] = f"No A records ({type(e).__name__})"
             print(f"DEBUG OSINT: DNS A no records for {domain}: {e}")
        except Exception as e:
            osint_data['dns_a'] = f"A Record Error: {type(e).__name__} - {e}"
            print(f"DEBUG OSINT: DNS A Error for {domain}: {e}")

        # MX Records
        try:
            mx_records = [f"{r.preference} {r.exchange}" for r in resolver.resolve(domain, 'MX')]
            osint_data['dns_mx'] = ', '.join(mx_records)
            print(f"DEBUG OSINT: DNS MX success for {domain}: {osint_data['dns_mx']}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
             osint_data['dns_mx'] = f"No MX records ({type(e).__name__})"
             print(f"DEBUG OSINT: DNS MX no records for {domain}: {e}")
        except Exception as e:
            osint_data['dns_mx'] = f"MX Record Error: {type(e).__name__} - {e}"
            print(f"DEBUG OSINT: DNS MX Error for {domain}: {e}")

        # NS Records
        try:
            ns_records = [str(r) for r in resolver.resolve(domain, 'NS')]
            osint_data['dns_ns'] = ', '.join(ns_records)
            print(f"DEBUG OSINT: DNS NS success for {domain}: {osint_data['dns_ns']}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
             osint_data['dns_ns'] = f"No NS records ({type(e).__name__})"
             print(f"DEBUG OSINT: DNS NS no records for {domain}: {e}")
        except Exception as e:
            osint_data['dns_ns'] = f"NS Record Error: {type(e).__name__} - {e}"
            print(f"DEBUG OSINT: DNS NS Error for {domain}: {e}")

    except Exception as e: # Catch resolver setup issues etc.
        dns_error_msg = f"DNS Resolver Setup Error: {type(e).__name__} - {e}"
        print(f"DEBUG OSINT: DNS Resolver Error for {domain}: {e}")
        # Apply this error unless a more specific DNS error was already captured
        if osint_data['dns_a'].startswith('N/A'): osint_data['dns_a'] = dns_error_msg
        if osint_data['dns_mx'].startswith('N/A'): osint_data['dns_mx'] = dns_error_msg
        if osint_data['dns_ns'].startswith('N/A'): osint_data['dns_ns'] = dns_error_msg


    # ASN Lookup (requires an IP address from A records)
    try:
        if osint_data['dns_a'] != 'N/A' and "No A records" not in osint_data['dns_a'] and "Error" not in osint_data['dns_a']:
            ip_address = osint_data['dns_a'].split(', ')[0] # Use the first IP
            try:
                obj = IPWhois(ip_address)
                # Corrected: Removed the timeout argument from lookup_whois for compatibility
                # The timeout for socket connections is handled by the IPWhois object's initialization (default is 5s)
                # Or you can pass it to the IPWhois constructor: obj = IPWhois(ip_address, timeout=10)
                results = obj.lookup_whois(get_asn_description=True, retry_count=1) # Removed timeout=15

                if results and results.get('asn'):
                    asn_info = f"ASN: {results['asn']}"
                    if results.get('asn_description'):
                         asn_info += f", Org: {results['asn_description']}"
                    if results.get('asn_date'):
                         asn_info += f", Date: {results['asn_date']}"
                    if results.get('asn_registry'):
                         asn_info += f", Registry: {results['asn_registry']}"
                    osint_data['asn'] = asn_info
                    print(f"DEBUG OSINT: ASN success for {ip_address}: {osint_data['asn']}")
                else:
                    osint_data['asn'] = "ASN data not found for IP"
                    print(f"DEBUG OSINT: ASN data not found for IP {ip_address}")

            # Corrected Exception Handling: Only catching existing ipwhois exceptions
            except (ASNRegistryError, WhoisLookupError) as e:
                 osint_data['asn'] = f'ASN Lookup Error: {type(e).__name__} - {e}'
                 print(f"DEBUG OSINT: ASN Lookup Error for {ip_address}: {e}")
            except Exception as e:
                 osint_data['asn'] = f'ASN Lookup Unexpected Error: {type(e).__name__} - {e}'
                 print(f"DEBUG OSINT: ASN Lookup Unexpected Error for {ip_address}: {e}")
        else:
             osint_data['asn'] = "Cannot lookup ASN without valid A record IP"
             # print(f"DEBUG OSINT: Skipping ASN for {domain} due to no valid IP") # Too verbose

    except Exception as e: # Catch IPWhois initialization errors etc.
        osint_data['asn'] = f"ASN Process Error: {type(e).__name__} - {e}"
        print(f"DEBUG OSINT: ASN Process Error for {domain}: {e}")

    print(f"DEBUG OSINT: Finished OSINT for {domain}")
    return domain, osint_data # Return domain with data for caching

# --- Authentication Indicator Function ---
def check_authentication_indicators(response_text, final_url, status_code):
    """Infers potential for authentication based on response content and status."""
    indicators = set() # Use a set to avoid duplicate indicators

    # Check status codes often associated with auth requirements
    if isinstance(status_code, int) and status_code in [401, 403]:
        indicators.add(f"Status Code {status_code}")

    # Check if final URL path or query suggests login
    if final_url:
        try:
            parsed_url = urlparse(final_url)
            path_and_query = (parsed_url.path + '?' + parsed_url.query).lower()
            if any(keyword in path_and_query for keyword in ['login', 'signin', 'auth', 'secure', 'account', 'admin', 'dashboard']):
                 indicators.add("URL Path/Query Keyword")
        except Exception:
             pass # Ignore URL parsing errors for this check

    # Check for common HTML elements related to login forms in response body (only if text/html)
    if response_text: # Check if we successfully got text content
        try:
            soup = BeautifulSoup(response_text, 'html.parser')

            # Look for form elements, especially with password fields
            if soup.find('form') and (soup.find('input', {'type': 'password'}) or soup.find('input', {'name': re.compile(r'pass|pwd', re.IGNORECASE)})):
                indicators.add("Contains Login Form")
            # Look for common login link/button text or form action keywords
            if soup.find(text=re.compile(r'\b(log ?in|sign ?in|authenticate|username|password|sign ?up|register)\b', re.IGNORECASE)) or \
               soup.find('form', {'action': re.compile(r'log ?in|sign ?in|auth', re.IGNORECASE)}):
                 indicators.add("Contains Login Text/Form Action")

        except Exception as e:
            # print(f"Warning: Could not parse HTML for auth indicators: {e}") # Too verbose
            pass # Ignore parsing errors for authentication indicators


    if indicators:
        return "Yes (" + ", ".join(sorted(list(indicators))) + ")"
    else:
        return "No Clear Indication"

# --- Helper Function to Fetch URL Details (incorporating Auth Check) ---
def fetch_url_details_with_auth(url, timeout, allow_redirects, max_redirects_config, verify_ssl, retries, retry_delay):
    """
    Fetches URL details with retry logic, checks auth indicators, handles errors/retries.
    Returns original_url, final_url, status_code, content_type, server_headers, page_title, auth_indicator, comment, response_text (for parsing auth).
    Note: max_redirects_config is the user's setting, but not passed directly to requests.get.
    """
    original_url = url
    final_url = None
    status_code = None
    content_type = None
    server_headers_str = ''
    page_title = ''
    auth_indicator = "Processing..."
    comment = ""
    response_text = None # To store text content for parsing

    # Ensure URL has a scheme, default to https if missing or invalid
    try:
        parsed = urlparse(original_url)
        if not parsed.scheme or parsed.scheme not in ['http', 'https']:
             # Attempt to fix scheme if missing or non-http/https
             original_url = 'https://' + urlparse(url).netloc + urlparse(url).path + urlparse(url).query + urlparse(url).fragment
             # Re-parse to validate the fixed URL
             re_parsed = urlparse(original_url)
             if not re_parsed.netloc: # If fixing didn't result in a valid netloc
                 comment = f"Error: Malformed URL (No hostname after scheme fix)"
                 print(f"DEBUG URL: Malformed URL (No hostname after fix): {url}")
                 return url, None, None, None, '', '', "Not Applicable (Malformed URL)", comment

             print(f"DEBUG URL: Corrected scheme for '{url}' to '{original_url}'")

        # Basic validation for hostname presence after potential fixing
        elif not parsed.netloc:
             comment = f"Error: Malformed URL (No hostname)"
             print(f"DEBUG URL: Malformed URL (No hostname): {url}")
             return url, None, None, None, '', '', "Not Applicable (Malformed URL)", comment

    except Exception as e:
         comment = f"Error: Malformed URL Parsing - {type(e).__name__} - {e}"
         print(f"DEBUG URL: Malformed URL Parsing Error for '{url}': {e}")
         return url, None, None, None, '', '', "Not Applicable (Malformed URL)", comment


    for attempt in range(retries + 1):
        print(f"DEBUG URL: Attempt {attempt + 1}/{retries + 1} for {original_url}")
        try:
            # Use stream=True and limit content read to avoid memory issues with large files
            response = requests.get(
                original_url, # Use original_url here after scheme check/fix
                timeout=timeout,
                allow_redirects=allow_redirects, # This is the correct argument name
                # Removed: max_redirects=max_redirects, # This argument is not supported by requests.get
                verify=verify_ssl,
                 # Added headers for better acceptance of content types
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                         'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/;q=0.8'},
                 stream=True # Use stream to avoid downloading large files fully unless needed
            )
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            final_url = response.url
            status_code = response.status_code
            content_type = response.headers.get('Content-Type', '').lower()

            # Store relevant headers (convert to string for CSV)
            relevant_headers = {k: v for k, v in response.headers.items() if k.lower() in ['server', 'x-powered-by', 'content-security-policy', 'strict-transport-security', 'www-authenticate', 'location', 'set-cookie']}
            server_headers_str = str(relevant_headers)

            # Only download content if it's likely HTML or we need it for auth check/title
            if 'text/html' in content_type or content_type.startswith('text/'):
                 try:
                     # Read and decode a limited portion of the content
                     response_text = response.content[:1024*200].decode('utf-8', errors='ignore') # Read max 200KB
                 except Exception as e:
                     print(f"DEBUG URL: Error reading content for {original_url}: {type(e).__name__} - {e}")
                     response_text = None # Cannot parse if content reading failed

                 # Try to parse HTML title if content type is HTML and content is available
                 if response_text: # Only try if content was successfully read
                      try:
                         soup = BeautifulSoup(response_text, 'html.parser')
                         page_title = soup.title.string.strip() if soup.title and soup.title.string else ''
                         # print(f"DEBUG URL: Parsed title for {original_url}: {page_title[:50]}...") # Print first 50 chars # Too verbose

                      except Exception as e:
                         print(f"DEBUG URL: Error parsing title for {original_url}: {type(e).__name__} - {e}")
                         page_title = f"Error parsing title: {type(e).__name__}"

            else:
                 response_text = None # Don't parse non-text content
                 # print(f"DEBUG URL: Not text/html content for parsing for {original_url}. Type: {content_type}") # Too verbose

            response.close() # Ensure the connection is closed

            # Determine initial comment
            comment = "Success"
            # Check authentication indicators AFTER getting status and content
            auth_indicator = check_authentication_indicators(response_text, final_url, status_code)
            print(f"DEBUG URL: Auth indicator for {original_url}: {auth_indicator}")


            print(f"DEBUG URL: Success for {original_url} -> {final_url} Status: {status_code}")
            return original_url, final_url, status_code, content_type, server_headers_str, page_title, auth_indicator, comment

        except TooManyRedirects:
            comment = f"Error: Too many redirects ({max_redirects_config})" # Use config value for comment
            auth_indicator = "Not Applicable (Error)"
            print(f"DEBUG URL: Too many redirects for {original_url}")
            break
        except Timeout:
            comment = f"Error: Timeout after {timeout} seconds"
            if attempt < retries:
                print(f"DEBUG URL: Timeout for {original_url}, attempt {attempt + 1}/{retries + 1}. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                continue
            comment = f"Error: Timeout after {retries + 1} attempts"
            auth_indicator = "Not Applicable (Error)"
            print(f"DEBUG URL: Final Timeout for {original_url}")
            break
        except SSLError as e:
             comment = f"Error: SSL/TLS issue - {type(e).__name__} - {e}"
             print(f"DEBUG URL: SSL Error for {original_url}: {e}")
             if attempt < retries and not verify_ssl: # Retry SSL errors only if verify_ssl is False
                 print(f"DEBUG URL: SSL Error (verify=False), attempt {attempt + 1}/{retries + 1}. Retrying in {retry_delay}s...")
                 time.sleep(retry_delay)
                 continue
             comment = f"Error: SSL/TLS issue after {retries + 1} attempts or SSL verification enabled - {type(e).__name__} - {e}"
             auth_indicator = "Not Applicable (Error)"
             break
        except ConnectionError as e:
             comment = f"Error: Connection Error - {type(e).__name__} - {e}"
             print(f"DEBUG URL: Connection Error for {original_url}: {e}")
             if attempt < retries:
                print(f"DEBUG URL: Connection Error for {original_url}, attempt {attempt + 1}/{retries + 1}. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                continue
             comment = f"Error: Connection Error after {retries + 1} attempts - {type(e).__name__} - {e}"
             auth_indicator = "Not Applicable (Error)"
             break
        except requests.exceptions.HTTPError as e:
             status_code = e.response.status_code
             comment = f"Error: HTTP Status {status_code}"
             print(f"DEBUG URL: HTTP Error for {original_url}: {e}")
             final_url = getattr(e.response, 'url', original_url) # Capture final URL even on error if available
             content_type = getattr(e.response.headers, 'Content-Type', '').lower() # Capture content type

             # Try to get relevant headers even from error response
             server_headers_str = str({k: v for k, v in getattr(e.response.headers, 'items', lambda: [])() if k.lower() in ['server', 'x-powered-by', 'content-security-policy', 'strict-transport-security', 'www-authenticate', 'location', 'set-cookie']})


             # Still try to get auth indicators based on status/url and maybe limited error page content
             error_response_text = None
             try:
                 # Try reading a small portion of the error page content
                 error_response_text = e.response.content[:1024*5].decode('utf-8', errors='ignore')
             except Exception:
                 pass # Ignore errors reading error page content
             auth_indicator = check_authentication_indicators(error_response_text, final_url, status_code)
             # No need to retry on client/server errors typically
             break
        except RequestException as e:
            comment = f"Error: Request failed - {type(e).__name__} - {e}"
            print(f"DEBUG URL: Request Error for {original_url}: {e}")
            if attempt < retries:
                print(f"DEBUG URL: Request Error for {original_url}, attempt {attempt + 1}/{retries + 1}. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                continue
            comment = f"Error: Request failed after {retries + 1} attempts - {type(e).__name__} - {e}"
            auth_indicator = "Not Applicable (Error)"
            break
        except Exception as e:
            comment = f"Error: Unexpected error during request - {type(e).__name__} - {e}"
            auth_indicator = "Not Applicable (Error)"
            print(f"DEBUG URL: Unexpected Error for {original_url}: {e}")
            break

    # If the loop finishes without success after retries
    # Ensure auth_indicator is set if it was still "Processing..."
    if auth_indicator == "Processing...":
         auth_indicator = "Not Applicable (Processing Error)"

    print(f"DEBUG URL: Finished processing {original_url}. Comment: {comment}")
    # Ensure required fields are not None for CSV writing if errors occurred early
    final_url = final_url if final_url is not None else ''
    status_code = status_code if status_code is not None else ''
    content_type = content_type if content_type is not None else ''
    page_title = page_title if page_title is not None else ''
    server_headers_str = server_headers_str if server_headers_str is not None else ''


    return original_url, final_url, status_code, content_type, server_headers_str, page_title, auth_indicator, comment


# --- Main part of the script ---
processed_scannable_final_urls = set() # Set to track unique *final URLs* classified as scannable
results_data = [] # List to store all row data

# CSV Header - Including all requested columns
header = [
    'Input URL',
    'Final URL (after redirects)',
    'Final Status Code',
    'Comment', # Overall classification
    'Final Content Type',
    'Page Title',
    'Relevant Headers',
    'Authentication Indicated', # New column
    'WHOIS Info',              # New column
    'DNS Records (A)',         # New column
    'DNS Records (MX)',        # New column
    'DNS Records (NS)',        # New column
    'ASN Info'                 # New column
]
results_data.append(header)

try:
    with open(input_file, 'r', encoding='utf-8') as f:
        urls_to_check = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    print(f"Error: Input file '{input_file}' not found.")
    exit()
except Exception as e:
    print(f"Error reading input file: {type(e).__name__} - {e}")
    exit()


print(f"Read {len(urls_to_check)} URLs from '{input_file}'.")

# --- Step 1: Get unique domains ---
unique_domains = get_unique_domains(urls_to_check)
print(f"Identified {len(unique_domains)} unique domains.")

# --- Step 2: Fetch OSINT data for unique domains ---
print(f"Fetching OSINT data for {len(unique_domains)} unique domains with {max_osint_threads} threads...")
osint_cache = {} # Cache to store fetched OSINT data {domain: osint_dict}

# Use ThreadPoolExecutor for concurrent OSINT lookups
# Limit workers to the number of domains if fewer than max_osint_threads
with ThreadPoolExecutor(max_workers=min(len(unique_domains), max_osint_threads or 1)) as executor:
    # Submit OSINT tasks to the executor
    future_to_domain = {executor.submit(get_osint_for_domain, domain): domain for domain in unique_domains}

    # Process OSINT results as they complete
    for i, future in enumerate(as_completed(future_to_domain)):
        domain = future_to_domain[future]
        # print(f"Fetching OSINT for {i + 1}/{len(unique_domains)}: {domain}...", end='\r') # Progress for OSINT

        try:
            domain_result, osint_data = future.result()
            osint_cache[domain_result] = osint_data
        except Exception as e:
            print(f"\nError processing OSINT future for {domain}: {type(e).__name__} - {e}")
            # Store an error placeholder in the cache
            osint_cache[domain] = {
                 'whois': f'OSINT Future Error: {type(e).__name__} - {e}', 'dns_a': 'N/A', 'dns_mx': 'N/A',
                 'dns_ns': 'N/A', 'asn': 'N/A'
            }
    # print("\nOSINT data fetching complete.") # Final message after OSINT

print("\nOSINT data fetching complete.")
print(f"Starting URL details check for {len(urls_to_check)} URLs with {max_url_check_threads} threads...")

# --- Step 3: Check URL details and combine with OSINT ---
# Use a separate ThreadPoolExecutor for URL checks
with ThreadPoolExecutor(max_workers=max_url_check_threads) as executor:
    # Submit URL check tasks
    future_to_url = {
        executor.submit(
            fetch_url_details_with_auth,
            url,
            request_timeout,
            True, # allow_redirects
            max_redirects, # Pass the config value for comment only
            verify_ssl,
            retries,
            retry_delay
        ): url for url in urls_to_check
    }

    for i, future in enumerate(as_completed(future_to_url)):
        original_url = future_to_url[future]
        # print(f"Processing URL {i + 1}/{len(urls_to_check)}: {original_url}...", end='\r') # Progress for URL checks

        try:
            original_url, final_url, status_code, content_type, server_headers_str, page_title, auth_indicator, comment = future.result()

            # Determine the final classification comment
            final_comment = comment # Start with comment from fetch function

            if final_comment == "Success":
                if isinstance(status_code, int) and 200 <= status_code < 300:
                    if 'text/html' in content_type or 'application/xhtml+xml' in content_type:
                        # Check for duplicate final URLs *among the scannable ones*
                        if final_url in processed_scannable_final_urls:
                            final_comment = "Duplicate (Final URL)"
                        else:
                            final_comment = "Potential Scannable Website" # Classified as Scannable after adding unique to set
                            processed_scannable_final_urls.add(final_url) # Add to set only if initially looks scannable and unique
                    # Optional: Add logic for other content types if needed (e.g., APIs)
                    # elif 'application/json' in content_type:
                    #     final_comment = "Potential API Endpoint"
                    else:
                         final_comment = "Not Scannable (Non-HTML Content)"

                elif isinstance(status_code, int):
                     final_comment = f"Not Scannable (Status Code: {status_code})"
                else:
                     final_comment = f"Unknown Status Issue: {status_code}"
            # else: The comment from fetch_url_details (e.g., Error, Timeout) is already set

            # --- Get OSINT data for the domain of the FINAL URL ---
            osint_info = {'whois': 'WHOIS lookup skipped (requires system command).', 'dns_a': 'N/A', 'dns_mx': 'N/A', 'dns_ns': 'N/A', 'asn': 'N/A'} # Default with skipped WHOIS
            domain_for_osint = None

            if final_url:
                try:
                    parsed_final_url = urlparse(final_url)
                    domain_for_osint = parsed_final_url.netloc
                     # Remove port number if present
                    if ':' in domain_for_osint:
                        domain_for_osint = domain_for_osint.split(':')[0]
                except Exception:
                     print(f"DEBUG OSINT: Error parsing final URL '{final_url}' for domain.")
                     domain_for_osint = None # Cannot get domain from final URL

            # If final URL failed or parsing failed, try original URL's domain
            if not domain_for_osint:
                try:
                      parsed_original_url = urlparse(original_url)
                      domain_for_osint = parsed_original_url.netloc
                      if ':' in domain_for_osint:
                           domain_for_osint = domain_for_osint.split(':')[0]
                except Exception:
                      print(f"DEBUG OSINT: Error parsing original URL '{original_url}' for domain.")
                      domain_for_osint = None # Cannot get domain from original URL

            if domain_for_osint:
                 # Retrieve OSINT data from the cache using the domain
                 osint_info = osint_cache.get(domain_for_osint, {
                      'whois': f'OSINT Cache Miss or Error for "{domain_for_osint}".', # Updated message
                      'dns_a': 'N/A', 'dns_mx': 'N/A', 'dns_ns': 'N/A', 'asn': 'N/A'
                 })
                 # Explicitly set WHOIS skipped message if it's still default from cache
                 if osint_info.get('whois', 'N/A') == 'WHOIS lookup skipped (requires system command).':
                     pass # Keep the skipped message
                 elif osint_info.get('whois', 'N/A').startswith('OSINT Cache Miss'):
                     # If there was a cache miss for OSINT but OSINT ran for this domain, get the actual result
                     # This might happen if domain extraction differs between initial unique list and final URL domain
                     # Re-running OSINT here would defeat caching, so rely on the initial cache or the skipped message.
                     # The initial OSINT run covers all unique domains from input URLs.
                     # If the final URL's domain wasn't in the input URLs, its OSINT won't be in cache.
                     # In this case, the default 'OSINT Cache Miss or Error' is appropriate.
                      pass # Keep the cache miss message
                 else:
                      # If OSINT was actually attempted and got a result (or error), use that
                      pass # Use the cached OSINT info


            # Append the processed data row to results_data
            results_data.append([
                original_url,
                final_url if final_url else '',
                status_code if status_code is not None else '',
                final_comment,
                content_type if content_type is not None else '',
                page_title if page_title is not None else '',
                server_headers_str if server_headers_str is not None else '',
                auth_indicator,
                osint_info.get('whois', 'N/A'), # Use .get for safety
                osint_info.get('dns_a', 'N/A'),
                osint_info.get('dns_mx', 'N/A'),
                osint_info.get('dns_ns', 'N/A'),
                osint_info.get('asn', 'N/A')
            ])

        except Exception as e:
            # This catches errors from the thread execution itself
            print(f"\nError processing future for {original_url}: {type(e).__name__} - {e}")
            results_data.append([
                original_url, '', '', f"Processing Error (Thread): {type(e).__name__} - {e}", '', '', '', '', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A' # Add N/A for OSINT columns
            ])

        # print(f"Completed URL {i + 1}/{len(urls_to_check)}...", end='\r') # Progress bar for URL checks


# Print final counts
print("\nProcessing complete.")
print(f"Analyzed {len(urls_to_check)} URLs.")
print(f"Identified {len(processed_scannable_final_urls)} unique potential scannable websites.")

# Save the results to a CSV file
try:
    with open(output_csv_file, 'w', newline='', encoding='utf-8') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerows(results_data)
    print(f"Analysis results saved to '{output_csv_file}'.")
except IOError as e:
    print(f"Error writing to CSV file: {type(e).__name__} - {e}")