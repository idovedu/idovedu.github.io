import argparse
import json
import os
import subprocess
import sys
import socket
import requests
import re
import signal
import logging
from urllib.parse import urlparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

def setup_logging(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    log_file = os.path.join(output_dir, 'recon.log')
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger()

def install_dependencies():
    try:
        import colorama
    except ImportError:
        logging.info("Installing colorama...")
        subprocess.run([sys.executable, "-m", "pip", "install", "colorama"], check=True)
    try:
        import requests
    except ImportError:
        logging.info("Installing requests...")
        subprocess.run([sys.executable, "-m", "pip", "install", "requests"], check=True)
    from colorama import init, Fore, Style
    init(autoreset=True)
    return Fore, Style

Fore, Style = install_dependencies()

def parse_arguments():
    parser = argparse.ArgumentParser(description="CyberSift - Advanced reconnaissance tool for Red Team operations")
    parser.add_argument('-i', action='store_true', help='Install tools')
    parser.add_argument('-u', action='store_true', help='Update tools')
    parser.add_argument('-p', type=str, default='socks5://127.0.0.1:1080', help='Custom proxy address')
    parser.add_argument('-np', action='store_true', help='Disable proxy')
    parser.add_argument('-m', action='store_true', help='Low memory mode')
    parser.add_argument('-r', type=int, default=50, help='Maximum report lines')
    parser.add_argument('-n', action='store_true', help='Skip internet check')
    parser.add_argument('-c', action='store_true', help='Enable colored output')
    parser.add_argument('-f', type=str, default='domain.txt', help='Domain file')
    parser.add_argument('-o', type=str, default='recon_results', help='Output directory')
    parser.add_argument('-w', type=str, default='wordlist-for-check-vulnerability.txt', help='Wordlist file for sensitive URLs')
    parser.add_argument('-t', type=int, default=10, help='Number of threads')
    return parser.parse_args()

args = parse_arguments()
logger = setup_logging(args.o)

def signal_handler(sig, frame):
    logger.warning("Ctrl+C pressed!")
    confirm = input("Do you really want to exit? (y/N): ").strip().lower()
    if confirm == 'y':
        logger.info("Exiting program...")
        sys.exit(0)
    else:
        logger.info("Continuing execution...")

signal.signal(signal.SIGINT, signal_handler)

def log(message, color=''):
    logger.info(message)
    if args.c:
        print(f"{color}{message}{Style.RESET_ALL}")
    else:
        print(message)

def test_internet():
    if args.n:
        log("Skipping internet check as requested")
        return True
    try:
        socket.create_connection(("google.com", 80), timeout=5)
        log("Internet connection verified")
        return True
    except OSError as e:
        log(f"No internet connection: {e}", color=Fore.RED)
        return False

def test_command(command):
    try:
        if os.name == 'nt':
            result = subprocess.run(['where', command], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                cmd_path = result.stdout.strip().split('\n')[0]
                version_result = subprocess.run([cmd_path, '--version'], capture_output=True, text=True)
                if version_result.returncode == 0:
                    log(f"Command {command} found at {cmd_path}")
                    return True
        else:
            result = subprocess.run(['which', command], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                cmd_path = result.stdout.strip()
                version_result = subprocess.run([cmd_path, '--version'], capture_output=True, text=True)
                if version_result.returncode == 0:
                    log(f"Command {command} found at {cmd_path}")
                    return True
        return False
    except Exception:
        return False

def load_config():
    config_path = os.path.join(os.getcwd(), 'cybersift/recon-config.json')
    default_config = {'LastNucleiUpdate': '1970-01-01T00:00:00Z', 'InstalledTools': {}}
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    else:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(default_config, f)
        return default_config

def save_config(config):
    config_path = os.path.join(os.getcwd(), 'cybersift/recon-config.json')
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f)

config = load_config()

def strip_ansi_codes(text):
    ansi_regex = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_regex.sub('', text)

def download_subdomain_wordlists(wordlist_dir):
    os.makedirs(wordlist_dir, exist_ok=True)
    wordlists = [
        {'name': 'subdomains-top1million-5000.txt', 'url': 'https://idovedu.github.io/cybersift/wordlists/subdomains-top1million-5000.txt'}
    ]
    downloaded = False
    for wordlist in wordlists:
        wordlist_path = os.path.join(wordlist_dir, wordlist['name'])
        if not os.path.exists(wordlist_path):
            log(f"Downloading {wordlist['name']}...")
            try:
                response = requests.get(wordlist['url'], timeout=10)
                if response.status_code == 200:
                    with open(wordlist_path, 'w', encoding='utf-8') as f:
                        f.write(response.text)
                    log(f"Downloaded {wordlist['name']} to {wordlist_path}")
                    downloaded = True
                else:
                    log(f"Failed to download {wordlist['name']}: Status {response.status_code}", color=Fore.YELLOW)
            except Exception as e:
                log(f"Error downloading {wordlist['name']}: {e}", color=Fore.YELLOW)
    
    default_wordlist_path = os.path.join(wordlist_dir, 'default-subdomains.txt')
    default_subdomains = ['www', 'mail', 'ftp', 'admin', 'login', 'api', 'test', 'dev', 'staging', 'beta']
    if not os.path.exists(default_wordlist_path):
        try:
            with open(default_wordlist_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(default_subdomains) + '\n')
            log(f"Created default wordlist at {default_wordlist_path}")
        except Exception as e:
            log(f"Failed to create default wordlist: {e}", color=Fore.RED)
    else:
        log(f"Default wordlist already exists at {default_wordlist_path}")

def update_wordlist(wordlist_file):
    additional_words = [
        'config.yml', 'backup.tar', 'admin-console', 'api/v3', 'graphql/v2', 'settings.yaml',
        'db.backup', 'auth.json', 'control-panel', 'upload-dir', 'file-upload', 'api-token'
    ]
    existing_words = set()
    if os.path.exists(wordlist_file):
        with open(wordlist_file, 'r', encoding='utf-8') as f:
            existing_words = set(line.strip() for line in f if line.strip())
    existing_words.update(additional_words)
    with open(wordlist_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(existing_words)) + '\n')
    log(f"Updated {wordlist_file} with {len(existing_words)} entries")

def create_input_files(domain_file, wordlist_file):
    if not os.path.exists(domain_file):
        with open(domain_file, 'w', encoding='utf-8') as f:
            f.write("example.com\n")
        log(f"Created {domain_file}")
    
    if not os.path.exists(wordlist_file):
        wordlist_url = 'https://idovedu.github.io/cybersift/wordlists/wordlist-for-check-vulnerability.txt'
        log(f"Downloading {wordlist_file} from {wordlist_url}...")
        try:
            response = requests.get(wordlist_url, timeout=10)
            if response.status_code == 200:
                with open(wordlist_file, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                log(f"Downloaded {wordlist_file}")
            else:
                log(f"Failed to download {wordlist_file}: Status {response.status_code}", color=Fore.YELLOW)
                sample_wordlist = [
                    '.bak', '.config', '.db', '.env', '.git', '.sql', '.asp', '.aspx', '.html', '.js', 
                    '.php', '.tar', '.txt', '.zip', '.yaml', '.yml', '.conf', '.log', '.swp', '.old', 
                    '.backup', '.tar.gz', '.zip.bak', 'account', 'admin', 'admin-login', 'adminpanel', 
                    'api', 'api/v1', 'api/v2', 'api_key', 'apikey', 'assetsmanager', 'auth', 'backup', 
                    'backup.sql', 'browse', 'bucket', 'ckeditor', 'cmd', 'conf', 'config', 'config.json', 
                    'config.bak', 'connectors', 'console', 'control', 'controlpanel', 'crm', 'dashboard', 
                    'database', 'db.sql', 'data.json', 'debug', 'dev', 'editor', 'env', 'fckeditor', 
                    'filemanager', 'fileupload', 'git', 'graphql', 'graphql/v1', 'internal', 'json', 
                    'key', 'login', 'login.php', 'login.aspx', 'mail', 'manage', 'panel', 'phpinfo', 
                    'portal', 'private', 'profile', 'register', 'rest', 'api/rest', 's3', 'secret', 
                    'secure', 'server', 'settings', 'settings.json', 'signin', 'signup', 'staging', 
                    'swagger', 'test', 'tinemc', 'tiny', 'token', 'upload', 'upload.php', 'uploadfile', 
                    'user', 'wp-admin', 'xml', 'admin.php', 'auth.php', 'admin/dashboard', 'backup.zip',
                    'config.yml', 'backup.tar', 'admin-console', 'api/v3', 'graphql/v2', 'settings.yaml',
                    'db.backup', 'auth.json', 'control-panel', 'upload-dir', 'file-upload', 'api-token'
                ]
                with open(wordlist_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(sorted(set(sample_wordlist))) + '\n')
                log(f"Created {wordlist_file} with {len(sample_wordlist)} sample entries")
        except Exception as e:
            log(f"Error downloading {wordlist_file}: {e}", color=Fore.YELLOW)
            sample_wordlist = [
                '.bak', '.config', '.db', '.env', '.git', '.sql', '.asp', '.aspx', '.html', '.js', 
                '.php', '.tar', '.txt', '.zip', '.yaml', '.yml', '.conf', '.log', '.swp', '.old', 
                '.backup', '.tar.gz', '.zip.bak', 'account', 'admin', 'admin-login', 'adminpanel', 
                'api', 'api/v1', 'api/v2', 'api_key', 'apikey', 'assetsmanager', 'auth', 'backup', 
                'backup.sql', 'browse', 'bucket', 'ckeditor', 'cmd', 'conf', 'config', 'config.json', 
                'config.bak', 'connectors', 'console', 'control', 'controlpanel', 'crm', 'dashboard', 
                'database', 'db.sql', 'data.json', 'debug', 'dev', 'editor', 'env', 'fckeditor', 
                'filemanager', 'fileupload', 'git', 'graphql', 'graphql/v1', 'internal', 'json', 
                'key', 'login', 'login.php', 'login.aspx', 'mail', 'manage', 'panel', 'phpinfo', 
                'portal', 'private', 'profile', 'register', 'rest', 'api/rest', 's3', 'secret', 
                'secure', 'server', 'settings', 'settings.json', 'signin', 'signup', 'staging', 
                'swagger', 'test', 'tinemc', 'tiny', 'token', 'upload', 'upload.php', 'uploadfile', 
                'user', 'wp-admin', 'xml', 'admin.php', 'auth.php', 'admin/dashboard', 'backup.zip',
                'config.yml', 'backup.tar', 'admin-console', 'api/v3', 'graphql/v2', 'settings.yaml',
                'db.backup', 'auth.json', 'control-panel', 'upload-dir', 'file-upload', 'api-token'
            ]
            with open(wordlist_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(set(sample_wordlist))) + '\n')
            log(f"Created {wordlist_file} with {len(sample_wordlist)} sample entries")
    update_wordlist(wordlist_file)

def install_or_update_tools(update_only=False):
    action = "Updating" if update_only else "Installing"
    log(f"Checking and {action} tools...")
    if not test_command('go'):
        log("Go is not installed. Please install Go from https://go.dev/dl/", color=Fore.RED)
        sys.exit(3)

    tools = [
        {'name': 'subfinder', 'package': 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'},
        {'name': 'dnsx', 'package': 'github.com/projectdiscovery/dnsx/cmd/dnsx@latest'},
        {'name': 'httpx', 'package': 'github.com/projectdiscovery/httpx/cmd/httpx@latest'},
        {'name': 'katana', 'package': 'github.com/projectdiscovery/katana/cmd/katana@latest'},
        {'name': 'gau', 'package': 'github.com/lc/gau/v2/cmd/gau@latest'},
        {'name': 'waybackurls', 'package': 'github.com/tomnomnom/waybackurls@latest'},
        {'name': 'puredns', 'package': 'github.com/d3mondev/puredns/v2/cmd/puredns@latest'},
        {'name': 'waymore', 'package': 'github.com/xnl-h4ck3r/waymore@latest'},
        {'name': 'assetfinder', 'package': 'github.com/tomnomnom/assetfinder@latest'},
        {'name': 'favfreak', 'package': 'github.com/devanshbatham/FavFreak@latest'},
        {'name': 'ctfr', 'install': 'pip install ctfr', 'type': 'python'},
        {'name': 'theHarvester', 'install': 'pip install theHarvester', 'type': 'python'}
    ]
    for tool in tools:
        if update_only or not test_command(tool['name']):
            log(f"{action} {tool['name']}...")
            try:
                if tool.get('type') == 'python':
                    subprocess.run(tool['install'].split(), capture_output=True, text=True, check=True)
                else:
                    subprocess.run(['go', 'install', tool['package']], capture_output=True, text=True, check=True)
                if test_command(tool['name']):
                    log(f"Successfully {action.lower()} {tool['name']}")
                else:
                    log(f"Failed to verify {tool['name']} after installation", color=Fore.YELLOW)
            except subprocess.CalledProcessError as e:
                log(f"Error {action.lower()} {tool['name']}: {e}", color=Fore.RED)
    save_config(config)

def test_proxy(proxy_url):
    if args.np:
        log("Proxy disabled by -np flag")
        return False
    try:
        response = requests.get('http://www.google.com', proxies={'http': proxy_url, 'https': proxy_url}, timeout=5)
        return response.status_code == 200
    except Exception:
        log(f"Proxy {proxy_url} failed", color=Fore.RED)
        return False

def read_file_line_by_line(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                yield line.strip()

def deduplicate_file(file_path):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return
    lines = set()
    for line in read_file_line_by_line(file_path):
        clean_line = strip_ansi_codes(line.strip())
        if clean_line:
            lines.add(clean_line)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    log(f"Deduplicated and cleaned {file_path}: {len(lines)} unique entries")

def normalize_url(url):
    try:
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return normalized.lower()
    except:
        return url.lower()

def merge_subdomains(subfinder_file, fuzz_file, output_file):
    subdomains = set()
    for file_path in [subfinder_file, fuzz_file]:
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            for line in read_file_line_by_line(file_path):
                normalized = re.sub(r'^(https?://)?(www\.)?', '', line.strip().lower())
                subdomains.add(normalized)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(subdomains)) + '\n')
    log(f"Merged and normalized subdomains into {output_file}: {len(subdomains)} unique entries")

def categorize_keyword(word):
    word_lower = word.lower()
    blacklist = {'testimonials', 'contest', 'testing', 'about', 'contact'}
    if any(b in word_lower for b in blacklist):
        return 'other'
    
    if re.search(r'(upload|filemanager|ckeditor|fckeditor|assetsmanager|fileupload|uploadfile|s3|bucket)', word_lower):
        return 'uploaders'
    elif re.search(r'(admin|manage|dashboard|console|control|panel|adminpanel|controlpanel)', word_lower):
        return 'admin_panels'
    elif re.search(r'\.(bak|env|git|config|sql|db|conf|backup|yml|yaml|log|swp|old)$', word_lower) or re.search(r'(backup|conf|git|sql|database)', word_lower):
        return 'sensitive_files'
    elif re.search(r'(login|register|signup|signin|auth|password|oauth)', word_lower):
        return 'auth_endpoints'
    elif re.search(r'(api|graphql|key|token|secret|swagger|api_key|endpoint)', word_lower):
        return 'api_endpoints'
    elif re.search(r'(debug|staging|dev|phpinfo|settings|xml|json)', word_lower):
        return 'other'
    return 'other'

def validate_url(url):
    if not test_command('httpx'):
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            return {
                'status': str(response.status_code),
                'content_length': str(len(response.content)),
                'content_type': response.headers.get('Content-Type', 'N/A')
            }
        except:
            return {'status': 'Pending', 'content_length': 'N/A', 'content_type': 'N/A'}
    
    try:
        result = subprocess.run(
            ['httpx', '-u', url, '-status-code', '-content-length', '-content-type', '-silent', '--no-color'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split()
            status = parts[-3] if len(parts) >= 3 else 'N/A'
            content_length = parts[-2] if len(parts) >= 2 else 'N/A'
            content_type = parts[-1] if len(parts) >= 1 else 'N/A'
            return {
                'status': status,
                'content_length': content_length,
                'content_type': content_type
            }
    except:
        pass
    return {'status': 'Pending', 'content_length': 'N/A', 'content_type': 'N/A'}

def extract_base_domain(domain):
    try:
        parsed = urlparse(f"http://{domain}")
        netloc = parsed.netloc
        parts = netloc.split('.')
        if len(parts) >= 2:
            return parts[-2]
        return netloc
    except:
        return domain.split('.')[0]

def extract_tld(domain):
    try:
        parsed = urlparse(f"http://{domain}")
        netloc = parsed.netloc
        parts = netloc.split('.')
        if len(parts) >= 2:
            return parts[-1]
        return ''
    except:
        return domain.split('.')[-1] if '.' in domain else ''

def discover_assets(domain, output_dir, threads, use_proxy, proxy_url):
    log(f"Discovering assets for {domain}...")
    assets_file = os.path.join(output_dir, 'assets.txt')
    assets = set()
    results = []
    base_domain = extract_base_domain(domain)
    log(f"Base domain: {base_domain}")

    if test_command('assetfinder'):
        log("Running assetfinder...")
        assetfinder_args = ['assetfinder', '--subs-only', domain]
        if use_proxy:
            assetfinder_args.extend(['--proxy', proxy_url])
        try:
            result = subprocess.run(assetfinder_args, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                clean_line = strip_ansi_codes(line.strip())
                if clean_line and clean_line.endswith(domain):
                    assets.add(clean_line)
                    tld = extract_tld(clean_line)
                    results.append({'asset': clean_line, 'source': 'assetfinder', 'type': 'subdomain', 'tld': tld})
        except Exception as e:
            log(f"Error running assetfinder: {e}", color=Fore.YELLOW)

    if test_command('favfreak'):
        log("Extracting favicon hashes...")
        favfreak_dir = os.path.join(output_dir, 'favfreak')
        os.makedirs(favfreak_dir, exist_ok=True)
        favfreak_input = os.path.join(output_dir, 'web-services.txt')
        if os.path.exists(favfreak_input):
            favfreak_args = ['favfreak', '-i', favfreak_input, '-o', favfreak_dir]
            try:
                subprocess.run(favfreak_args, capture_output=True, text=True)
                favicon_file = os.path.join(favfreak_dir, 'output.json')
                if os.path.exists(favicon_file):
                    with open(favicon_file, 'r', encoding='utf-8') as f:
                        favicon_data = json.load(f)
                    for entry in favicon_data:
                        url = entry.get('url', '')
                        hash_val = entry.get('hash', '')
                        tld = extract_tld(url)
                        results.append({'asset': url, 'source': 'favfreak', 'type': 'favicon', 'hash': hash_val, 'tld': tld})
                        assets.add(url)
            except Exception as e:
                log(f"Error running favfreak: {e}", color=Fore.YELLOW)

    if test_command('ctfr'):
        log("Searching SSL certificates with ctfr...")
        ctfr_output = os.path.join(output_dir, 'ctfr.json')
        ctfr_args = ['ctfr', '-d', domain, '-o', ctfr_output]
        try:
            subprocess.run(ctfr_args, capture_output=True, text=True)
            if os.path.exists(ctfr_output):
                with open(ctfr_output, 'r', encoding='utf-8') as f:
                    ctfr_data = json.load(f)
                for subdomain in ctfr_data.get('subdomains', []):
                    assets.add(subdomain)
                    tld = extract_tld(subdomain)
                    results.append({'asset': subdomain, 'source': 'ctfr', 'type': 'certificate', 'tld': tld})
        except Exception as e:
            log(f"Error running ctfr: {e}", color=Fore.YELLOW)

    if test_command('theHarvester'):
        log("Running theHarvester for OSINT...")
        harvester_output = os.path.join(output_dir, 'harvester.xml')
        harvester_args = ['theHarvester', '-d', base_domain, '-b', 'bing,duckduckgo,google', '-f', harvester_output]
        try:
            subprocess.run(harvester_args, capture_output=True, text=True)
            if os.path.exists(harvester_output):
                with open(harvester_output, 'r', encoding='utf-8') as f:
                    harvester_data = f.read()
                hosts = re.findall(r'<host>(.*?)</host>', harvester_data)
                for host in hosts:
                    if base_domain in host and not host.endswith(domain):
                        assets.add(host)
                        tld = extract_tld(host)
                        results.append({'asset': host, 'source': 'theHarvester', 'type': 'related_domain', 'tld': tld})
                    elif host.endswith(domain):
                        assets.add(host)
                        tld = extract_tld(host)
                        results.append({'asset': host, 'source': 'theHarvester', 'type': 'subdomain', 'tld': tld})
        except Exception as e:
            log(f"Error running theHarvester: {e}", color=Fore.YELLOW)

    if test_command('dnsx'):
        log("Checking additional DNS records...")
        dns_temp_file = os.path.join(output_dir, 'dns_temp.txt')
        dns_args = ['dnsx', '-d', domain, '-cname', '-ns', '-mx', '-o', dns_temp_file, '-t', str(threads), '-silent', '--no-color']
        if use_proxy:
            dns_args.extend(['-proxy', proxy_url])
        try:
            subprocess.run(dns_args, capture_output=True, text=True)
            if os.path.exists(dns_temp_file):
                for line in read_file_line_by_line(dns_temp_file):
                    clean_line = strip_ansi_codes(line.strip())
                    if clean_line and not clean_line.startswith('['):
                        assets.add(clean_line)
                        tld = extract_tld(clean_line)
                        asset_type = 'related_domain' if base_domain in clean_line and not clean_line.endswith(domain) else 'dns'
                        results.append({'asset': clean_line, 'source': 'dnsx', 'type': asset_type, 'tld': tld})
        except Exception as e:
            log(f"Error running dnsx for additional records: {e}", color=Fore.YELLOW)

    with open(assets_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(assets)) + '\n')
    log(f"Saved {len(assets)} unique assets to {assets_file}")

    validated_results = []
    if test_command('httpx') and assets:
        log("Validating assets with httpx...")
        assets_temp_file = os.path.join(output_dir, 'assets_temp.txt')
        with open(assets_temp_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(assets) + '\n')
        httpx_args = ['httpx', '-l', assets_temp_file, '-status-code', '-content-length', '-content-type', '-silent', '--no-color', '-t', str(threads)]
        if use_proxy:
            httpx_args.extend(['-http-proxy', proxy_url])
        try:
            result = subprocess.run(httpx_args, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4:
                    asset = parts[0]
                    status = parts[-3]
                    content_length = parts[-2]
                    content_type = parts[-1]
                    for res in results:
                        if res['asset'] == asset:
                            res.update({
                                'status': status,
                                'content_length': content_length,
                                'content_type': content_type
                            })
                            validated_results.append(res)
                            break
        except Exception as e:
            log(f"Error validating assets with httpx: {e}", color=Fore.YELLOW)

    return validated_results

def categorize_urls(crawling_file, wordlist_file, sensitive_dir, threads):
    if not os.path.exists(crawling_file) or os.path.getsize(crawling_file) == 0:
        log("No URLs to categorize, check crawling tools (katana, gau, waymore, waybackurls)", color=Fore.RED)
        return []
    os.makedirs(sensitive_dir, exist_ok=True)
    categories = ['uploaders', 'admin_panels', 'sensitive_files', 'auth_endpoints', 'api_endpoints', 'other']
    for cat in categories:
        os.makedirs(os.path.join(sensitive_dir, cat), exist_ok=True)
    
    sensitive_words = set(read_file_line_by_line(wordlist_file))
    log(f"Loaded {len(sensitive_words)} keywords from {wordlist_file}")
    urls = set(normalize_url(url) for url in read_file_line_by_line(crawling_file) if url.strip())
    log(f"Loaded {len(urls)} unique URLs from {crawling_file}")
    sensitive_endpoints = []
    seen_urls = set()
    
    for word in sensitive_words:
        word_safe = re.sub(r'[^\w\-]', '_', word)
        category = categorize_keyword(word)
        output_file = os.path.join(sensitive_dir, category, f'sensitive_{word_safe}.txt')
        matching_urls = []
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            results = executor.map(lambda url: check_url_for_word(url, word), urls)
            for result in results:
                if result and result['url'] not in seen_urls:
                    response_info = validate_url(result['url'])
                    result.update({
                        'status': response_info['status'],
                        'content_length': response_info['content_length'],
                        'content_type': response_info['content_type']
                    })
                    matching_urls.append(result['url'])
                    sensitive_endpoints.append(result)
                    seen_urls.add(result['url'])
                    log(f"Found URL {result['url']} for keyword '{word}' (Status: {response_info['status']}, Content-Type: {response_info['content_type']})")
        
        if matching_urls:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(matching_urls) + '\n')
            log(f"Categorized {len(matching_urls)} URLs for '{word}' in {output_file} (Category: {category})")
        else:
            log(f"No URLs found for keyword '{word}' (Category: {category})", color=Fore.YELLOW)
    
    if not sensitive_endpoints:
        log("No sensitive endpoints found, check wordlist or crawling output", color=Fore.YELLOW)
    else:
        log(f"Found {len(sensitive_endpoints)} sensitive endpoints")
    return sensitive_endpoints

def check_url_for_word(url, word):
    if re.search(rf'(?:^|/|\.){re.escape(word)}(?:$|/|\?|\.)', url, re.IGNORECASE):
        category = categorize_keyword(word)
        return {'url': url, 'keyword': word, 'status': 'N/A', 'category': category, 'content_length': 'N/A', 'content_type': 'N/A'}
    return None

def run_recon(domain_file, output_dir, wordlist_file, threads, use_proxy, report_limit, proxy_url):
    log("Starting advanced reconnaissance...")
    if not test_internet():
        sys.exit(1)
    if use_proxy and not args.np:
        use_proxy = test_proxy(proxy_url)

    with open(domain_file, 'r', encoding='utf-8') as f:
        domains = [d.strip() for d in f.readlines() if d.strip()]
    if not domains:
        log(f"Domain file {domain_file} is empty", color=Fore.RED)
        sys.exit(1)
    log(f"Found {len(domains)} domains: {', '.join(domains)}")

    required_tools = ['subfinder', 'dnsx', 'httpx', 'katana', 'puredns', 'waymore']
    optional_tools = ['gau', 'waybackurls', 'assetfinder', 'favfreak', 'ctfr', 'theHarvester']
    missing_required_tools = [tool for tool in required_tools if not test_command(tool)]
    if missing_required_tools:
        log(f"Missing required tools: {', '.join(missing_required_tools)}. Install them with -i flag.", color=Fore.RED)
        sys.exit(1)
    missing_optional_tools = [tool for tool in optional_tools if not test_command(tool)]
    if missing_optional_tools:
        log(f"Optional tools missing: {', '.join(missing_optional_tools)}. Some features may be limited.", color=Fore.YELLOW)

    wordlist_dir = os.path.join(os.getcwd(), 'cybersift/subdomain_wordlists')
    download_subdomain_wordlists(wordlist_dir)
    create_input_files(domain_file, wordlist_file)

    os.makedirs(output_dir, exist_ok=True)
    for domain in domains:
        domain_dir = os.path.join(output_dir, domain)
        os.makedirs(domain_dir, exist_ok=True)

        subfinder_file = os.path.join(domain_dir, 'subfinder.txt')
        fuzz_file = os.path.join(domain_dir, 'fuzz.txt')
        valid_subdomains_file = os.path.join(domain_dir, 'valid_subdomains.txt')
        dns_file = os.path.join(domain_dir, 'dns.txt')
        sub_status_file = os.path.join(domain_dir, 'web-services.txt')
        crawling_file = os.path.join(domain_dir, 'crawled-urls.txt')
        sensitive_dir = os.path.join(domain_dir, 'sensitive_urls')

        assets = discover_assets(domain, domain_dir, threads, use_proxy, proxy_url)

        log(f"Enumerating subdomains for {domain}...")
        subfinder_args = ['subfinder', '-d', domain, '-o', subfinder_file, '-silent', '-t', str(threads), '-all', '--no-color']
        if use_proxy:
            subfinder_args.extend(['-proxy', proxy_url])
        subprocess.run(subfinder_args, capture_output=True, text=True)
        deduplicate_file(subfinder_file)

        if test_command('puredns'):
            log(f"Fuzzing subdomains for {domain}...")
            wordlists = [
                os.path.join(wordlist_dir, 'subdomains-top1million-5000.txt'),
                os.path.join(wordlist_dir, 'default-subdomains.txt')
            ]
            for wordlist in wordlists:
                if os.path.exists(wordlist):
                    puredns_args = ['puredns', 'bruteforce', wordlist, domain, '-o', fuzz_file, '-t', str(threads), '--quiet']
                    if use_proxy:
                        puredns_args.extend(['--proxy', proxy_url])
                    subprocess.run(puredns_args, capture_output=True, text=True)
                    deduplicate_file(fuzz_file)
                    log(f"Puredns fuzzing completed with {wordlist}")
                else:
                    log(f"Wordlist {wordlist} not found, skipping", color=Fore.YELLOW)

        merge_subdomains(subfinder_file, fuzz_file, valid_subdomains_file)

        if os.path.exists(valid_subdomains_file) and os.path.getsize(valid_subdomains_file) > 0:
            log(f"Resolving DNS records for {domain}...")
            dnsx_args = ['dnsx', '-l', valid_subdomains_file, '-a', '-aaaa', '-o', dns_file, '-t', str(threads), '-silent', '-resp', '--no-color']
            if use_proxy:
                dnsx_args.extend(['-proxy', proxy_url])
            subprocess.run(dnsx_args, capture_output=True, text=True)
            deduplicate_file(dns_file)

        if os.path.exists(valid_subdomains_file) and os.path.getsize(valid_subdomains_file) > 0:
            log(f"Discovering web services and technologies for {domain}...")
            httpx_args = ['httpx', '-l', valid_subdomains_file, '-o', sub_status_file, '-tech-detect', '-status-code', '-t', str(threads), '-silent', '-follow-redirects', '--no-color']
            if use_proxy:
                httpx_args.extend(['-http-proxy', proxy_url])
            subprocess.run(httpx_args, capture_output=True, text=True)
            deduplicate_file(sub_status_file)

        if os.path.exists(sub_status_file) and os.path.getsize(sub_status_file) > 0:
            log(f"Crawling URLs with katana for {domain}...")
            katana_args = ['katana', '-u', sub_status_file, '-o', crawling_file, '-silent', '-c', str(threads), '-js-crawl', '-js-lu', '-depth', '8', '-crawl-hidden-paths', '--no-color']
            if use_proxy:
                katana_args.extend(['-proxy', proxy_url])
            subprocess.run(katana_args, capture_output=True, text=True)
            deduplicate_file(crawling_file)

            if test_command('gau'):
                log(f"Crawling URLs with gau for {domain}...")
                gau_args = ['gau', '--subs', '--threads', str(threads), '--providers', 'wayback,commoncrawl,otx,urlscan', domain]
                if use_proxy:
                    gau_args.extend(['--proxy', proxy_url])
                with open(crawling_file, 'a', encoding='utf-8') as f:
                    subprocess.run(gau_args, stdout=f, stderr=subprocess.PIPE, text=True)
                deduplicate_file(crawling_file)

            if test_command('waybackurls'):
                log(f"Crawling URLs with waybackurls for {domain}...")
                wayback_args = ['waybackurls', domain]
                with open(crawling_file, 'a', encoding='utf-8') as f:
                    subprocess.run(wayback_args, stdout=f, stderr=subprocess.PIPE, text=True)
                deduplicate_file(crawling_file)

            if test_command('waymore'):
                log(f"Crawling URLs with waymore for {domain}...")
                waymore_args = ['waymore', '-i', domain, '-oU', crawling_file, '-mode', 'U', '-t', str(threads), '-no-subs']
                if use_proxy:
                    waymore_args.extend(['-proxy', proxy_url])
                subprocess.run(waymore_args, capture_output=True, text=True)
                deduplicate_file(crawling_file)

        sensitive_endpoints = categorize_urls(crawling_file, wordlist_file, sensitive_dir, threads)

        log(f"Generating report for {domain}...")
        dns_content = 'No DNS records found'
        if os.path.exists(dns_file) and os.path.getsize(dns_file) > 0:
            dns_content = '\n'.join(list(read_file_line_by_line(dns_file))[:report_limit])

        web_content = 'No web services found'
        if os.path.exists(sub_status_file) and os.path.getsize(sub_status_file) > 0:
            web_content = '\n'.join(list(read_file_line_by_line(sub_status_file))[:report_limit])

        crawl_content = 'No URLs crawled'
        crawling_file_link = 'No crawled URLs file'
        if os.path.exists(crawling_file) and os.path.getsize(crawling_file) > 0:
            crawled_urls = list(read_file_line_by_line(crawling_file))[:3]
            crawl_content = '\n'.join(crawled_urls)
            crawling_file_link = f'<a href="file:///{os.path.abspath(crawling_file)}" class="text-blue-500 underline">View Full Crawled URLs</a>'

        categories = ['uploaders', 'admin_panels', 'sensitive_files', 'auth_endpoints', 'api_endpoints', 'other']
        sensitive_tables = {cat: [] for cat in categories}
        for endpoint in sensitive_endpoints:
            sensitive_tables[endpoint['category']].append(endpoint)

        sensitive_html = ''
        for category in categories:
            endpoints = sensitive_tables[category][:report_limit]
            if endpoints:
                table = f'''
                <div class="mb-6">
                    <h3 class="text-xl font-semibold text-gray-700 mb-2 capitalize">{category.replace('_', ' ')}</h3>
                    <table class="min-w-full bg-white border" id="{category}Table">
                        <thead>
                            <tr>
                                <th class="py-2 px-4 border-b">URL</th>
                                <th class="py-2 px-4 border-b">Keyword</th>
                                <th class="py-2 px-4 border-b">Status</th>
                                <th class="py-2 px-4 border-b">Content-Length</th>
                                <th class="py-2 px-4 border-b">Content-Type</th>
                            </tr>
                        </thead>
                        <tbody>
                '''
                for endpoint in endpoints:
                    table += f'''
                            <tr>
                                <td class="py-2 px-4 border-b break-all"><a href="{endpoint['url']}" class="text-blue-500 underline">{endpoint['url']}</a></td>
                                <td class="py-2 px-4 border-b">{endpoint['keyword']}</td>
                                <td class="py-2 px-4 border-b">{endpoint['status']}</td>
                                <td class="py-2 px-4 border-b">{endpoint['content_length']}</td>
                                <td class="py-2 px-4 border-b">{endpoint['content_type']}</td>
                            </tr>
                    '''
                table += '</tbody></table></div>'
                sensitive_html += table

        assets_html = ''
        if assets:
            table = f'''
            <div class="mb-6">
                <h3 class="text-xl font-semibold text-gray-700 mb-2">Discovered Assets</h3>
                <table class="min-w-full bg-white border" id="assetsTable">
                    <thead>
                        <tr>
                            <th class="py-2 px-4 border-b">Asset</th>
                            <th class="py-2 px-4 border-b">Source</th>
                            <th class="py-2 px-4 border-b">Type</th>
                            <th class="py-2 px-4 border-b">TLD</th>
                            <th class="py-2 px-4 border-b">Status</th>
                            <th class="py-2 px-4 border-b">Content-Length</th>
                            <th class="py-2 px-4 border-b">Content-Type</th>
                            <th class="py-2 px-4 border-b">Additional Info</th>
                        </tr>
                    </thead>
                    <tbody>
            '''
            for asset in assets[:report_limit]:
                additional_info = asset.get('hash', '') if asset['type'] == 'favicon' else ''
                table += f'''
                        <tr>
                            <td class="py-2 px-4 border-b break-all">{asset['asset']}</td>
                            <td class="py-2 px-4 border-b">{asset['source']}</td>
                            <td class="py-2 px-4 border-b">{asset['type']}</td>
                            <td class="py-2 px-4 border-b">{asset.get('tld', 'N/A')}</td>
                            <td class="py-2 px-4 border-b">{asset.get('status', 'N/A')}</td>
                            <td class="py-2 px-4 border-b">{asset.get('content_length', 'N/A')}</td>
                            <td class="py-2 px-4 border-b">{asset.get('content_type', 'N/A')}</td>
                            <td class="py-2 px-4 border-b">{additional_info}</td>
                        </tr>
                '''
            table += '</tbody></table></div>'
            assets_html = table

        report_file = os.path.join(domain_dir, f'report-{domain}.html')
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconnaissance Report for {domain}</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <style>
        pre {{ white-space: pre-wrap; word-break: break-all; }}
        table {{ table-layout: fixed; width: 100%; }}
        td, th {{ word-break: break-all; padding: 8px; text-align: center; }}
        .filter-container {{ margin-bottom: 16px; }}
        .category-section {{ margin-bottom: 24px; }}
    </style>
    <script>
        function filterTable() {{
            let input = document.getElementById('filterInput').value.toLowerCase();
            let tables = document.querySelectorAll('table[id$="Table"]');
            tables.forEach(table => {{
                let rows = table.querySelectorAll('tbody tr');
                rows.forEach(row => {{
                    let text = row.textContent.toLowerCase();
                    row.style.display = text.includes(input) ? '' : 'none';
                }});
            }});
        }}
    </script>
</head>
<body class="bg-gray-100 font-sans">
    <div class="container mx-auto p-6">
        <h1 class="text-3xl font-bold text-gray-800 mb-4">Reconnaissance Report for {domain}</h1>
        <div class="bg-white shadow-md rounded-lg p-6 mb-6">
            <h2 class="text-2xl font-semibold text-gray-700 mb-2">Discovered Assets</h2>
            {assets_html}
        </div>
        <div class="bg-white shadow-md rounded-lg p-6 mb-6">
            <h2 class="text-2xl font-semibold text-gray-700 mb-2">Subdomains with DNS Records (Real IP)</h2>
            <pre class="bg-gray-200 p-4 rounded">{dns_content}</pre>
        </div>
        <div class="bg-white shadow-md rounded-lg p-6 mb-6">
            <h2 class="text-2xl font-semibold text-gray-700 mb-2">Web Services with Technologies</h2>
            <pre class="bg-gray-200 p-4 rounded">{web_content}</pre>
        </div>
        <div class="bg-white shadow-md rounded-lg p-6 mb-6">
            <h2 class="text-2xl font-semibold text-gray-700 mb-2">Crawled URLs (Sample)</h2>
            <pre class="bg-gray-200 p-4 rounded">{crawl_content}</pre>
            <p class="mt-2">{crawling_file_link}</p>
        </div>
        <div class="bg-white shadow-md rounded-lg p-6">
            <h2 class="text-2xl font-semibold text-gray-700 mb-2">Sensitive Endpoints</h2>
            <div class="filter-container">
                <input id="filterInput" type="text" placeholder="Filter endpoints by keyword or category..." class="p-2 border rounded w-full" onkeyup="filterTable()">
            </div>
            {sensitive_html}
        </div>
    </div>
</body>
</html>
"""
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        log(f"Report generated: {report_file}")

if __name__ == '__main__':
    try:
        if args.i or args.u:
            install_or_update_tools(update_only=args.u)
            log("Tool operations completed!")
        else:
            install_dependencies()
            create_input_files(args.f, args.w)
            run_recon(args.f, args.o, args.w, args.t, not args.np, args.r, args.p)
            log("Script completed successfully")
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
