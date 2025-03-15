import os
import re
from colorama import Fore, Style
def build_patterns(custom_domain=None):
    patterns = {
        "email": [
            r'\b[A-Za-z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,15}\b'
        ],
        "username": [
            r'\b(?:user(?:name)?|login|usr|account|uname|identifier|id|uid|user_id)[\s:=]+["\']?([A-Za-z0-9._-]+)["\']?\b'
        ],
        "password": [
            r'\b(?:pass(?:word)?|pwd|secret|token|auth)[\s:=]+["\']?([A-Za-z0-9!@#$%^&*()_+\-=]+)["\']?\b'
        ],
        "database_credential": [
            r'\b(?:mysql|postgres|mongodb|redis|mssql)://[^\s]+\b',
            r'\b(?:jdbc|odbc):[^\s]+\b',
            r'\b(?:jdbc:mysql|jdbc:postgresql|jdbc:oracle|jdbc:sqlserver|jdbc:sqlite)://[^\s]+\b',
            r'\b(?:mongodb\+srv|mongodb)://[^\s]+\b',
            r'\bpostgres://[^\s]+:[^\s]+@[^\s]+:[0-9]+/[^\s]+\b',
            r'\bmysql:\/\/[^\s]+:[^\s]+@[^\s]+:[0-9]+/[^\s]+\b',
            r'\bredis:\/\/:[^\s]+@[^\s]+:[0-9]+\b',
            r'\bmssql:\/\/[^\s]+:[^\s]+@[^\s]+:[0-9]+/[^\s]+\b',
            r'\b(?:sqlite|file):\/\/[^\s]+\b',
            r'\b(?:DB_USERNAME|DB_PASSWORD|DATABASE_URL|MYSQL_URL|POSTGRES_URL|MONGO_URL|REDIS_URL|SQLSERVER_URL)=[^\s]+\b'
        ],
         "api_key": [
            r'\bsk_live_[0-9a-zA-Z]{24,}\b',
            r'\bpk_live_[0-9a-zA-Z]{24,}\b',
            r'\bghp_[0-9A-Za-z]{36}\b',
            r'\bpat_[0-9a-f]{40}\b',
            r'\bAIza[0-9A-Za-z-_]{35}\b',
            r'\bya29\.[0-9A-Za-z-_]+\b',
            r'\bAKIA[0-9A-Z]{16}\b',
            r'\bASIA[0-9A-Z]{16}\b',
            r'\bSG\.[0-9A-Za-z\._-]{22,}\b',
            r'\bTWILIO_[0-9A-Za-z]{32}\b',
            r'\bdropbox_[0-9A-Za-z]{15,}\b',
            r'\bslack_[0-9A-Za-z]{20,40}\b',
            r'\bxox[abp]-[0-9A-Za-z]{10,48}\b',
            r'\bsk-[0-9a-zA-Z]{32,}\b',
            r'\bAPCA-[0-9A-Za-z]{32}\b',
            r'\bmailgun_[0-9a-fA-F]{32}\b',
            r'\bkey-[0-9a-zA-Z]{32}\b',
            r'\brg-[0-9a-zA-Z]{32}\b',
            r'\bsk_test_[0-9a-zA-Z]{24,}\b',
            r'\bFBACCESSTOKEN_[0-9A-Za-z]{32,}\b',
            r'\bVONAGE_[0-9A-Za-z]{32}\b',
            r'\bokta_[0-9a-zA-Z]{32}\b',
            r'\bhv_[0-9a-zA-Z]{32}\b',
            r'\bcoinbase_[0-9a-zA-Z]{32,}\b',
            r'\bgithub_pat_[0-9A-Za-z]{40,}\b',
            r'\bghs_[0-9A-Za-z]{36}\b',
            r'\bgraph.facebook.com/[0-9A-Za-z]{30,}\b',
            r'\bapi_key=[0-9A-Za-z]{32,}\b',
            r'\bapitoken_[0-9A-Za-z]{30,}\b'
        ],
        "jwt_token": [
            r'\beyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\b'
        ],
        "ssh_private_key": [
            r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'
        ],
        "password_in_url": [
            r'\bhttps?:\/\/[^\s\/:]+:[^\s\/]+@[^\s]+\b'
        ],
        "hash": [
            r'\b[a-f0-9]{32}\b',
            r'\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b',
            r'\b[a-f0-9]{40}\b',
            r'\b[a-f0-9]{64}\b',
            r'\b[a-f0-9]{128}\b',
            r'\b[A-Fa-f0-9]{56}\b',
            r'\b[A-Fa-f0-9]{96}\b',
            r'\b[A-Fa-f0-9]{16}:[A-Fa-f0-9]{16}\b',
            r'\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b',
            r'\b\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}\b',
            r'\b\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53}\b',
            r'\b\$5\$[A-Za-z0-9./]{16}\$[A-Za-z0-9./]{43}\b',
            r'\b\$6\$[A-Za-z0-9./]{16}\$[A-Za-z0-9./]{86}\b',
            r'\b\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\b',
            r'\b\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\b',
            r'\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{8}\b',
            r'\b[0-9a-f]{40}:[0-9]{1,5}:[0-9a-f]{40}\b'
        ],
        "cloud_storage": [
            r'\bhttps?:\/\/s3[\.-][a-z0-9-]+\.amazonaws\.com\/[a-zA-Z0-9._-]+\b',
            r'\b(?:aws|AWS|s3_bucket|S3_BUCKET)[\s:=]+["\']?([a-zA-Z0-9._-]{3,63})["\']?\b',
            r'\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[\s:=]+["\']?([0-9a-zA-Z\/+=]{40})["\']?\b',
            r'\bhttps?:\/\/storage\.googleapis\.com\/[a-zA-Z0-9._-]+\b',
            r'\b(?:gcp_storage|GCP_STORAGE|google_cloud_bucket)[\s:=]+["\']?([a-zA-Z0-9._-]{3,63})["\']?\b',
            r'\bhttps?:\/\/[a-z0-9-]+\.blob\.core\.windows\.net\/[a-zA-Z0-9._-]+\b',
            r'\b(?:azure_storage_key|AZURE_STORAGE_KEY)[\s:=]+["\']?([A-Za-z0-9+/=]{88})["\']?\b',
        ],
        "ip_addresses": [
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'
        ]
    }
    if custom_domain:
        patterns["custom_email"] = [rf'\b[A-Za-z0-9._%+-]+@{custom_domain}\b']
    return patterns
def search_pattern_in_file(file_path, patterns):
    """Mencari pola dalam satu file"""
    found_items = {key: [] for key in patterns.keys()}
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            for category, regex_list in patterns.items():
                for regex in regex_list:
                    matches = re.findall(regex, content)
                    for match in matches:
                        found_items[category].append(match if isinstance(match, str) else match[0])
    except Exception as e:
        print(f"{Fore.YELLOW}[-] Tidak dapat membaca {file_path}: {e}{Style.RESET_ALL}")
    return found_items
def search_pattern_in_directory(directory, patterns):
    """Mencari pola dalam semua file di direktori"""
    results = []
    ignored_extensions = {'.exe', '.dll', '.zip', '.rar', '.7z', '.tar', '.gz', '.bin', '.iso'}
    max_file_size = 10 * 1024 * 1024
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if any(file.lower().endswith(ext) for ext in ignored_extensions):
                print(f"{Fore.CYAN}[!] Mengabaikan file biner: {file_path}{Style.RESET_ALL}")
                continue
            if os.path.getsize(file_path) > max_file_size:
                print(f"{Fore.CYAN}[!] Mengabaikan file besar: {file_path}{Style.RESET_ALL}")
                continue
            items = search_pattern_in_file(file_path, patterns)
            for category, values in items.items():
                for value in values:
                    print(f"{Fore.GREEN}[+] {category.capitalize()} ditemukan di {file_path}: {Fore.RED}{value}{Style.RESET_ALL}")
                    results.append({"file": file_path, category: value})
    return results
