import argparse
from scanner import search_pattern_in_directory, build_patterns
from utils import save_results_to_json, save_unique_to_txt

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Credential Scanner - Scan for emails, usernames, and passwords in text files.",
        epilog="""Usage Examples:
  python main.py ./target_directory
  python main.py ./target_directory --domain example.com
  python main.py /var/logs --domain corporate.net
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("directory", type=str, help="Path to the directory to scan.")
    parser.add_argument("--domain", type=str, help="Filter results to a specific email domain (e.g., example.com).", default=None)
    
    args = parser.parse_args()
    
    print("""
    ===================================
    🔍 CREDENTIAL SCANNER
    ===================================
    Scanning for emails, usernames, and passwords...
    """)

    patterns = build_patterns(args.domain)
    results = search_pattern_in_directory(args.directory, patterns)

    if results:
        save_results_to_json(results)
        save_unique_to_txt(results, "email", "emails.txt")
        save_unique_to_txt(results, "username", "usernames.txt")
        save_unique_to_txt(results, "password", "passwords.txt")
        save_unique_to_txt(results, "database_credential", "database_credentials.txt")
        save_unique_to_txt(results, "api_key", "api_keys")
        save_unique_to_txt(results, "jwt_token", "jwt_tokens.txt")
        save_unique_to_txt(results, "ssh_private_key", "ssh_private_keys.txt")
        save_unique_to_txt(results, "password_in_url", "passwords_in_urls.txt")
        save_unique_to_txt(results, "hash", "hashes.txt"),
        save_unique_to_txt(results,"cloud_storage", "cloud_storage.txt")
        save_unique_to_txt(results, "ip_addresses", "ip_addresses.txt")     

        if args.domain:
            save_unique_to_txt(results, "custom_email", f"emails_{args.domain.replace('.', '_')}.txt")

    else:
        print("[-] No credentials found.")

if __name__ == "__main__":
    main()
