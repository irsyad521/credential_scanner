# Credential Scanner

Credential Scanner is a tool designed to detect credentials such as emails, usernames, passwords, and database credentials in text files.

## 📌 Features
- Detects emails, usernames, passwords, and database credentials in text files.
- Ignores large or binary files such as `.exe`, `.dll`, `.zip`.
- Displays results with color using **colorama**.
- Saves detected credentials in the `result/` folder.

## 🔧 Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/irsyad521/credential_scanner.git
cd credential_scanner
pip install -r requirements.txt
```

## 🚀 Usage
Run the script to scan a directory:
```bash
python3 main.py ./target_directory
```
Filter results by email domain:
```bash
python3 main.py ./target_directory --domain example.com
```
Example for scanning system logs:
```bash
python3 main.py /var/logs --domain corporate.net
```



