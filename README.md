# 🦠 HashCheck – Malware Hash Reputation Lookup

**HashCheck** is a Python tool that checks file hashes against a simulated malware database. It mimics the behavior of a basic threat intel lookup engine like VirusTotal or internal IOC scanners.

## 💡 Features

- Accepts single hash or list of hashes
- Flags known malware hashes from offline DB
- Supports MD5/SHA1/SHA256 formats
- Saves results to file (optional)

## 📦 Usage

```bash
python hashcheck.py -H 5d41402abc4b2a76b9719d911017c592
python hashcheck.py -f hashes.txt -o result.txt
