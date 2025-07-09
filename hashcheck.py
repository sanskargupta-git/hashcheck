import argparse

# Simulated malware database (hash: description)
malware_db = {
    "5d41402abc4b2a76b9719d911017c592": "Trojan.Generic",
    "098f6bcd4621d373cade4e832627b4f6": "Keylogger.Win32",
    "6f1ed002ab5595859014ebf0951522d9": "Backdoor.Python",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File",
    "9e107d9d372bb6826bd81d3542a419d6": "Ransomware.Demo",
}

def check_hash(hash_val):
    hash_val = hash_val.lower()
    if hash_val in malware_db:
        return f"⚠️ MALICIOUS: {malware_db[hash_val]}"
    else:
        return "✅ CLEAN / Not in DB"

def process_hashes(hashes, output_file=None):
    results = []
    for h in hashes:
        status = check_hash(h.strip())
        line = f"{h.strip()} → {status}"
        print(line)
        results.append(line)

    if output_file:
        with open(output_file, "w") as f:
            for line in results:
                f.write(line + "\n")
        print(f"\n📁 Results saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="🦠 HashCheck – Malware Hash Reputation Lookup")
    parser.add_argument("-H", "--hash", help="Single hash to check")
    parser.add_argument("-f", "--file", help="File containing list of hashes")
    parser.add_argument("-o", "--output", help="Output file to save report")
    args = parser.parse_args()

    hashes = []
    if args.hash:
        hashes.append(args.hash)
    if args.file:
        with open(args.file, "r") as f:
            hashes.extend([line.strip() for line in f if line.strip()])

    if not hashes:
        print("❌ No hashes provided.")
        return

    process_hashes(hashes, args.output)

if __name__ == "__main__":
    main()
