# EvilParser
Offensive tooling to quickly identify password reuse across Active Directory environments by combining secretsdump output, hashcat results, Kerberoast plaintexts, and BloodHound user data.

EvilParser

EvilParser is a fast, flexible post-exploitation helper for analyzing NTLM password reuse across:

Impacket secretsdump output

Hashcat cracked hashes (supports both domain\user:hash:plaintext and potfile hash:plaintext formats)

Optional Kerberoast cracked hashes

Optional BloodHound user data

It identifies reused passwords, correlates cracked credentials, and generates clean exports for reporting or automation.

Features

🔍 Parse secretsdump and cracked hashes to map NTLM → plaintext

🔑 Detect password reuse across multiple users

🎭 Supports hashcat potfiles (hash:plaintext)

🐶 Optional BloodHound JSON correlation

🔥 Optional Kerberoast cracked SPN mapping

📊 CSV/JSON export

🏷 Auto-generate tags for downstream automation (e.g., reused passwords, service-account creds)

💻 Supports machine accounts, domain filters, and custom percentage calculations
