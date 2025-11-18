#!/usr/bin/env python3
r"""
EvilParser

Parse secretsdump output and hashcat cracked hashes to find reused passwords.

Features:
 - CSV/JSON export of reused-password groups and full cracked mapping
 - Optional BloodHound JSON correlation (mark which BH users had cracked passwords)
 - Optional Kerberoast cracked file correlation (detect services whose plaintexts were cracked and mark reuse with user accounts)
 - Post-crack tagging: write a tags JSON mapping accounts -> tags (e.g. "reused", "service-password") for downstream workflows

Usage:
  python3 EvilParser.py secretsdump.txt cracked.txt [options]

Options:
  --full                Show full cracked user list
  --log FILE            Write plain-text log (ANSI colors stripped)
  --export-csv FILE     Export results to CSV
  --export-json FILE    Export results to JSON
  --bloodhound FILE     Optional BloodHound JSON to mark BH users (nodes with label 'User')
  --kerberoast FILE     Optional Kerberoast cracked file (lines like SPN:hash:plaintext)
  --auto-tag FILE       Write tags JSON for post-crack workflow
  --include-machines    Include machine accounts (names ending with $) in percentage calculation
  --include-all         Ignore FQDN-only rule and include all accounts in percentage calculation
  --domain DOMAIN       Restrict percentage calculation to provided domain(s); use multiple times

Dependencies:
 - Python 3.8+
 - colorama (pip install colorama)
"""
import argparse
import sys
import re
import json
import csv
from collections import defaultdict
from pathlib import Path

try:
    from colorama import init as colorama_init, Fore, Style
except Exception:
    print('This script requires the colorama package. Install with: pip install colorama')
    raise

colorama_init(autoreset=True)

BANNER = r'''
 __   _____       _ _ ____                            __ 
| _| | ____|_   _(_) |  _ \ __ _ _ __ ___  ___ _ __  |_ |
| |  |  _| \ \ / / | | |_) / _` | '__/ __|/ _ \ '__|  | |
| |  | |___ \ V /| | |  __/ (_| | |  \__ \  __/ |     | |
| |  |_____| \_/ |_|_|_|   \__,_|_|  |___/\___|_|     | |
|__|                                                 |__|
'''


def parse_secretsdump(path):
    r"""
    Parse secretsdump lines. Returns dict mapping full_user (domain\\user) -> nt_hash (lowercase)
    """
    out = {}
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) < 4:
                continue
            user = parts[0]
            nt_hash = parts[3].lower()
            out[user] = nt_hash
    return out


def parse_hashcat_cracked(path):
    r"""
    Parse cracked hashes in **two formats**:

    Format A (EvilParser style):
        domain\\user:hash:plaintext

    Format B (Hashcat potfile):
        hash:plaintext

    Returns: dict mapping nt_hash -> plaintext
    """
    out = {}
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue

            parts = line.split(':')

            # POTFILE SUPPORT: hash:plaintext
            if len(parts) == 2:
                nt_hash = parts[0].lower()
                plaintext = parts[1]
                out[nt_hash] = plaintext
                continue

            # Original format: domain\user:hash:plaintext
            if len(parts) >= 3:
                nt_hash = parts[1].lower()
                plaintext = ':'.join(parts[2:])
                out[nt_hash] = plaintext
                continue

    return out


def parse_kerberoast_cracked(path):
    r"""
    Parse a Kerberoast cracked file. Expected format:
      SPN:hash:plaintext
    """
    spn_by_plain = defaultdict(list)
    plain_by_spn = {}
    if not path:
        return spn_by_plain, plain_by_spn
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            parts = line.split(':')
            if len(parts) < 3:
                continue
            spn = parts[0]
            plaintext = ':'.join(parts[2:])
            spn_by_plain[plaintext].append(spn)
            plain_by_spn[spn] = plaintext
    return spn_by_plain, plain_by_spn


def load_bloodhound_users(path):
    """Load BloodHound JSON and return a set of usernames"""
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
    except Exception:
        return set()

    users = set()
    nodes = None
    if isinstance(data, dict):
        nodes = data.get('nodes') or data.get('Nodes')
    if not nodes and isinstance(data, list):
        nodes = data
    if not nodes:
        for k, v in data.items():
            if isinstance(v, list) and len(v) and isinstance(v[0], dict):
                nodes = v
                break
    if not nodes:
        return users

    for node in nodes:
        labels = node.get('labels') if isinstance(node, dict) else []
        props = node.get('properties') if isinstance(node, dict) else node
        if labels and any((isinstance(lbl, str) and lbl.lower() == 'user') for lbl in labels):
            name = props.get('name') or props.get('samaccountname') or props.get('userprincipalname')
            domain = props.get('domain') or props.get('Domain')
            if name:
                name = str(name).strip()
                users.add(name)
                if domain and '\\' not in name and '@' not in name:
                    users.add(f"{domain}\\{name}")
    return users


def strip_ansi(s):
    ansi = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi.sub('', s)


def write_log(path, lines):
    p = Path(path)
    with p.open('w', encoding='utf-8') as f:
        for l in lines:
            f.write(strip_ansi(l) + '\n')


def extract_domain_and_name(full_user):
    if '\\' in full_user:
        dom, name = full_user.split('\\', 1)
        return dom, name
    return None, full_user


def should_count_user(full_user, include_machines=False, include_all=False, domain_filters=None):
    domain, name = extract_domain_and_name(full_user)
    is_machine = name.endswith('$')

    if domain_filters:
        if not domain:
            return False
        if domain.lower() not in {d.lower() for d in domain_filters}:
            return False

    if include_all:
        if not include_machines and is_machine:
            return False
        return True

    if domain and '.' in domain:
        if not include_machines and is_machine:
            return False
        return True

    return False


def export_csv(path, rows):
    p = Path(path)
    with p.open('w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['plaintext', 'count', 'users', 'services', 'reused']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({
                'plaintext': r.get('plaintext',''),
                'count': r.get('count',0),
                'users': ';'.join(r.get('users',[])),
                'services': ';'.join(r.get('services',[])),
                'reused': r.get('reused', False),
            })


def export_json(path, obj):
    p = Path(path)
    with p.open('w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2)


def main():
    ap = argparse.ArgumentParser(description='EvilParser — find password reuse from secretsdump + cracked hashes.')
    ap.add_argument('secretsdump')
    ap.add_argument('cracked')
    ap.add_argument('--full', '-f', action='store_true')
    ap.add_argument('--log', '-l')
    ap.add_argument('--export-csv')
    ap.add_argument('--export-json')
    ap.add_argument('--bloodhound')
    ap.add_argument('--kerberoast')
    ap.add_argument('--auto-tag')
    ap.add_argument('--include-machines', '-m', action='store_true')
    ap.add_argument('--include-all', '-a', action='store_true')
    ap.add_argument('--domain', '-d', action='append')
    args = ap.parse_args()

    sd_path = Path(args.secretsdump)
    cracked_path = Path(args.cracked)

    if not sd_path.exists():
        print(Fore.RED + f"Secretsdump file not found: {sd_path}")
        sys.exit(2)
    if not cracked_path.exists():
        print(Fore.RED + f"Cracked file not found: {cracked_path}")
        sys.exit(2)

    print(Fore.YELLOW + Style.BRIGHT + BANNER)

    sd = parse_secretsdump(sd_path)
    cracked = parse_hashcat_cracked(cracked_path)
    spn_by_plain, plain_by_spn = parse_kerberoast_cracked(args.kerberoast) if args.kerberoast else (defaultdict(list), {})
    bh_users = load_bloodhound_users(args.bloodhound) if args.bloodhound else set()

    user_plain = {}
    plain_users = defaultdict(list)
    for user, nthash in sd.items():
        plaintext = cracked.get(nthash)
        if plaintext:
            user_plain[user] = plaintext
            plain_users[plaintext].append(user)

    lines_for_log = []

    if args.full:
        print(Style.BRIGHT + "\nCracked users:")
        lines_for_log.append('Cracked users:')
        if not user_plain:
            msg = '  No NT hashes from secretsdump were found in the cracked file.'
            print(Fore.YELLOW + msg)
            lines_for_log.append(msg)
        else:
            max_user_len = max(len(u) for u in user_plain.keys())
            for user, plain in sorted(user_plain.items(), key=lambda x: x[0].lower()):
                user_str = user.ljust(max_user_len)
                line = f"  {user_str} -> {plain}"
                print(Fore.CYAN + f"  {user_str} " + Fore.GREEN + f"-> {plain}")
                lines_for_log.append(line)

    print(Style.BRIGHT + "\nReused passwords:")
    lines_for_log.append('Reused passwords:')

    rows_for_export = []
    printed_any = False

    for plain, users in sorted(plain_users.items(), key=lambda x: (-len(x[1]), x[0])):
        services = spn_by_plain.get(plain, [])
        if len(users) == 1 and not services:
            continue
        printed_any = True
        is_reused = len(users) > 1 or len(services) > 0
        header = f"\n  Password: {plain}  (used by {len(users)} accounts)"
        if services:
            header += f"  [services: {len(services)}]"
        print(Fore.MAGENTA + header)
        lines_for_log.append(header)

        for u in users:
            l = f"    - {u}"
            print(Fore.CYAN + l)
            lines_for_log.append(l)

        for s in services:
            l = f"    * service: {s}"
            print(Fore.YELLOW + l)
            lines_for_log.append(l)

        rows_for_export.append({
            'plaintext': plain,
            'count': len(users),
            'users': users,
            'services': services,
            'reused': is_reused,
        })

    for plain, services in spn_by_plain.items():
        if plain in plain_users:
            continue
        printed_any = True
        header = f"\n  Password (service-only): {plain}  (services: {len(services)})"
        print(Fore.YELLOW + header)
        lines_for_log.append(header)
        for s in services:
            l = f"    * service: {s}"
            print(Fore.YELLOW + l)
            lines_for_log.append(l)
        rows_for_export.append({
            'plaintext': plain,
            'count': 0,
            'users': [],
            'services': services,
            'reused': True,
        })

    if not printed_any:
        msg = '  No reused or service-linked passwords to display.'
        print(Fore.GREEN + msg)
        lines_for_log.append(msg)

    total_secretsdump_users = len(sd)
    cracked_count_total = len(user_plain)

    domain_filters = args.domain if args.domain else None
    denominator_users = [u for u in sd.keys()
                         if should_count_user(u,
                                              include_machines=args.include_machines,
                                              include_all=args.include_all,
                                              domain_filters=domain_filters)]
    denominator = len(denominator_users)

    numerator = sum(1 for u in denominator_users if u in user_plain)

    pct = (numerator / denominator * 100) if denominator else 0.0

    print(Style.BRIGHT + "\nSummary:")
    print(Fore.BLUE + f"  Secretsdump users (all): {total_secretsdump_users}")
    print(Fore.BLUE + f"  Cracked (from secretsdump, all): {cracked_count_total}")
    print(Fore.BLUE + f"  Accounts considered for percentage: {denominator}")
    print(Fore.BLUE + f"  Of those, cracked: {numerator} ({pct:.2f}%)")

    if bh_users:
        matched = 0
        for u in user_plain.keys():
            if u in bh_users:
                matched += 1
            else:
                dom, name = extract_domain_and_name(u)
                if name in bh_users:
                    matched += 1
        print(Fore.YELLOW + f"  BloodHound users matched with cracked creds: {matched} (out of {len(bh_users)})")

    if args.export_csv:
        try:
            export_csv(args.export_csv, rows_for_export)
            print(Fore.YELLOW + f"\nExported CSV to: {args.export_csv}")
        except Exception as e:
            print(Fore.RED + f"Failed to export CSV: {e}")

    if args.export_json:
        try:
            export_json(args.export_json, {'rows': rows_for_export})
            print(Fore.YELLOW + f"Exported JSON to: {args.export_json}")
        except Exception as e:
            print(Fore.RED + f"Failed to export JSON: {e}")

    if args.auto_tag:
        tags = {}
        for plain, users in plain_users.items():
            if len(users) > 1:
                for u in users:
                    tags.setdefault(u, []).append('reused')
        for plain, services in spn_by_plain.items():
            users = plain_users.get(plain, [])
            if users:
                for u in users:
                    tags.setdefault(u, []).append('service-password')
                for s in services:
                    tags.setdefault(s, []).append('service-password')
            else:
                for s in services:
                    tags.setdefault(s, []).append('service-only')
        try:
            export_json(args.auto_tag, tags)
            print(Fore.YELLOW + f"\nWrote auto-tags to: {args.auto_tag}")
        except Exception as e:
            print(Fore.RED + f"Failed to write auto-tags: {e}")

    if args.log:
        try:
            write_log(args.log, lines_for_log)
            print(Fore.YELLOW + f"\nWrote log to: {args.log}")
        except Exception as e:
            print(Fore.RED + f"Failed to write log: {e}")

    print(Style.DIM + "\nDone.")


if __name__ == '__main__':
    main()
