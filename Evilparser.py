#!/usr/bin/env python3
r"""
EvilParser (final updated)

Features:
 - Parse secretsdump output and hashcat potfiles/cracked lists
 - Correlate with BloodHound users.json and groups.json (separate flags)
 - Detect high-value groups (Domain Admins, Enterprise Admins, Schema Admins, Administrators,
   Backup Operators, Server Operators, Account Operators, DNSAdmins) using name keywords and RID suffixes
 - Normalize domains (FQDN -> NetBIOS first-label uppercase) to match secretsdump <-> BloodHound exports
 - Always prints a High-Value Group Summary under the main Summary when BH files are supplied
 - Shows cracked high-value accounts (if any) and writes all findings into the log when requested
 - CSV/JSON export, Kerberoast correlation, auto-tagging
 - Backwards compatible with your previous workflow

Usage:
  python3 EvilParser.py secretsdump.txt cracked.txt [options]

Options:
  --full                       Show full cracked user list
  --log FILE                   Write plain-text log (ANSI colors stripped)
  --export-csv FILE            Export results to CSV
  --export-json FILE           Export results to JSON
  --bloodhound-users FILE      BloodHound users.json (optional)
  --bloodhound-groups FILE     BloodHound groups.json (optional)
  --kerberoast FILE            Kerberoast cracked file (SPN:hash:plaintext)
  --auto-tag FILE              Write tags JSON for post-crack workflow
  --include-machines           Include machine accounts (usernames ending with '$') in percentage calculation
  --include-all                Ignore FQDN-only rule and include all accounts in percentage calculation
  --domain DOMAIN              Restrict percentage calculation to provided domain(s); use multiple times

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
from typing import Tuple, Dict, Set, List

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


def parse_secretsdump(path: Path) -> Dict[str, str]:
    """
    Parse secretsdump lines. Returns dict mapping full_user (domain\\user) -> nt_hash (lowercase)
    Expected secretsdump line format (fields separated by ':'):
      domain\\user:rid:lmhash:nthash:::
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


def parse_hashcat_cracked(path: Path) -> Dict[str, str]:
    """
    Parse cracked hashes in two formats:
      - domain\\user:hash:plaintext  (existing)
      - hash:plaintext                (potfile)
    Returns dict mapping nt_hash -> plaintext
    """
    out = {}
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            parts = line.split(':')
            if len(parts) == 2:
                nt_hash = parts[0].lower()
                plaintext = parts[1]
                out[nt_hash] = plaintext
                continue
            if len(parts) >= 3:
                nt_hash = parts[1].lower()
                plaintext = ':'.join(parts[2:])
                out[nt_hash] = plaintext
                continue
    return out


def parse_kerberoast_cracked(path: str) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
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


def load_bloodhound_users(path: str) -> Tuple[Dict[str, Dict], Dict[str, Set[str]]]:
    """
    Load BloodHound users JSON and return:
      - users_by_objectid: mapping objectid -> properties dict
      - username_sets: mapping of normalized username forms -> set(objectid)
    Tolerant to several BH export shapes.
    """
    users_by_objectid = {}
    username_sets = defaultdict(set)

    if not path:
        return users_by_objectid, username_sets

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
    except Exception:
        return users_by_objectid, username_sets

    nodes = None
    if isinstance(data, dict):
        nodes = data.get('nodes') or data.get('Nodes')
    if not nodes and isinstance(data, list):
        nodes = data
    if not nodes:
        for v in data.values() if isinstance(data, dict) else []:
            if isinstance(v, list) and len(v) and isinstance(v[0], dict):
                nodes = v
                break
    if not nodes:
        return users_by_objectid, username_sets

    for node in nodes:
        if not isinstance(node, dict):
            continue
        labels = node.get('labels') or []
        if isinstance(labels, str):
            labels = [labels]
        if any((isinstance(lbl, str) and lbl.lower() == 'user') for lbl in labels):
            props = node.get('properties') or node
            objid = props.get('objectid') or props.get('objectId') or node.get('objectid') or node.get('objectId')
            sam = props.get('samaccountname') or props.get('sAMAccountName') or props.get('SamAccountName')
            upn = props.get('userprincipalname') or props.get('userPrincipalName')
            name = props.get('name') or props.get('displayName')
            domain = props.get('domain') or props.get('domainname') or props.get('Domain')
            if objid:
                objid = str(objid)
                users_by_objectid[objid] = {
                    'sam': str(sam) if sam else None,
                    'upn': str(upn) if upn else None,
                    'name': str(name) if name else None,
                    'domain': str(domain) if domain else None,
                    'objectid': objid
                }
                # build resolution keys
                if sam:
                    if domain:
                        username_sets[f"{domain}\\{sam}".lower()].add(objid)
                    username_sets[sam.lower()].add(objid)
                if upn:
                    username_sets[upn.lower()].add(objid)
                    local = upn.split('@', 1)[0]
                    username_sets[local.lower()].add(objid)
                if name:
                    username_sets[name.lower()].add(objid)
    return users_by_objectid, username_sets


def load_bloodhound_groups(path: str) -> Dict[str, Dict]:
    """
    Load BloodHound groups JSON and return mapping group_key -> group_properties
    """
    groups = {}
    if not path:
        return groups
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
    except Exception:
        return groups

    nodes = None
    if isinstance(data, dict):
        nodes = data.get('nodes') or data.get('Nodes')
    if not nodes and isinstance(data, list):
        nodes = data
    if not nodes:
        for v in data.values() if isinstance(data, dict) else []:
            if isinstance(v, list) and len(v) and isinstance(v[0], dict):
                nodes = v
                break
    if not nodes:
        return groups

    for node in nodes:
        if not isinstance(node, dict):
            continue
        labels = node.get('labels') or []
        if isinstance(labels, str):
            labels = [labels]
        if any((isinstance(lbl, str) and lbl.lower() == 'group') for lbl in labels):
            props = node.get('properties') or node
            objid = props.get('objectid') or props.get('objectId') or node.get('objectid') or node.get('objectId')
            name = props.get('name') or props.get('samaccountname') or props.get('groupname') or props.get('displayName')
            members = []
            for k in ('members', 'Members', 'member', 'Member', 'memberids', 'MemberIds', 'MemberOf'):
                mv = props.get(k)
                if mv and isinstance(mv, list):
                    members = mv
                    break
            # fallback: any string-list that looks like member tokens
            if not members:
                for v in props.values():
                    if isinstance(v, list) and len(v) and isinstance(v[0], str):
                        if any((re.match(r'^S-1-5-', str(i)) or '\\' in str(i) or '@' in str(i)) for i in v):
                            members = v
                            break
            key = objid or (str(name) if name else '')
            groups[key] = {
                'objectid': str(objid) if objid else None,
                'name': str(name) if name else None,
                'members': [str(m) for m in members] if members else []
            }
    return groups


def normalize_domain_netbios(domain_str: str) -> str:
    """
    Convert domain FQDN like 'eidsvoll.kommune.no' -> NetBIOS-like 'EIDSVOLL'
    If already short, uppercase and return.
    """
    if not domain_str:
        return None
    domain = str(domain_str).strip()
    # if contains dot, take first label
    if '.' in domain:
        domain = domain.split('.', 1)[0]
    return domain.upper()


def normalize_secretsdump_user_variants(user: str) -> Set[str]:
    """
    Given a secretsdump user like 'eidsvoll.kommune.no\\sarasi-eid',
    produce a set of normalized forms to aid matching to BloodHound:
      - original (as-is)
      - netbios domain version 'EIDSVOLL\\sarasi-eid'
      - sam only 'sarasi-eid'
    """
    variants = set()
    variants.add(user)  # original
    if '\\' in user:
        dom, name = user.split('\\', 1)
        nb = normalize_domain_netbios(dom)
        if nb:
            variants.add(f"{nb}\\{name}")
        variants.add(name)
        # also lower variants
        variants.add(user.lower())
        if nb:
            variants.add(f"{nb}\\{name}".lower())
        variants.add(name.lower())
    else:
        variants.add(user.lower())
    return variants


def normalize_user_forms_from_bh(users_by_objectid: Dict[str, Dict]) -> Dict[str, str]:
    """
    Build mapping objectid -> canonical username form (prefer NETBIOS\\sam, fallback to upn or name)
    """
    out = {}
    for objid, props in users_by_objectid.items():
        sam = props.get('sam')
        upn = props.get('upn')
        domain = props.get('domain')
        name = props.get('name')
        chosen = None
        # BH domain may already be NetBIOS; but normalize domain if FQDN present
        nb = normalize_domain_netbios(domain) if domain else None
        if sam and nb:
            chosen = f"{nb}\\{sam}"
        elif sam:
            chosen = sam
        elif upn:
            chosen = upn
        elif name:
            chosen = name
        else:
            chosen = objid
        out[objid] = chosen
    return out


def strip_ansi(s: str) -> str:
    ansi = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi.sub('', s)


def write_log(path: str, lines: List[str]):
    p = Path(path)
    with p.open('w', encoding='utf-8') as f:
        for l in lines:
            f.write(strip_ansi(l) + '\n')


def extract_domain_and_name(full_user: str) -> Tuple[str, str]:
    if '\\' in full_user:
        dom, name = full_user.split('\\', 1)
        return dom, name
    return None, full_user


def should_count_user(full_user: str, include_machines: bool = False,
                      include_all: bool = False, domain_filters=None) -> bool:
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


def export_csv(path: str, rows: List[Dict]):
    p = Path(path)
    with p.open('w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['plaintext', 'count', 'users', 'services', 'reused']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({
                'plaintext': r.get('plaintext', ''),
                'count': r.get('count', 0),
                'users': ';'.join(r.get('users', [])),
                'services': ';'.join(r.get('services', [])),
                'reused': r.get('reused', False),
            })


def export_json(path: str, obj):
    p = Path(path)
    with p.open('w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2)


# High-value groups config
HIGH_VALUE_GROUP_KEYWORDS = {
    'domain-admins': ['domain admins', 'domain-admins', 'domain_admins'],
    'enterprise-admins': ['enterprise admins', 'enterprise-admins', 'enterprise_admins'],
    'schema-admins': ['schema admins', 'schema-admins', 'schema_admins'],
    'administrators': ['administrators', 'administrators(s)'],
    'backup-operators': ['backup operators', 'backup-operators', 'backup_operators'],
    'server-operators': ['server operators', 'server-operators', 'server_operators'],
    'account-operators': ['account operators', 'account-operators', 'account_operators'],
    'dns-admins': ['dnsadmins', 'dns admins', 'dns-admins', 'dns_admins'],
}

RID_TO_TAG = {
    '512': 'domain-admins',
    '519': 'enterprise-admins',
    '518': 'schema-admins',
    '544': 'administrators',
}


def identify_high_value_groups(groups: Dict[str, Dict], users_by_objectid: Dict[str, Dict],
                               objectid_to_usercanonical: Dict[str, str],
                               username_sets: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    """
    Identify high-value groups and resolve their members to canonical username forms used in objectid_to_usercanonical.
    Returns mapping tag -> set(canonical usernames)
    """
    hv = defaultdict(set)

    def resolve_member_token(tok: str):
        tok_str = str(tok)
        # direct objectid
        if tok_str in objectid_to_usercanonical:
            return objectid_to_usercanonical[tok_str]
        # SID-like token (S-1-5-...)
        if tok_str.upper().startswith('S-1-5-'):
            # try direct match to objectid
            if tok_str in objectid_to_usercanonical:
                return objectid_to_usercanonical[tok_str]
            # fallback: try to match on RID suffix -> naive heuristic
            try:
                rid = tok_str.split('-')[-1]
            except Exception:
                rid = None
            if rid:
                for oid, canonical in objectid_to_usercanonical.items():
                    if oid.endswith('-' + rid):
                        return canonical
            return tok_str
        # domain\user or upn or sam
        k = tok_str.lower()
        if k in username_sets:
            oid = next(iter(username_sets[k]))
            return objectid_to_usercanonical.get(oid, tok_str)
        # try splitting backslash to normalize domain forms (FQDN -> NETBIOS) and check username_sets
        if '\\' in tok_str:
            dom, name = tok_str.split('\\', 1)
            nb = normalize_domain_netbios(dom)
            if nb:
                k2 = f"{nb}\\{name}".lower()
                if k2 in username_sets:
                    oid = next(iter(username_sets[k2]))
                    return objectid_to_usercanonical.get(oid, tok_str)
            # also try name only
            if name.lower() in username_sets:
                oid = next(iter(username_sets[name.lower()]))
                return objectid_to_usercanonical.get(oid, tok_str)
        # last resort: return token itself
        return tok_str

    for gid, g in groups.items():
        gname = (g.get('name') or '').lower() if g.get('name') else ''
        members = g.get('members') or []
        # detect via name keywords
        for tag, kwlist in HIGH_VALUE_GROUP_KEYWORDS.items():
            if any(kw in gname for kw in kwlist):
                for m in members:
                    resolved = resolve_member_token(m)
                    if resolved:
                        hv[tag].add(resolved)
        # detect by RID suffix in objectid
        objid = g.get('objectid') or ''
        if objid:
            for rid, tag in RID_TO_TAG.items():
                if str(objid).endswith('-' + rid) or str(objid).lower().endswith('-' + rid):
                    for m in members:
                        resolved = resolve_member_token(m)
                        if resolved:
                            hv[tag].add(resolved)
    return hv


def main():
    ap = argparse.ArgumentParser(description='EvilParser — find password reuse from secretsdump + cracked hashes.')
    ap.add_argument('secretsdump', help='secretsdump output file (domain\\\\user:rid:lmhash:nthash:::)')
    ap.add_argument('cracked', help='hashcat cracked file (domain\\\\user:hash:plaintext or hash:plaintext)')
    ap.add_argument('--full', '-f', action='store_true', help='Show full output (list all cracked users and plaintexts)')
    ap.add_argument('--log', '-l', help='Write a plain-text log to this file (colors removed)')
    ap.add_argument('--export-csv', help='Export results (reused groups) to CSV')
    ap.add_argument('--export-json', help='Export results to JSON')
    ap.add_argument('--bloodhound-users', help='BloodHound users JSON file (optional)')
    ap.add_argument('--bloodhound-groups', help='BloodHound groups JSON file (optional)')
    ap.add_argument('--kerberoast', help='Optional Kerberoast cracked file (SPN:hash:plaintext)')
    ap.add_argument('--auto-tag', help='Write tags JSON for post-crack workflow')
    ap.add_argument('--include-machines', '-m', action='store_true', help="Include machine accounts (usernames ending with '$') in percentage calculation")
    ap.add_argument('--include-all', '-a', action='store_true', help='Ignore FQDN-only rule and include all accounts in percentage calculation')
    ap.add_argument('--domain', '-d', action='append', help='Restrict percentage calculation to one or more domains (can be used multiple times)')
    args = ap.parse_args()

    sd_path = Path(args.secretsdump)
    cracked_path = Path(args.cracked)

    if not sd_path.exists():
        print(Fore.RED + f"Secretsdump file not found: {sd_path}")
        sys.exit(2)
    if not cracked_path.exists():
        print(Fore.RED + f"Cracked file not found: {cracked_path}")
        sys.exit(2)

    # Banner
    print(Fore.YELLOW + Style.BRIGHT + BANNER)

    sd = parse_secretsdump(sd_path)
    cracked = parse_hashcat_cracked(cracked_path)
    spn_by_plain, plain_by_spn = parse_kerberoast_cracked(args.kerberoast) if args.kerberoast else (defaultdict(list), {})
    users_by_objectid, username_sets = load_bloodhound_users(args.bloodhound_users) if args.bloodhound_users else ({}, defaultdict(set))
    groups = load_bloodhound_groups(args.bloodhound_groups) if args.bloodhound_groups else {}

    objectid_to_usercanonical = normalize_user_forms_from_bh(users_by_objectid)

    # Build secretsdump normalized variants map for quick resolution
    sd_variants_map = {}  # user -> set(variants)
    for u in sd.keys():
        sd_variants_map[u] = normalize_secretsdump_user_variants(u)

    # Map users to plaintext (if cracked)
    user_plain = {}
    plain_users = defaultdict(list)
    for user, nthash in sd.items():
        plaintext = cracked.get(nthash)
        if plaintext:
            user_plain[user] = plaintext
            plain_users[plaintext].append(user)

    lines_for_log: List[str] = []

    # Full output (list all cracked mappings)
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

    # Reused passwords output
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
        print(Fore.MAGENTA + header if is_reused else Fore.CYAN + header)
        lines_for_log.append(strip_ansi(header))
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

    # Kerberoast-only plaintexts
    for plain, services in spn_by_plain.items():
        if plain in plain_users:
            continue
        printed_any = True
        header = f"\n  Password (service-only): {plain}  (services: {len(services)})"
        print(Fore.YELLOW + header)
        lines_for_log.append(strip_ansi(header))
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

    # Summary
    total_secretsdump_users = len(sd)
    cracked_count_total = len(user_plain)
    domain_filters = args.domain if args.domain else None
    denominator_users = [u for u in sd.keys() if should_count_user(u,
                                                                    include_machines=args.include_machines,
                                                                    include_all=args.include_all,
                                                                    domain_filters=domain_filters)]
    denominator = len(denominator_users)
    numerator = sum(1 for u in denominator_users if u in user_plain)
    pct = (numerator / denominator * 100) if denominator else 0.0

    print(Style.BRIGHT + "\nSummary:")
    s_total = f"  Secretsdump users (all): {total_secretsdump_users}"
    s_cracked_total = f"  Cracked (from secretsdump, all): {cracked_count_total}"
    s_den = f"  Accounts considered for percentage: {denominator}"
    s_num = f"  Of those, cracked: {numerator} ({pct:.2f}%)"
    print(Fore.BLUE + s_total)
    print(Fore.BLUE + s_cracked_total)
    print(Fore.BLUE + s_den)
    print(Fore.BLUE + s_num)
    lines_for_log.extend(['', s_total, s_cracked_total, s_den, s_num])

    # BloodHound quick match summary (existing behavior)
    bh_users = set()
    if objectid_to_usercanonical:
        for oid, canonical in objectid_to_usercanonical.items():
            bh_users.add(canonical)
            # also sam-only / upn forms
            sam = users_by_objectid[oid].get('sam')
            if sam:
                bh_users.add(sam)
            upn = users_by_objectid[oid].get('upn')
            if upn:
                bh_users.add(upn)
    if bh_users:
        matched = 0
        for u in user_plain.keys():
            if u in bh_users:
                matched += 1
            else:
                dom, name = extract_domain_and_name(u)
                if name in bh_users:
                    matched += 1
        bh_summary = f"  BloodHound users matched with cracked creds: {matched} (out of {len(bh_users)})"
        print(Fore.YELLOW + bh_summary)
        lines_for_log.append(bh_summary)

    # --- High-value group detection & summaries ---
    high_value_groups = {}
    if groups and objectid_to_usercanonical:
        high_value_groups = identify_high_value_groups(groups, users_by_objectid, objectid_to_usercanonical, username_sets)

    # Always print a high-value group summary if BH groups were provided
    if groups:
        print(Style.BRIGHT + "\n[HIGH-VALUE GROUP SUMMARY]")
        lines_for_log.append('[HIGH-VALUE GROUP SUMMARY]')
        if not high_value_groups:
            msg = "  No recognized high-value groups detected in groups.json."
            print(Fore.GREEN + msg)
            lines_for_log.append(msg)
        else:
            for tag in sorted(HIGH_VALUE_GROUP_KEYWORDS.keys()):
                members = sorted(list(high_value_groups.get(tag, [])))
                count = len(members)
                cracked_count = 0
                # count cracked among these members by matching to secretsdump users (with normalization)
                for m in members:
                    # check direct match in sd keys
                    found_cracked = False
                    # m may be canonical BH 'NETBIOS\\sam' or 'sam' or 'user@domain' etc.
                    for sd_user, variants in sd_variants_map.items():
                        if m.lower() in (v.lower() for v in variants):
                            if sd_user in user_plain:
                                cracked_count += 1
                                found_cracked = True
                                break
                    if not found_cracked:
                        # also compare name part
                        dom, name = extract_domain_and_name(m)
                        for sd_user, variants in sd_variants_map.items():
                            if name and any(v.lower().endswith('\\' + name.lower()) or v.lower() == name.lower() for v in variants):
                                if sd_user in user_plain:
                                    cracked_count += 1
                                    break
                pretty = tag.replace('-', ' ').title()
                line = f"  {pretty}: {count} member(s), {cracked_count} cracked"
                print(Fore.YELLOW + line if cracked_count else Fore.BLUE + line)
                lines_for_log.append(line)

    # Now list cracked high-value accounts specifically
    cracked_high_value = {}
    for tag, members in (high_value_groups.items() if high_value_groups else []):
        for m in members:
            # resolve m against secretsdump variants and user_plain
            matched = False
            for sd_user, variants in sd_variants_map.items():
                # match case-insensitive against any variant
                if any(m.lower() == v.lower() for v in variants):
                    if sd_user in user_plain:
                        cracked_high_value.setdefault(tag, []).append((sd_user, user_plain[sd_user]))
                    matched = True
                    break
            if not matched:
                # try match by name component
                dom, name = extract_domain_and_name(m)
                if name:
                    for sd_user, variants in sd_variants_map.items():
                        if any(v.lower().endswith('\\' + name.lower()) or v.lower() == name.lower() for v in variants):
                            if sd_user in user_plain:
                                cracked_high_value.setdefault(tag, []).append((sd_user, user_plain[sd_user]))
                            break

    print(Style.BRIGHT + "\n[HIGH-VALUE ACCOUNTS - CRACKED]")
    lines_for_log.append('[HIGH-VALUE ACCOUNTS - CRACKED]')
    if cracked_high_value:
        for tag, entries in cracked_high_value.items():
            pretty = tag.replace('-', ' ').title()
            print(Fore.RED + f"\n  {pretty}:")
            lines_for_log.append(f"  {pretty}:")
            for (user, pwd) in sorted(entries, key=lambda x: x[0].lower()):
                line = f"    - {user} -> {pwd}"
                print(Fore.RED + line)
                lines_for_log.append(line)
    else:
        msg = "  No high-value group members had cracked passwords."
        print(Fore.GREEN + msg)
        lines_for_log.append(msg)

    # Export CSV/JSON if requested
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

    # Auto-tagging (extended)
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
        # high-value tagging
        for tag, members in high_value_groups.items():
            for m in members:
                # try map to secretsdump users
                mapped = False
                for sd_user, variants in sd_variants_map.items():
                    if any(m.lower() == v.lower() for v in variants):
                        tags.setdefault(sd_user, []).append(tag)
                        mapped = True
                        break
                if not mapped:
                    dom, name = extract_domain_and_name(m)
                    if name:
                        for sd_user, variants in sd_variants_map.items():
                            if any(v.lower().endswith('\\' + name.lower()) or v.lower() == name.lower() for v in variants):
                                tags.setdefault(sd_user, []).append(tag)
                                break
        try:
            export_json(args.auto_tag, tags)
            print(Fore.YELLOW + f"\nWrote auto-tags to: {args.auto_tag}")
        except Exception as e:
            print(Fore.RED + f"Failed to write auto-tags: {e}")

    # Log
    if args.log:
        try:
            write_log(args.log, lines_for_log)
            print(Fore.YELLOW + f"\nWrote log to: {args.log}")
        except Exception as e:
            print(Fore.RED + f"Failed to write log: {e}")

    print(Style.DIM + "\nDone.")


if __name__ == '__main__':
    main()
