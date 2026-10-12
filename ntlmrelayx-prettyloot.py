#!/usr/bin/env python3
"""
ntlmrelayx-prettyloot - enum4linux-style pretty-printer for ntlmrelayx LDAP loot dirs.

Loot generation:
    screen 1 => ntlmrelayx.py -t ldap://dc-ip --no-da --no-acl -l /tmp/loot
    screen 2 => responder -I eth0

The loot files (domain_policy.json, domain_users.json, domain_groups.json,
domain_computers.json, domain_trusts.json) are written by ldapdomaindump (bundled
with impacket), which serializes LDAP entries via ldap3's entry_to_json().

VALUE FORMATS DIFFER ACROSS ldap3 VERSIONS - this tool normalizes all of them:
  * ldap3 >= 2.6 with schema: interval attributes (maxPwdAge, minPwdAge,
    lockoutDuration, lockOutObservationWindow) are converted to
    datetime.timedelta and serialized as str(timedelta), e.g.
    "1 day, 0:00:00", "0:30:00", and "999999999 days, 23:59:59.999999"
    (which is timedelta.max, the 'never' sentinel).
  * older ldap3 / no schema info: raw filetime strings, e.g. "-864000000000".
  * integers may arrive as int OR str; unset attributes appear as empty lists.

Bugs fixed vs the original script:
  * 'Minimum password length' was read from instanceType (always 4 on domain
    objects) - now correctly read from minPwdLength
  * TypeError/ValueError/KeyError crashes on string, None or missing values
  * stray 'import os.path' text inside the Groups banner
  * invalid escape sequences (Python 3.12 SyntaxWarning)

Original script by @mpgn_x64 (https://github.com/mpgn/ntlmrelayx-prettyloot),
idea credit to @ditrizna.
"""

import argparse
import json
import os
import re
import sys

# AD filetime sentinel stored in maxPwdAge/forceLogoff when the value means "never"
FILETIME_NEVER = -9223372036854775808
# str(datetime.timedelta.max) - what ldap3 produces for the sentinel above
TD_MAX_DAYS = 999999999

PWD_FLAGS = [
    (0x01, 'PASSWORD_COMPLEX'),
    (0x02, 'NO_ANON_CHANGE'),
    (0x04, 'NO_CLEAR_CHANGE'),
    (0x08, 'LOCKOUT_ADMINS'),
    (0x10, 'STORE_CLEARTEXT'),
    (0x20, 'REFUSE_PASSWORD_CHANGE'),
]

UAC_FLAGS = [
    (0x00000002, 'ACCOUNT_DISABLED'),
    (0x00000010, 'ACCOUNT_LOCKED'),
    (0x00000020, 'PASSWD_NOTREQD'),
    (0x00000080, 'STORE_CLEARTEXT'),
    (0x00000200, 'NORMAL_ACCOUNT'),
    (0x00001000, 'WORKSTATION_ACCOUNT'),
    (0x00002000, 'SERVER_TRUST_ACCOUNT'),
    (0x00010000, 'DONT_EXPIRE_PASSWD'),
    (0x00040000, 'SMARTCARD_REQUIRED'),
    (0x00080000, 'TRUSTED_FOR_DELEGATION'),
    (0x00100000, 'NOT_DELEGATED'),
    (0x00200000, 'USE_DES_KEY_ONLY'),
    (0x00400000, 'DONT_REQ_PREAUTH'),
    (0x00800000, 'PASSWORD_EXPIRED'),
    (0x01000000, 'TRUSTED_TO_AUTH_FOR_DELEGATION'),
    (0x04000000, 'PARTIAL_SECRETS_ACCOUNT'),
]

WELL_KNOWN_SIDS = {
    'S-1-1-0': 'Everyone',
    'S-1-5-4': 'NT AUTHORITY\\INTERACTIVE',
    'S-1-5-11': 'NT AUTHORITY\\Authenticated Users',
    'S-1-5-17': 'NT AUTHORITY\\IUSR',
    'S-1-5-18': 'NT AUTHORITY\\SYSTEM',
    'S-1-5-19': 'NT AUTHORITY\\LOCAL SERVICE',
    'S-1-5-20': 'NT AUTHORITY\\NETWORK SERVICE',
    'S-1-5-32-544': 'BUILTIN\\Administrators',
    'S-1-5-32-545': 'BUILTIN\\Users',
    'S-1-5-32-548': 'BUILTIN\\Account Operators',
    'S-1-5-32-549': 'BUILTIN\\Server Operators',
    'S-1-5-32-551': 'BUILTIN\\Backup Operators',
}

TRUST_DIRECTIONS = {0: 'DISABLED', 1: 'INBOUND', 2: 'OUTBOUND', 3: 'BIDIRECTIONAL'}
TRUST_TYPES = {1: 'DOWNLEVEL', 2: 'UPLEVEL', 3: 'MIT'}
TRUST_ATTRS = [
    (0x00000001, 'NON_TRANSITIVE'),
    (0x00000002, 'UPLEVEL_ONLY'),
    (0x00000004, 'QUARANTINED_DOMAIN'),
    (0x00000008, 'FOREST_TRANSITIVE'),
    (0x00000010, 'CROSS_ORGANIZATION'),
    (0x00000020, 'WITHIN_FOREST'),
    (0x00000040, 'TREAT_AS_EXTERNAL'),
    (0x00000400, 'PIM_TRUST'),
    (0x00000200, 'CROSS_ORG_NO_TGT_DELEGATION'),
    (0x00000800, 'CROSS_ORG_ENABLE_TGT_DELEGATION'),
]

# matches str(datetime.timedelta): "1 day, 0:00:00", "0:30:00", "-2 days, 3:00:00.500000"
_TD_RE = re.compile(
    r'^\s*(?P<sign>-)?\s*(?:(?P<days>\d+)\s+days?(?:,\s*)|\s*)?'
    r'(?:(?P<h>\d+):)?(?P<m>\d+):(?P<s>\d+(?:\.\d+)?)\s*$'
)
# matches the first "KEY=value" component of a DN, honouring "\,"-escaped commas
_DN_COMP_RE = re.compile(r'^\s*([A-Za-z]+)=((?:\\.|[^,\\])+)')
_NUMERIC_RE = re.compile(r'^[+-]?\d+(?:\.\d+)?$')


class UnknownInterval(ValueError):
    """Value is not a recognizable AD interval representation."""


def to_int(value):
    """Coerce an LDAP attribute value to int; None if not numeric."""
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    s = str(value).strip()
    if _NUMERIC_RE.match(s):
        return int(float(s))
    return None


def interval_seconds(value):
    """
    Normalize any serialized AD interval attribute to non-negative whole seconds.
    Returns None for 'never' / 'not set'. Raises UnknownInterval if unparseable.
    """
    if value is None:
        return None
    if isinstance(value, int):
        if value == FILETIME_NEVER or value == 0:
            return None
        return abs(value) // 10000000
    s = str(value).strip()
    if not s or s.lower() in ('none', 'not set'):
        return None
    if _NUMERIC_RE.match(s):                       # raw filetime, e.g. "-864000000000"
        i = int(float(s))
        if i == FILETIME_NEVER or i == 0:
            return None
        return abs(i) // 10000000
    m = _TD_RE.match(s)                            # str(timedelta), e.g. "1 day, 0:00:00"
    if m:
        days = int(m.group('days') or 0)
        if days >= TD_MAX_DAYS:                    # timedelta.max = 'never'
            return None
        secs = days * 86400 + int(m.group('h') or 0) * 3600 \
            + int(m.group('m')) * 60 + float(m.group('s'))
        return int(abs(secs))
    raise UnknownInterval(s)


def human_interval(value):
    """Pretty-print an AD interval value in days/hours/minutes (enum4linux style)."""
    try:
        secs = interval_seconds(value)
    except UnknownInterval:
        return 'Unknown (%r)' % (value,)
    if secs is None:
        return 'Not Set'
    if secs == 0:
        return 'None'
    days, secs = divmod(secs, 86400)
    hrs, secs = divmod(secs, 3600)
    mins = secs // 60
    out = []
    if days:
        out.append('%d day%s' % (days, 's' if days > 1 else ''))
    if hrs:
        out.append('%d hour%s' % (hrs, 's' if hrs > 1 else ''))
    if mins or not out:
        out.append('%d minute%s' % (mins, 's' if mins > 1 else ''))
    return ' '.join(out)


def decode_flags(value, flags):
    """Return names of set bits in a bitwise-flag attribute."""
    v = to_int(value)
    if v is None:
        return None
    return [name for mask, name in flags if v & mask]


def attr(entry, name, default=None):
    """
    Safe attribute lookup on a serialized ldap3 entry.
    Handles: missing 'attributes' dict, missing attribute, empty value list.
    Returns the first value (ldap3 always stores lists).
    """
    values = entry.get('attributes', {}).get(name, [])
    if not values:
        return default
    v = values[0]
    return default if v is None else v


def attr_list(entry, name):
    """Return all values of an attribute as a list (empty if unset)."""
    values = entry.get('attributes', {}).get(name, [])
    if values is None:
        return []
    return values if isinstance(values, list) else [values]


def load_json(path, required=True, label=None):
    label = label or os.path.basename(path)
    if not os.path.isfile(path):
        if required:
            print('[-] Missing loot file: %s' % path)
            sys.exit(1)
        return None
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print('[-] Failed to parse %s: %s' % (path, e))
        return None


def banner(title, width=43):
    print('+' + '-' * width + '+')
    print('| %s%s|' % (title, ' ' * (width - len(title) - 2)))
    print('+' + '-' * width + '+')
    print()


def dn_first_component(dn):
    """Extract the value of the first DN component, handling escaped commas."""
    m = _DN_COMP_RE.match(dn)
    if not m:
        return dn
    return m.group(2).replace('\\,', ',').replace('\\=', '=')


def domain_name_from_policy(entry):
    """Domain label: prefer the 'dc' attribute, fall back to parsing the DN."""
    dc = attr(entry, 'dc')
    if dc:
        return str(dc)
    dn = attr(entry, 'distinguishedName', '')
    m = re.match(r'^DC=([^,]+)', str(dn), re.I)
    if m:
        return m.group(1)
    return 'unknown'


# ---------------------------------------------------------------- sections

def print_domain_info(domain):
    entry = domain[0] if domain else {}
    banner('Getting Domain Sid For')
    print('[+] Domain Name:', domain_name_from_policy(entry))
    print('Domain Sid:', attr(entry, 'objectSid', 'Not Set'))
    print()


def print_password_policy(domain):
    entry = domain[0] if domain else {}
    banner('Password Policy Information')
    print('[+] Password Info for Domain:', domain_name_from_policy(entry).upper())
    print('\t[+] Minimum password length:', attr(entry, 'minPwdLength', 'Not Set'))
    print('\t[+] Password history length:', attr(entry, 'pwdHistoryLength', 'Not Set'))

    pwd_props = attr(entry, 'pwdProperties')
    names = decode_flags(pwd_props, PWD_FLAGS) or []
    print('\t[+] Password Complexity Flags:', pwd_props if pwd_props is not None else 'Not Set',
          ('(%s)' % ', '.join(names)) if names else '')
    if names:
        for name in names:
            print('\t\t[+] %s' % name)
    print()
    print('\t[+] Maximum password age:', human_interval(attr(entry, 'maxPwdAge')))
    print('\t[+] Minimum password age:', human_interval(attr(entry, 'minPwdAge')))
    print('\t[+] Reset Account Lockout Counter:', human_interval(attr(entry, 'lockoutDuration')))
    print('\t[+] Account Lockout Threshold:', attr(entry, 'lockoutThreshold', 'Not Set'))
    print('\t[+] Forced Log off Time:', human_interval(attr(entry, 'forceLogoff')))
    print('\t[+] Machine Account Quota:', attr(entry, 'ms-DS-MachineAccountQuota', 'Not Set'))
    print()


def print_user_info(users, dc):
    banner('Users Info')
    spn_users = []
    for user in users:
        sam = str(attr(user, 'sAMAccountName', '?'))
        name = str(attr(user, 'name', ''))
        desc = attr(user, 'description')
        desc = str(desc) if desc is not None else '(null)'
        uac = attr(user, 'userAccountControl')
        flags = decode_flags(uac, UAC_FLAGS) or []
        spns = [str(s) for s in attr_list(user, 'servicePrincipalName')]
        if spns:
            spn_users.append((sam, spns))
        line = 'Account: %s\\%s\tName: %s\tDesc: %s' % (dc, sam, name, desc)
        if flags:
            line += '\tFlags: %s' % ', '.join(flags)
        print(line)
    print()

    for user in users:
        print('user:[%s]' % attr(user, 'sAMAccountName', '?'))
    print()

    if spn_users:
        print('[+] Kerberoastable accounts (servicePrincipalName set):')
        for sam, spns in spn_users:
            print('\tuser:[%s] -> %s' % (sam, ', '.join(spns)))
        print()


def print_group_info(groups, dc):
    banner('Groups Info')
    for group in groups:
        print('group:[%s]' % attr(group, 'name', '?'))
    print()

    for group in groups:
        members = [str(m) for m in attr_list(group, 'member')]
        if not members:
            continue
        print('[+] Getting domain group memberships:')
        gname = attr(group, 'name', '?')
        for member_dn in members:
            user = dn_first_component(member_dn)
            if user in WELL_KNOWN_SIDS:
                user = WELL_KNOWN_SIDS[user]
            print("\tGroup '%s' has member: %s\\%s" % (gname, dc, user))
    print()


def print_computer_info(computers):
    banner('Computers / Domain Controllers')
    os_counts = {}
    dcs = []
    for comp in computers:
        os_name = str(attr(comp, 'operatingSystem', 'Unknown'))
        os_counts[os_name] = os_counts.get(os_name, 0) + 1
        uac = to_int(attr(comp, 'userAccountControl')) or 0
        if uac & 0x2000:  # SERVER_TRUST_ACCOUNT
            host = str(attr(comp, 'dNSHostName', attr(comp, 'cn', '?')))
            dcs.append('%s (%s)' % (host, os_name))
    for os_name, count in sorted(os_counts.items(), key=lambda x: -x[1]):
        print('\t[+] %-40s : %d' % (os_name, count))
    print()
    if dcs:
        print('[+] Domain Controllers:')
        for dc in dcs:
            print('\t%s' % dc)
        print()


def print_trust_info(trusts):
    banner('Domain Trusts')
    if not trusts:
        print('[-] No domain trusts found')
        print()
        return
    for trust in trusts:
        name = attr(trust, 'cn', attr(trust, 'flatName', '?'))
        direction = TRUST_DIRECTIONS.get(to_int(attr(trust, 'trustDirection')), 'UNKNOWN')
        ttype = TRUST_TYPES.get(to_int(attr(trust, 'trustType')), 'UNKNOWN')
        attrs = decode_flags(attr(trust, 'trustAttributes'), TRUST_ATTRS) or []
        print('\t[+] Trust: %s' % name)
        print('\t\tDirection: %s\tType: %s' % (direction, ttype))
        if attrs:
            print('\t\tAttributes: %s' % ', '.join(attrs))
    print()


# ---------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(
        description='Convert an ntlmrelayx LDAP loot directory into enum4linux-like output.')
    parser.add_argument('lootdir', help='loot directory (produced by ntlmrelayx -l/--lootdir)')
    args = parser.parse_args()

    lootdir = args.lootdir
    if not os.path.isdir(lootdir):
        print('[-] Not a directory: %s' % lootdir)
        sys.exit(1)

    domain = load_json(os.path.join(lootdir, 'domain_policy.json'), required=True)
    if domain is None:
        sys.exit(1)
    users = load_json(os.path.join(lootdir, 'domain_users.json'), required=False) or []
    groups = load_json(os.path.join(lootdir, 'domain_groups.json'), required=False) or []
    computers = load_json(os.path.join(lootdir, 'domain_computers.json'), required=False)
    trusts = load_json(os.path.join(lootdir, 'domain_trusts.json'), required=False)

    entry = domain[0] if domain else {}
    dc = domain_name_from_policy(entry).upper()

    print_domain_info(domain)
    print_password_policy(domain)
    if users:
        print_user_info(users, dc)
    else:
        print('[-] domain_users.json missing or empty - skipping users section\n')
    if groups:
        print_group_info(groups, dc)
    else:
        print('[-] domain_groups.json missing or empty - skipping groups section\n')
    if computers is not None:
        print_computer_info(computers)
    if trusts is not None:
        print_trust_info(trusts)


if __name__ == '__main__':
    main()