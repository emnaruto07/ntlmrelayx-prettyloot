#!/usr/bin/env python3
"""Test harness for ntlmrelayx-prettyloot - builds synthetic loot dirs in all
known ldap3 serialization shapes and verifies output + exit codes."""
import json
import os
import shutil
import subprocess
import sys
import tempfile

SCRIPT = os.path.join(os.path.dirname(__file__), 'ntlmrelayx-prettyloot.py')

def policy(attrs):
    return [{"attributes": attrs}]

# --- Shape A: old ldap3 / no schema => raw filetime strings (the 2018 shape mpgn coded against)
SHAPE_A = {
    "dc": ["corp"],
    "distinguishedName": ["DC=corp,DC=local"],
    "objectSid": ["S-1-5-21-1-2-3-101"],
    "minPwdLength": ["7"],
    "pwdHistoryLength": ["24"],
    "pwdProperties": ["1"],
    "maxPwdAge": ["-864000000000"],
    "minPwdAge": ["-864000000000"],
    "lockoutDuration": ["-18000000000"],
    "lockoutThreshold": ["0"],
    "forceLogoff": ["-9223372036854775808"],
    "ms-DS-MachineAccountQuota": ["10"],
}

# --- Shape B: ldap3 >= 2.6 with schema => str(timedelta) everywhere (user's crash shape)
SHAPE_B = {
    "dc": ["corp"],
    "distinguishedName": ["DC=corp,DC=local"],
    "objectSid": ["S-1-5-21-1-2-3-101"],
    "minPwdLength": [7],
    "pwdHistoryLength": [24],
    "pwdProperties": [1],
    "maxPwdAge": ["1 day, 0:00:00"],          # -864000000000 filetime
    "minPwdAge": ["1 day, 0:00:00"],
    "lockoutDuration": ["0:30:00"],            # -18000000000 filetime => 30 min
    "lockoutThreshold": [0],
    "forceLogoff": ["999999999 days, 23:59:59.999999"],  # timedelta.max = never
    "ms-DS-MachineAccountQuota": [10],
}

# --- Shape C: hostile mix - missing attrs, empty lists, None, ints, weird strings
SHAPE_C = {
    "dc": ["corp"],
    # no distinguishedName
    "objectSid": ["S-1-5-21-1-2-3-101"],
    "minPwdLength": [],                      # empty list -> Not Set
    "pwdHistoryLength": [None],              # None -> Not Set
    "pwdProperties": [33],                   # 0x21 = COMPLEX + REFUSE
    "maxPwdAge": ["-9223372036854775808"],    # never
    # no minPwdAge at all     -> Not Set
    "lockoutDuration": ["0:00:00"],           # zero
    "lockoutThreshold": ["5"],
    "forceLogoff": [0],
    "ms-DS-MachineAccountQuota": [],
}

USERS = [
    {"attributes": {"sAMAccountName": ["administrator"], "name": ["Administrator"],
                    "description": ["Built-in account"],
                    "userAccountControl": ["66048"],
                    "servicePrincipalName": []}},
    {"attributes": {"sAMAccountName": ["jdoe"], "name": ["John Doe"],
                    "description": [],
                    "userAccountControl": ["512"],
                    "servicePrincipalName": ["HTTP/web.corp.local", "MSSQLSvc/db.corp.local:1433"]}},
    {"attributes": {"sAMAccountName": ["svc_backup"], "name": ["Backup Service"],
                    "userAccountControl": [514],
                    "servicePrincipalName": []}},
]

GROUPS = [
    {"attributes": {"name": ["Domain Admins"],
                    "member": ["CN=Administrator,CN=Users,DC=corp,DC=local",
                               "CN=jdoe,OU=Sales\\, HQ,DC=corp,DC=local"]}},  # escaped comma mid-DN
    {"attributes": {"name": ["Domain Users"],
                    "member": ["CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local",
                               "CN=S-1-5-18,CN=ForeignSecurityPrincipals,DC=corp,DC=local"]}},
    {"attributes": {"name": ["Empty Group"]}},                                # no member
    {"attributes": {"name": ["Weird Group"],
                    "member": ["CN=Smith\\, John,OU=People,DC=corp,DC=local"]}},  # escaped comma in CN
]

COMPUTERS = [
    {"attributes": {"cn": ["DC01$"], "dNSHostName": ["dc01.corp.local"],
                    "operatingSystem": ["Windows Server 2022 Datacenter"], "userAccountControl": ["8192"]}},  # DC
    {"attributes": {"cn": ["WS01$"], "dNSHostName": ["ws01.corp.local"],
                    "operatingSystem": ["Windows 11 Pro"], "userAccountControl": ["4096"]}},
    {"attributes": {"cn": ["WS02$"], "dNSHostName": ["ws02.corp.local"],
                    "operatingSystem": ["Windows 11 Pro"], "userAccountControl": ["4096"]}},
    {"attributes": {"cn": ["APP01$"], "dNSHostName": ["app01.corp.local"],
                    "operatingSystem": ["Windows Server 2019 Standard"], "userAccountControl": ["4096"]}},
]

TRUSTS = [
    {"attributes": {"cn": ["other.corp.local"], "flatName": ["OTHER"],
                    "trustDirection": [3], "trustType": [2], "trustAttributes": [32]}},
]


def build_loot(dirpath, shape):
    os.makedirs(dirpath, exist_ok=True)
    with open(os.path.join(dirpath, 'domain_policy.json'), 'w') as f:
        json.dump(policy(shape), f)
    with open(os.path.join(dirpath, 'domain_users.json'), 'w') as f:
        json.dump(USERS, f)
    with open(os.path.join(dirpath, 'domain_groups.json'), 'w') as f:
        json.dump(GROUPS, f)
    with open(os.path.join(dirpath, 'domain_computers.json'), 'w') as f:
        json.dump(COMPUTERS, f)
    with open(os.path.join(dirpath, 'domain_trusts.json'), 'w') as f:
        json.dump(TRUSTS, f)


def run(lootdir, expect_fail=False):
    r = subprocess.run([sys.executable, '-W', 'error::SyntaxWarning', SCRIPT, lootdir],
                       capture_output=True, text=True)
    if expect_fail and r.returncode != 0:
        return r
    if r.returncode != 0:
        raise AssertionError('exit=%d stderr=%s' % (r.returncode, r.stderr))
    if 'Traceback' in r.stderr:
        raise AssertionError('Traceback in stderr: %s' % r.stderr)
    return r


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print('  [ok]', msg)


def main():
    tmp = tempfile.mkdtemp(prefix='prettyloot-test-')
    failures = 0
    try:
        for label, shape in [('A: raw-filetime (2018 style)', SHAPE_A),
                             ('B: str(timedelta) (ldap3>=2.6, the crash shape)', SHAPE_B),
                             ('C: hostile mix (None/empty/missing/never)', SHAPE_C)]:
            print('\n== Shape %s ==' % label)
            d = os.path.join(tmp, label.split(':')[0])
            build_loot(d, shape)
            r = run(d)
            out = r.stdout

            check('Traceback' not in r.stderr, 'no traceback')
            check('invalid literal' not in r.stderr + out, 'no invalid-literal error')

            # shape-specific assertions
            if label.startswith('A'):
                check('Minimum password length: 7' in out, 'minPwdLength=7 (real fix)')
                check('Maximum password age: 1 day' in out, 'maxPwdAge 1 day (filetime)')
                check('Reset Account Lockout Counter: 30 minutes' in out, 'lockout 30 min (filetime)')
                check('Forced Log off Time: Not Set' in out, 'forceLogoff sentinel -> Not Set')
                check('instanceType' not in out, 'no bogus instanceType read')
            if label.startswith('B'):
                check('Maximum password age: 1 day' in out, 'maxPwdAge 1 day (timedelta str)')
                check('Reset Account Lockout Counter: 30 minutes' in out, 'lockout 30 min (timedelta str)')
                check('Forced Log off Time: Not Set' in out, 'timedelta.max sentinel -> Not Set')
                check('999999999' not in out, 'no raw timedelta.max leak')
            if label.startswith('C'):
                check('Minimum password length: Not Set' in out, 'empty list -> Not Set')
                check('Minimum password age: Not Set' in out, 'missing attr -> Not Set')
                check('PASSWORD_COMPLEX' in out and 'REFUSE_PASSWORD_CHANGE' in out,
                      'pwdProperties 0x21 decoded')
                check('Maximum password age: Not Set' in out, 'never sentinel -> Not Set')
                check('Reset Account Lockout Counter: None' in out, 'zero -> None')

            # common assertions (all shapes)
            check('CORP\\administrator' in out, 'user account line')
            check('user:[jdoe]' in out, 'user:[] greppable line')
            check('group:[Domain Admins]' in out, 'group:[] line')
            check('Kerberoastable' in out and 'HTTP/web.corp.local' in out,
                  'SPN extraction works')
            check('CORP\\NT AUTHORITY\\Authenticated Users' in out, 'well-known SID mapping')
            check('CORP\\Smith, John' in out, 'escaped-comma CN member parsed')
            check('group:[Weird Group]' in out, 'all groups listed')
            check('Domain Controllers:' in out and 'dc01.corp.local' in out, 'DC detection')
            check('Trust: other.corp.local' in out and 'BIDIRECTIONAL' in out, 'trust parsing')
            check('WITHIN_FOREST' in out, 'trust attr flags')

        # edge: empty trusts list
        print('\n== Shape D: empty trusts ==')
        d = os.path.join(tmp, 'D')
        build_loot(d, SHAPE_B)
        with open(os.path.join(d, 'domain_trusts.json'), 'w') as f:
            json.dump([], f)
        r = run(d)
        check('No domain trusts found' in r.stdout, 'empty trust list handled')

        # edge: users file missing entirely
        print('\n== Shape E: users/groups missing ==')
        d = os.path.join(tmp, 'E')
        build_loot(d, SHAPE_B)
        os.remove(os.path.join(d, 'domain_users.json'))
        os.remove(os.path.join(d, 'domain_groups.json'))
        r = run(d)
        check('skipping users section' in r.stdout, 'missing users handled')
        check('skipping groups section' in r.stdout, 'missing groups handled')

        # edge: nonexistent dir
        print('\n== Shape F: bad dir ==')
        r = run(os.path.join(tmp, 'does-not-exist'), expect_fail=True)
        check('Not a directory' in r.stdout, 'bad dir error message')

        print('\nALL TESTS PASSED')
    except AssertionError as e:
        print('\nFAIL: %s' % e)
        failures = 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(failures)


if __name__ == '__main__':
    main()