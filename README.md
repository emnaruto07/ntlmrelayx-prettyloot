# ntlmrelayx-prettyloot

Convert the loot directory of **ntlmrelayx** (LDAP relay attack) into an **enum4linux-style** output after you dump the domain info using LDAP!

This is a hardened fork of [mpgn/ntlmrelayx-prettyloot](https://github.com/mpgn/ntlmrelayx-prettyloot) (idea credit to [@ditrizna](https://twitter.com/ditrizna/status/1103964505510416384)).

### Why this fork

The original script crashes with modern impacket/ldap3 stacks:

```
TypeError: bad operand type for abs(): 'str'
ValueError: invalid literal for int() with base 10: '1 day, 0:00:00'
```

**Root cause:** the loot JSONs are written by `ldapdomaindump` via ldap3's `entry_to_json()`. Depending on the ldap3 version and whether schema info was available during the relay, interval attributes (`maxPwdAge`, `minPwdAge`, `lockoutDuration`, ...) arrive in *different shapes*:

| ldap3 version / conditions | loot contains | example |
|---|---|---|
| old / no schema | raw filetime string | `"-864000000000"` |
| >= 2.6 with schema | `str(datetime.timedelta)` | `"1 day, 0:00:00"` |
| "never" sentinel | `str(timedelta.max)` | `"999999999 days, 23:59:59.999999"` |
| integers | may be int or str | `7` or `"7"` |

This fork **normalizes all shapes** and adds:

- ✅ No crashes on missing/None/empty/malformed attributes (`Not Set` instead)
- ✅ Fixed real bug: *Minimum password length* read `instanceType` (always 4) instead of `minPwdLength`
- ✅ Decoded flags: password complexity, userAccountControl (disabled, locked, no-expire, delegation, ...)
- ✅ **Kerberoastable account list** (accounts with servicePrincipalName)
- ✅ Computers/OS breakdown + Domain Controller detection (UAC `SERVER_TRUST_ACCOUNT`)
- ✅ Domain trust parsing (direction, type, attributes incl. PIM, quarantined, TREAT_AS_EXTERNAL)
- ✅ Well-known SID translation (Authenticated Users, INTERACTIVE, SYSTEM, ...)
- ✅ Correct DN parsing incl. escaped commas (`CN=Smith\, John`)
- ✅ argparse CLI, proper exit codes, no SyntaxWarnings on Python 3.12+

### Usage

```
# dump the loot
screen 1 => ntlmrelayx.py -t ldap://dc-ip --no-da --no-acl -l /tmp/loot
screen 2 => responder -I eth0

# pretty-print it
python3 ntlmrelayx-prettyloot.py /tmp/loot
```

### Tests

```
python3 test_prettyloot.py
```

Covers all three loot shapes, sentinels, missing files, empty lists, escaped DNs, and CLI failure modes.

### License

Same as upstream (MIT-style, credit to mpgn).