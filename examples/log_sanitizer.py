# ruff: noqa: RUF003
"""Sanitize parsed log data to expose hidden indicators of compromise.

Attackers embed bidi overrides and zero-width characters in log entries to
hide malicious content from analysts and pattern-matching tools. walk()
sanitizes every string in a nested structure so what you search is what's
actually there.

Usage:
    python examples/log_sanitizer.py
"""

from navi_sanitize import walk

# Simulated parsed log entries with hidden evasion characters
log_entries = [
    {
        "timestamp": "2026-03-07T14:30:00Z",
        "level": "WARNING",
        "source_ip": "192.168.1.\u200b100",  # zero-width space in IP
        "message": "Failed login for \u202eadmin\u202c",  # bidi override hides "admin"
        "user_agent": "Mozilla/5.0 (\u200bcompatible)",  # hidden ZWS
    },
    {
        "timestamp": "2026-03-07T14:30:01Z",
        "level": "ERROR",
        "source_ip": "10.0.0.1",
        "message": "SQL error in query: \x00SELECT * FROM users",  # null byte
        "payload": "p\u0430ypal.com/login",  # Cyrillic а in domain
    },
]

print("=== Before sanitization ===")
for entry in log_entries:
    print(f"  [{entry['level']}] {entry['message']!r}")
    if "payload" in entry:
        print(f"    payload: {entry['payload']!r}")

print()

clean_logs = walk(log_entries)

print("=== After sanitization ===")
for entry in clean_logs:
    print(f"  [{entry['level']}] {entry['message']!r}")
    if "payload" in entry:
        print(f"    payload: {entry['payload']!r}")

print()
print(f"Original data unchanged: {log_entries[0]['source_ip']!r}")
print(f"Clean copy:              {clean_logs[0]['source_ip']!r}")
