"""A bounded lab deployment profile; unsupported Suricata semantics never become IPS."""
import re
from urllib.parse import unquote

PROFILE = 'dvwa-xss-http'
PATH = '/vulnerabilities/xss_r/?'
TASK = ('Write one Suricata alert for GET URI beginning /vulnerabilities/xss_r/? and containing '
        'case-insensitive <script. Avoid benign names. GET is exactly 3 bytes. '
        'Use flow:established,to_server; http.method; content:"GET"; bsize:3; '
        'http.uri; content:"/vulnerabilities/xss_r/?"; startswith; content:"<script"; nocase;. '
        'Do not claim validation or deployment.')


def supported(rule):
    # shortcut: only this audited HTTP URI profile is auto-enforced; extend with native parity tests.
    return bool(re.fullmatch(
        r'alert\s+(?:http|tcp)\s+any\s+any\s+->\s+any\s+any\s*\(\s*'
        r'msg:\s*"[^";\r\n]{1,200}"\s*;\s*flow:\s*established,to_server\s*;\s*'
        r'http\.method\s*;\s*content:\s*"GET"\s*;\s*bsize:\s*3\s*;\s*'
        r'http\.uri\s*;\s*content:\s*"/vulnerabilities/xss_r/\?"\s*;\s*startswith\s*;\s*'
        r'content:\s*"<script"\s*;\s*nocase\s*;\s*sid:\s*\d+\s*;\s*rev:\s*\d+\s*;\s*\)', rule))


def matches(method, uri):
    # Suricata's normalized URI percent-decodes once; '+' remains a URI character.
    normalized = unquote(uri, encoding='latin1')
    return method == 'GET' and normalized.startswith(PATH) and '<script' in normalized.lower()


def replay_pass(receipt):
    r = receipt.get('replay') or {}
    return (receipt.get('syntax', {}).get('ok') is True and r.get('tp', 0) >= 50
            and r.get('tn', 0) >= 50 and r.get('fp') == 0 and r.get('fn') == 0
            and len(r.get('cases', [])) >= 100 and receipt.get('gateway_parity') is True)


def shadow_pass(elapsed, matches, nonmatches):
    return elapsed >= 60 and matches >= 3 and nonmatches >= 10 and matches + nonmatches >= 20
