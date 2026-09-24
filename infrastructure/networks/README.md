# Phase 1 network zones

| Logical network | Internal | Members | Purpose |
| --- | --- | --- | --- |
| `ingress` | no | Nginx | Carries the single `127.0.0.1` host binding. |
| `dvwa_front` | yes | Nginx, DVWA | Reverse-proxy traffic only. |
| `dvwa_db` | yes | DVWA, MariaDB | DVWA database traffic only. |
| `data` | yes | PostgreSQL, Redis | Future trusted AHR-IDPS services only. |

DVWA has no external-gateway attachment. PostgreSQL and Redis are not on either
DVWA network. Docker service DNS is used instead of fixed container addresses.
