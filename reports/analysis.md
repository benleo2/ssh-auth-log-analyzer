# Security Log Analysis Report

## 1. Overview

This report summarizes the findings produced by the Security Log Analyzer
using the sample Linux authentication log.

The analyzer examines authentication events and identifies repeated
failed logins, targeted usernames, and potentially suspicious successful
logins.

---

## 2. Log Source

Log analyzed:

`sample_logs/auth.log`

The sample log contains SSH authentication events and sudo authentication
events.

---

## 3. Detection Rules

### Rule 1 — Repeated Failed Logins

An IP address is considered suspicious when it produces multiple failed
authentication attempts.

### Rule 2 — Brute-Force Success

An IP is classified as HIGH severity when it has at least 5 failed
authentication attempts followed by a successful login.

### Rule 3 — Repeated Username Targeting

The analyzer counts failed authentication attempts associated with each
username to identify accounts that may be repeatedly targeted.

---

## 4. Findings

### Failed Login Attempts

The analyzer identified repeated authentication failures from:

- `192.168.1.50`
- `10.0.0.25`

### Invalid Usernames

The following usernames appeared in invalid-user authentication attempts:

- `admin`
- `test`
- `guest`
- `root`

### Potential Brute-Force Success

`192.168.1.50` generated multiple failed authentication attempts and
subsequently successfully authenticated.

This is treated as a potential security incident and requires further
investigation.

---

## 5. Severity

| Severity | Condition |
|----------|-----------|
| LOW | Small number of failed attempts |
| MEDIUM | Repeated failed authentication attempts |
| HIGH | Repeated failures followed by successful authentication |

---

## 6. Recommended Investigation

For a real environment, an analyst should investigate:

1. Whether the successful login was legitimate.
2. Which account was accessed.
3. Whether the source IP is trusted.
4. What actions occurred after authentication.
5. Relevant system and cloud logs.
6. Whether other systems show activity from the same source.

---

## 7. Limitations

This analyzer uses simple rule-based detection.

A failed login does not automatically indicate malicious activity,
and a successful login after failed attempts does not prove that an
account was compromised.

The tool should therefore be used as an initial detection and triage
mechanism rather than as definitive proof of an attack.

---

## 8. Future Improvements

Possible improvements include:

- Time-window based brute-force detection
- Automatic CSV/JSON reports
- More authentication event types
- IP reputation checking
- Configurable detection thresholds
- Unit tests
- Command-line arguments
- Real-time log monitoring
