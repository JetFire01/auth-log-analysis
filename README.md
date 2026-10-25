# Auth log analysis — TP1 Mashup (JSON / XML)

A local command-line service written in Python that combines three data sources (two JSON, one XML) to analyse the login activity of an information system and detect suspicious behaviour.

## 1. Data sources

| File | Format | Content | Size |
|---|---|---|---|
| `data/users.json` | JSON | User accounts: `id`, `first_name`, `last_name`, `email`, `role` (`admin` / `user` / `guest`) | 100 users |
| `data/logins.xml` | XML | Login attempts: `id`, `user_id`, `timestamp`, `ip`, `status` (`success` / `fail`) | 1028 attempts (Jan – Oct 2026) |
| `data/blocklist.json` | JSON | Known malicious IP addresses: `ip`, `reason` (`malware`, `brute force`, `tor exit node`, `spam`) | 10 IPs |

## 2. How to use the service

Requirements: Python 3.10+. Only the standard library is used (`json`, `xml.etree.ElementTree`, `datetime`, `collections`, `pathlib`), so no installation is needed.

From the project root:

```bash
python3 src/auth_log_analysis/main.py
```

On start, the service loads the three files and shows a menu:

```
Loaded 100 users, 1028 logins, 10 blocklisted IPs

=== Auth log analysis ===
1. User report (by id or email)
2. IP investigation
3. Successful logins from blocklisted IPs
4. Users with many failed logins
5. Statistics over a period
0. Quit
Choice:
```

Type the number of a scenario, then answer the questions it asks. Optional parameters can be skipped by pressing Enter. After each scenario the menu is shown again; `0` quits.

Code structure (`src/auth_log_analysis/main.py`):

- **Data loading** — `load_users()`, `load_blocklist()`, `load_logins()`. The JSON files are read with `json.load`, the XML file with `ElementTree`. Because XML has no data types, ids are converted to `int` and timestamps to `datetime` while reading. Users are indexed by id and the blocklist by IP (dictionaries), so that each join is a single lookup.
- **Other function** — formatting of a user name and of a login line (a login from a blocklisted IP is flagged automatically).
- **Scenarios** — one function per scenario.
- **Menu** — reads the user input and calls the right scenario.

## 3. Scenarios

### Scenario 1 — User report

- **Input:** a user id or an email address.
- **Output:** the user's name, email and role, then the chronological list of all their login attempts (date, IP, status). Attempts coming from a blocklisted IP are flagged with the reason. A summary line gives the number of successes, failures and attempts from blocklisted IPs.
- **Data used:** `users.json` (identity, role) + `logins.xml` (attempts of that `user_id`) + `blocklist.json` (flag on the IPs).
- **Use case:** a user says "I can't log in" or "my account behaves strangely": the administrator checks the history.

```
Choice: 1
User id or email: tshuttell0@php.net

Tatiana Shuttell <tshuttell0@php.net>  role: admin
  2026-01-03 13:36:43  203.0.113.9     fail
  ...
  2026-10-04 01:19:24  203.0.113.3     success   [BLOCKLISTED: malware]
  2026-10-09 18:08:00  203.0.113.4     success
Total: 8 | success: 5 | fail: 3 | from blocklisted IPs: 1
```

### Scenario 2 — IP investigation

- **Input:** an IP address.
- **Output:** whether the IP is in the blocklist (and why), every login attempt made from it with the user concerned (name and role), and a summary: number of attempts, of successes and of different users.
- **Data used:** `blocklist.json` (status of the IP) + `logins.xml` (attempts from that IP) + `users.json` (who is behind each `user_id`).
- **Use case:** an IP appears in firewall alerts; we want to know which accounts it touched.

```
Choice: 2
IP address: 203.0.113.16

IP 203.0.113.16: BLOCKLISTED (brute force)
  2026-03-04 17:20:37  203.0.113.16    fail     Peadar Del Checolo (admin)  [BLOCKLISTED: brute force]
  2026-03-17 04:29:42  203.0.113.16    success  Keane Matfin (user)  [BLOCKLISTED: brute force]
  ...
```

### Scenario 3 — Successful logins from blocklisted IPs

- **Input:** optional role filter (`admin`, `user`, `guest`, or empty for all).
- **Output:** every *successful* login made from a blocklisted IP, i.e. accounts that are possibly compromised, with the user's role, name, email, the IP and the reason it is blocked. Administrators are listed first because their compromise is the most critical.
- **Data used:** `logins.xml` (successful attempts) + `blocklist.json` (malicious IPs and reasons) + `users.json` (contact details and role, used for filtering and sorting).
- **Use case:** produce the list of accounts whose password should be reset and whose owners should be contacted.

```
Choice: 3
Filter by role (admin/user/guest, empty = all): admin

41 successful logins from blocklisted IPs (role: admin):
  [admin] Trish Tapply      ttapplyn@hibu.com      203.0.113.8     tor exit node
  ...
```

### Scenario 4 — Users with many failed logins

- **Input:** the minimum number of failed attempts (default: 10).
- **Output:** every user with at least N failed login attempts, with the number of failures and the blocklisted IPs those failures came from (with the reason).
- **Data used:** `logins.xml` (failed attempts, grouped by user) + `users.json` (who is concerned, role) + `blocklist.json` (whether the failures came from known malicious IPs).
- **Use case:** spot accounts that are probably targeted by password guessing. A user with many failures coming from blocklisted IPs is more likely under attack than one who simply mistypes the password.

```
Choice: 4
Minimum failed attempts [10]:

Iver Sollett (admin): 20 failed attempts
  from 203.0.113.8 [BLOCKLISTED: tor exit node]
  from 203.0.113.16 [BLOCKLISTED: brute force]

Anderea Selvey (admin): 18 failed attempts
  from 203.0.113.3 [BLOCKLISTED: malware]
  from 203.0.113.7 [BLOCKLISTED: malware]
  from 203.0.113.31 [BLOCKLISTED: brute force]
...
```

### Scenario 5 — Statistics over a period

- **Input:** start date and end date (`YYYY-MM-DD`), optional role filter.
- **Output:**
  - number of attempts, successes and failures (with the failure rate);
  - number of attempts from blocklisted IPs, grouped by reason (malware, tor exit node, …);
  - the 5 most active users;
  - inactive accounts: users with no login attempt in the period (candidates for deactivation).
- **Data used:** `logins.xml` (attempts in the period) + `blocklist.json` (classification of threats) + `users.json` (names, role filter, and the full list of accounts needed to find the inactive ones).
- **Use case:** monthly security report for the administrators.

```
Choice: 5
Start date (YYYY-MM-DD): 2026-10-01
End date (YYYY-MM-DD): 2026-10-31
Filter by role (admin/user/guest, empty = all): guest

Period 2026-10-01 -> 2026-10-31, role: guest
Attempts: 11 | success: 4 | fail: 7 (64%)
Attempts from blocklisted IPs by reason:
  malware         1
  tor exit node   1
Top 5 most active users:
  Audra Boykett                2 attempts
  ...
Inactive accounts (no attempt in this period): 25
  #2    Harley Norcliffe             guest
  ...
```

## 4. Summary: data sources per scenario

| Scenario | users.json | logins.xml | blocklist.json |
|---|:-:|:-:|:-:|
| 1. User report | ✓ | ✓ | ✓ |
| 2. IP investigation | ✓ | ✓ | ✓ |
| 3. Successful logins from blocklisted IPs | ✓ | ✓ | ✓ |
| 4. Users with many failed logins | ✓ | ✓ | ✓ |
| 5. Statistics over a period | ✓ | ✓ | ✓ |

All five scenarios combine the three sources, including both formats (JSON and XML).
