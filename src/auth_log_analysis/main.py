import json
import xml.etree.ElementTree as ET
from collections import Counter # Возвращает словарь с числом, сколько раз встретилось слово
from datetime import datetime
from pathlib import Path

DATA_DIR = Path("/Users/User1/Documents/Personal/Projects/auth-log-analysis/data")
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


# Data loading

# Import first JSON file
def load_users():
    with open(DATA_DIR / "users.json", encoding="utf-8") as f: # Find the file
        result = {} # Creating the dict
        for i in json.load(f):
            result[i["id"]] = i
        return result


# Import second JSON file
def load_blocklist():
    with open(DATA_DIR / "blocklist.json", encoding="utf-8") as f:
        data = json.load(f)
    blocklist = {}
    for entry in data:
        blocklist[entry["ip"]] = entry["reason"]
    return blocklist


# Import first XML file
def load_logins():
    root = ET.parse(DATA_DIR / "logins.xml").getroot()
    logins = []
    for node in root.findall("login"):
        logins.append({
            "id": int(node.findtext("id")),
            "user_id": int(node.findtext("user_id")),
            "time": datetime.strptime(node.findtext("timestamp"), TIME_FORMAT),
            "ip": node.findtext("ip"),
            "status": node.findtext("status"),
        })
    logins.sort(key=get_time)  # chronological order
    return logins


# Used by sort(): tells it to compare logins by their time
def get_time(login):
    return login["time"]


USERS = load_users()
BLOCKLIST = load_blocklist()
LOGINS = load_logins()


# Other function

def full_name(user):
    return f"{user['first_name']} {user['last_name']}"


# User login report
def print_login(login, show_user=False):
    line = f"{login['time']}  {login['ip']:<15} {login['status']:<8}"
    if show_user: # True in scenario 2 (IP investigation)
        user = USERS[login["user_id"]]
        line += f" {full_name(user)} ({user['role']})"
    if login["ip"] in BLOCKLIST: # used in scenarios 1 and 2
        line += f"  [BLOCKLISTED: {BLOCKLIST[login['ip']]}]"
    print(line)


def find_user(query):
    if query.isdigit():
        return USERS.get(int(query))
    for user in USERS.values():
        if user["email"].lower() == query.lower():
            return user
    return None


# Scenarios

# Scenario 1 - login history of one user, with suspicious IPs flagged
def scenario_user_report(query):
    user = find_user(query)
    if user is None:
        print("User not found")
        return
    print(f"\n{full_name(user)} <{user['email']}>  role: {user['role']}")
    history = []
    for l in LOGINS:
        if l["user_id"] == user["id"]:  # попытка этого пользователя?
            history.append(l)

    if not history:
        print(" No login attempts recorded")
        return
    success_count = 0
    fail_count = 0
    risky = 0
    for login in history:
        print_login(login)
        if login["status"] == "success":
            success_count += 1
        else:
            fail_count += 1
        if login["ip"] in BLOCKLIST:
            risky += 1
    print(f"Total: {len(history)} | success: {success_count} | "
          f"fail: {fail_count} | from blocklisted IPs: {risky}")


# Scenario 2 - everything known about one IP address
def scenario_ip_investigation(ip):
    if ip in BLOCKLIST:
        print(f"\nIP {ip}: BLOCKLISTED ({BLOCKLIST[ip]})")
    else:
        print(f"\nIP {ip}: not in blocklist")

    from_ip = []
    for login in LOGINS:
        if login["ip"] == ip:
            from_ip.append(login)
    if not from_ip:
        print("  No login attempts from this IP")
        return

    users = set()
    successes = 0
    for login in from_ip:
        print_login(login, show_user=True)
        users.add(login["user_id"])
        if login["status"] == "success":
            successes += 1
    print(f"Total: {len(from_ip)} attempts | {successes} successful | "
          f"{len(users)} different users")


# Scenario 3 - successful logins from blocklisted IPs
def scenario_compromised(role=None):
    admins = []      # admins first, their compromise is the most critical
    others = []
    for login in LOGINS:
        if login["status"] != "success":
            continue                     # skip failed attempts
        if login["ip"] not in BLOCKLIST:
            continue                     # skip safe IPs
        user = USERS[login["user_id"]]
        if role is not None and user["role"] != role:
            continue                     # skip other roles if a filter is set
        if user["role"] == "admin":
            admins.append(login)
        else:
            others.append(login)
    hits = admins + others

    if role is None:
        print(f"\n{len(hits)} successful logins from blocklisted IPs:")
    else:
        print(f"\n{len(hits)} successful logins from blocklisted IPs (role: {role}):")
    for login in hits:
        user = USERS[login["user_id"]]
        print(f"[{user['role']:<5}] {full_name(user):<28} {user['email']:<38} "
              f"{login['ip']:<15} {BLOCKLIST[login['ip']]}")


# Scenario 4 - users with many failed login attempts (possible password guessing)
def scenario_failed_logins(threshold):
    # Collect the failed attempts of each user: {user_id: [login, login, ...]}
    fails = {}
    for login in LOGINS:
        if login["status"] != "fail":
            continue
        if login["user_id"] not in fails:
            fails[login["user_id"]] = []
        fails[login["user_id"]].append(login)

    found = False
    for user_id in USERS:                # go through users in id order
        if user_id not in fails:
            continue                     # no failed attempt at all
        user_fails = fails[user_id]
        if len(user_fails) < threshold:
            continue                     # not enough failures
        found = True
        user = USERS[user_id]
        print(f"\n{full_name(user)} ({user['role']}): {len(user_fails)} failed attempts")

        bad_ips = []                     # blocklisted IPs used, without duplicates
        for login in user_fails:
            if login["ip"] in BLOCKLIST and login["ip"] not in bad_ips:
                bad_ips.append(login["ip"])
        for ip in bad_ips:
            print(f"  from {ip} [BLOCKLISTED: {BLOCKLIST[ip]}]")

    if not found:
        print(f"\nNo user with {threshold} or more failed attempts.")


# Scenario 5 - statistics over a period: success/fail, threats by type, top users, inactive accounts
def scenario_period_stats(start, end, role=None):
    period = []
    for login in LOGINS:
        if login["time"] < start or login["time"] > end:
            continue                     # outside the period
        if role is not None and USERS[login["user_id"]]["role"] != role:
            continue                     # other role
        period.append(login)

    if role is None:
        print(f"\nPeriod {start.date()} -> {end.date()}")
    else:
        print(f"\nPeriod {start.date()} -> {end.date()}, role: {role}")
    if not period:
        print("  No login attempts in this period")
        return

    success_count = 0
    fail_count = 0
    threats = Counter()          # {reason: number of attempts}
    per_user = Counter()         # {user_id: number of attempts}
    active = set()               # ids of users who tried to log in
    for login in period:
        if login["status"] == "success":
            success_count += 1
        else:
            fail_count += 1
        if login["ip"] in BLOCKLIST:
            threats[BLOCKLIST[login["ip"]]] += 1
        per_user[login["user_id"]] += 1
        active.add(login["user_id"])

    print(f"Attempts: {len(period)} | success: {success_count} | "
          f"fail: {fail_count} ({fail_count / len(period):.0%})")

    print("Attempts from blocklisted IPs by reason:")
    for reason, count in threats.most_common():
        print(f"  {reason:<15} {count}")

    print("Top 5 most active users:")
    for user_id, count in per_user.most_common(5):
        print(f"  {full_name(USERS[user_id]):<28} {count} attempts")

    inactive = []
    for user in USERS.values():
        if user["id"] in active:
            continue                     # this user was active
        if role is not None and user["role"] != role:
            continue                     # other role
        inactive.append(user)
    print(f"Inactive accounts (no attempt in this period): {len(inactive)}")
    for user in inactive:
        print(f"  #{user['id']:<4} {full_name(user):<28} {user['role']}")


# Menu

def ask_role():
    print("  Hint: admin, user or guest. Press Enter to include all roles.")
    role = input("Filter by role (admin/user/guest, empty = all): ").strip().lower()
    if role == "":
        return None              # nothing typed = no filter
    return role


def ask_date(prompt):
    while True:
        try:
            return datetime.strptime(input(prompt).strip(), "%Y-%m-%d")
        except ValueError:
            print("Format: YYYY-MM-DD")


MENU = """
=== Auth log analysis ===
1. User report (by id or email)
2. IP investigation
3. Successful logins from blocklisted IPs
4. Users with many failed logins
5. Statistics over a period
0. Quit"""


# Main program: menu loop

print(f"Loaded {len(USERS)} users, {len(LOGINS)} logins, {len(BLOCKLIST)} blocklisted IPs")
while True:
    print(MENU)
    choice = input("Choice: ").strip()
    if choice == "1":
        print(f"  Hint: an id from {min(USERS)} to {max(USERS)} (e.g. 7), "
              f"or an email (e.g. {USERS[1]['email']})")
        scenario_user_report(input("User id or email: ").strip())
    elif choice == "2":
        blocked_ips = list(BLOCKLIST)
        normal_ip = None             # first IP of the logs that is not blocklisted
        for login in LOGINS:
            if login["ip"] not in BLOCKLIST:
                normal_ip = login["ip"]
                break
        print(f"  Hint: blocklisted IPs, e.g. {blocked_ips[0]} or {blocked_ips[1]}; "
              f"a normal IP, e.g. {normal_ip}")
        scenario_ip_investigation(input("IP address: ").strip())
    elif choice == "3":
        scenario_compromised(ask_role())
    elif choice == "4":
        print("  Hint: a number, e.g. 10 or 15. Press Enter for 10")
        value = input("Minimum failed attempts [10]: ").strip()
        if value.isdigit():
            threshold = int(value)
        else:
            threshold = 10           # default if nothing (or not a number) is typed
        scenario_failed_logins(threshold)
    elif choice == "5":
        print(f"  Hint: the logs go from {LOGINS[0]['time'].date()} to "
              f"{LOGINS[-1]['time'].date()}, e.g. 2026-09-01 then 2026-09-30")
        start = ask_date("Start date (YYYY-MM-DD): ")
        end = ask_date("End date (YYYY-MM-DD): ").replace(hour=23, minute=59, second=59)
        scenario_period_stats(start, end, ask_role())
    elif choice == "0":
        break
    else:
        print("Unknown choice")