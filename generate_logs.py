"""Synthetic security logs for the analysis pipeline.

Three things this generator has to get right, and used to get wrong:

1. **A time span.** Every entry landed inside a 60-second window
   (`timedelta(seconds=random.randint(1, 60))`), so five thousand events
   happened in under a minute. Nothing could be plotted over time and no
   analysis of "when" was possible. The span is now a full week.

2. **Reproducibility.** The window started at `datetime.now()`, so every run
   produced a different file and the committed report stopped matching the
   committed log. The clock is now a fixed date and the seed is fixed too:
   same code, same log, same report.

3. **Signal.** Every IP behaved identically, so the top-five-failed-logins
   table came out flat -- 10, 10, 10, 9, 9 -- and ranking it told you nothing.
   A real intrusion is a handful of hosts hammering the door: a small set of
   attacker IPs now concentrates the failures, and they work at night, which
   is what the ranking and the hourly chart are supposed to reveal.
"""

import random
from datetime import datetime, timedelta

SEED = 20260105
START = datetime(2026, 1, 5, 0, 0, 0)
DAYS = 7
ENTRIES = 5000

# The handful of hosts doing the knocking, and the ordinary ones.
ATTACKER_IPS = [f"192.168.1.{n}" for n in range(201, 209)]
NORMAL_IPS = [f"192.168.1.{n}" for n in range(10, 190)]

# Business traffic clusters in office hours; the attacks run while nobody
# is watching. Weights per hour of day, 0..23.
BUSINESS_HOURS = [1, 1, 1, 1, 1, 1, 2, 5, 12, 18, 20, 18,
                  14, 16, 20, 19, 16, 12, 8, 5, 3, 2, 1, 1]
NIGHT_HOURS = [18, 20, 19, 16, 12, 8, 4, 2, 1, 1, 1, 1,
               1, 1, 1, 1, 1, 1, 2, 3, 5, 8, 12, 16]

USERS_OK = ["admin", "user1", "operador"]
USERS_FAIL = ["admin", "user1", "operador", "guest"]
RESOURCES = ["/admin", "/db_config", "/sales_data"]


def _stamp(rng, weights):
    """A moment inside the week, with the hour drawn from `weights`."""
    day = rng.randrange(DAYS)
    hour = rng.choices(range(24), weights=weights, k=1)[0]
    return START + timedelta(
        days=day, hours=hour, minutes=rng.randrange(60), seconds=rng.randrange(60)
    )


def _message(event, rng):
    if event in ("LOGIN_FAILED", "BRUTE_FORCE_ATTEMPT"):
        return f"User {rng.choice(USERS_FAIL)} failed to log in."
    if event == "LOGIN_SUCCESS":
        return f"User {rng.choice(USERS_OK)} logged in successfully."
    if event == "ACCESS_DENIED":
        return f"Unauthorized access attempt to {rng.choice(RESOURCES)}."
    return "Suspicious activity: Port scan detected."


def generate_entries(num_entries=ENTRIES, seed=SEED):
    """The week's entries, in chronological order."""
    rng = random.Random(seed)
    filas = []

    # Roughly a quarter of the traffic is the attackers. The proportions of
    # each event type stay close to the original mix.
    hostiles = int(num_entries * 0.26)
    for _ in range(hostiles):
        event = rng.choices(
            ["LOGIN_FAILED", "BRUTE_FORCE_ATTEMPT", "PORT_SCAN_DETECTED", "ACCESS_DENIED"],
            weights=[0.46, 0.24, 0.18, 0.12], k=1,
        )[0]
        filas.append((_stamp(rng, NIGHT_HOURS), rng.choice(ATTACKER_IPS), event))

    for _ in range(num_entries - hostiles):
        event = rng.choices(
            ["LOGIN_SUCCESS", "LOGIN_FAILED", "ACCESS_DENIED"],
            weights=[0.88, 0.09, 0.03], k=1,
        )[0]
        filas.append((_stamp(rng, BUSINESS_HOURS), rng.choice(NORMAL_IPS), event))

    # A log arrives in order. Sorting also stops the file from advertising
    # which half of it was generated first.
    filas.sort(key=lambda f: f[0])
    return [
        f'{t.strftime("%Y-%m-%d %H:%M:%S")} {ip} [{ev}] {_message(ev, rng)}'
        for t, ip, ev in filas
    ]


def generate_logs_file(filename, num_entries=ENTRIES):
    """Generates a file with synthetic log entries."""
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(generate_entries(num_entries)) + "\n")


if __name__ == "__main__":
    generate_logs_file("security_logs.txt", ENTRIES)
    print(f"Synthetic Security Logs generated successfully ({ENTRIES} entries).")
