import random
from datetime import datetime, timedelta

def generate_log_entry(start_time):
    """Generates a single synthetic log entry."""
    ip_address = f"192.168.1.{random.randint(10, 250)}"
    timestamp = (start_time + timedelta(seconds=random.randint(1, 60))).strftime("%Y-%m-%d %H:%M:%S")
    
    # Define common events and their likelihood
    events = {
        "LOGIN_SUCCESS": 0.6,
        "LOGIN_FAILED": 0.2,
        "ACCESS_DENIED": 0.1,
        "PORT_SCAN_DETECTED": 0.05,
        "BRUTE_FORCE_ATTEMPT": 0.05
    }
    
    event = random.choices(list(events.keys()), weights=list(events.values()), k=1)[0]
    
    # Add details based on the event
    if event == "LOGIN_FAILED" or event == "BRUTE_FORCE_ATTEMPT":
        user = random.choice(["admin", "user1", "guillermo", "guest"])
        message = f"User {user} failed to log in."
    elif event == "LOGIN_SUCCESS":
        user = random.choice(["admin", "user1", "guillermo"])
        message = f"User {user} logged in successfully."
    elif event == "ACCESS_DENIED":
        resource = random.choice(["/admin", "/db_config", "/sales_data"])
        message = f"Unauthorized access attempt to {resource}."
    elif event == "PORT_SCAN_DETECTED":
        message = "Suspicious activity: Port scan detected."
    
    return f"{timestamp} {ip_address} [{event}] {message}"

def generate_logs_file(filename, num_entries):
    """Generates a file with synthetic log entries."""
    start_time = datetime.now() - timedelta(hours=1)
    with open(filename, 'w') as f:
        for _ in range(num_entries):
            f.write(generate_log_entry(start_time) + '\n')

if __name__ == "__main__":
    generate_logs_file('security_logs.txt', 5000)
    print("Synthetic Security Logs generated successfully (5000 entries).")
