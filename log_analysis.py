import re
from collections import Counter

def analyze_logs(log_file):
    """Analyzes security logs to find key statistics and anomalies."""
    
    # Regex to extract key information: Timestamp, IP, Event, Message
    log_pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \[(.*?)\] (.*)")
    
    events = []
    ips = []
    failed_logins = 0
    brute_force_attempts = 0
    
    with open(log_file, 'r') as f:
        for line in f:
            match = log_pattern.match(line)
            if match:
                timestamp, ip, event, message = match.groups()
                events.append(event)
                ips.append(ip)
                
                if event == "LOGIN_FAILED":
                    failed_logins += 1
                if event == "BRUTE_FORCE_ATTEMPT":
                    brute_force_attempts += 1

    # 1. Count of each event type
    event_counts = Counter(events)
    
    # 2. Top 5 most active IPs
    top_ips = Counter(ips).most_common(5)
    
    # 3. IPs with high failed login attempts (potential brute force)
    failed_login_ips = [ip for ip, event in zip(ips, events) if event == "LOGIN_FAILED"]
    top_failed_login_ips = Counter(failed_login_ips).most_common(5)
    
    # 4. Generate Analysis Report
    report = "# 🛡️ Análisis de Logs de Seguridad - Reporte de Incidentes\n\n"
    report += "## Resumen de Eventos\n"
    report += f"| Evento | Conteo |\n"
    report += f"| :--- | :--- |\n"
    for event, count in event_counts.most_common():
        report += f"| {event} | {count} |\n"
    report += "\n"
    
    report += f"## Detección de Amenazas\n"
    report += f"**Intentos de Login Fallidos:** {failed_logins}\n"
    report += f"**Intentos de Fuerza Bruta Detectados:** {brute_force_attempts}\n\n"
    
    report += "## Top 5 IPs con Mayor Actividad\n"
    report += f"| IP | Conteo |\n"
    report += f"| :--- | :--- |\n"
    for ip, count in top_ips:
        report += f"| {ip} | {count} |\n"
    report += "\n"
    
    report += "## Top 5 IPs con Mayor Cantidad de Logins Fallidos\n"
    report += f"| IP | Conteo |\n"
    report += f"| :--- | :--- |\n"
    for ip, count in top_failed_login_ips:
        report += f"| {ip} | {count} |\n"
    report += "\n"
    
    return report

if __name__ == "__main__":
    report_content = analyze_logs('security_logs.txt')
    with open('security_analysis_report.md', 'w') as f:
        f.write(report_content)
    print("Security Log Analysis complete. Report saved to security_analysis_report.md.")
