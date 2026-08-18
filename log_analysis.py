import json
import re
from collections import Counter, defaultdict

# Regex to extract key information: Timestamp, IP, Event, Message
LOG_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \[(.*?)\] (.*)"
)

THREAT_EVENTS = ("LOGIN_FAILED", "ACCESS_DENIED", "PORT_SCAN_DETECTED", "BRUTE_FORCE_ATTEMPT")


def analyze(log_file):
    """Reads the log once and returns the figures, with no formatting applied.

    Counting and rendering used to live in the same function, which meant the
    only way to get at these numbers was to parse the Markdown back out of the
    report. Anything else that needed them -- a dashboard, a test -- had to
    recount the file and would drift the moment the rules changed here.
    """
    events, ips = [], []
    failed_login_ips = []
    per_hour = defaultdict(Counter)
    per_day = Counter()
    unparsed = 0
    stamps = []

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            match = LOG_PATTERN.match(line)
            if not match:
                # Counted rather than skipped in silence: a log the parser does
                # not understand is a finding, not an empty result.
                unparsed += 1
                continue
            timestamp, ip, event, _message = match.groups()
            events.append(event)
            ips.append(ip)
            stamps.append(timestamp)
            per_day[timestamp[:10]] += 1
            per_hour[timestamp[11:13]][event] += 1
            if event == "LOGIN_FAILED":
                failed_login_ips.append(ip)

    event_counts = Counter(events)
    return {
        "event_counts": event_counts,
        "top_ips": Counter(ips).most_common(5),
        "top_failed_login_ips": Counter(failed_login_ips).most_common(5),
        "failed_logins": event_counts["LOGIN_FAILED"],
        "brute_force_attempts": event_counts["BRUTE_FORCE_ATTEMPT"],
        "per_hour": per_hour,
        "per_day": per_day,
        "parsed": len(events),
        "unparsed": unparsed,
        "unique_ips": len(set(ips)),
        "first": min(stamps) if stamps else None,
        "last": max(stamps) if stamps else None,
    }


def build_report(d):
    """The same Markdown report as always, now built from analyze()."""
    report = "# 🛡️ Análisis de Logs de Seguridad - Reporte de Incidentes\n\n"
    report += "## Resumen de Eventos\n"
    report += "| Evento | Conteo |\n"
    report += "| :--- | :--- |\n"
    for event, count in d["event_counts"].most_common():
        report += f"| {event} | {count} |\n"
    report += "\n"

    report += "## Detección de Amenazas\n"
    report += f"**Intentos de Login Fallidos:** {d['failed_logins']}\n"
    report += f"**Intentos de Fuerza Bruta Detectados:** {d['brute_force_attempts']}\n\n"

    report += "## Top 5 IPs con Mayor Actividad\n"
    report += "| IP | Conteo |\n"
    report += "| :--- | :--- |\n"
    for ip, count in d["top_ips"]:
        report += f"| {ip} | {count} |\n"
    report += "\n"

    report += "## Top 5 IPs con Mayor Cantidad de Logins Fallidos\n"
    report += "| IP | Conteo |\n"
    report += "| :--- | :--- |\n"
    for ip, count in d["top_failed_login_ips"]:
        report += f"| {ip} | {count} |\n"
    report += "\n"

    return report


def analyze_logs(log_file):
    """Kept as it was: read the log, get the report back."""
    return build_report(analyze(log_file))


def export_json(d, out_dir):
    """Writes the same figures as JSON, for the dashboard that shows them."""
    import os

    os.makedirs(out_dir, exist_ok=True)
    horas = sorted(d["per_hour"])
    tipos = [e for e, _ in d["event_counts"].most_common()]

    ficheros = {
        "eventos.json": [{"evento": e, "conteo": c} for e, c in d["event_counts"].most_common()],
        "top_ips.json": [{"ip": i, "conteo": c} for i, c in d["top_ips"]],
        "top_fallidos.json": [{"ip": i, "conteo": c} for i, c in d["top_failed_login_ips"]],
        "por_hora.json": [
            dict({"hora": h + ":00"}, **{t: d["per_hour"][h].get(t, 0) for t in tipos})
            for h in horas
        ],
        "por_dia.json": [{"dia": k, "conteo": v} for k, v in sorted(d["per_day"].items())],
        "resumen.json": {
            "lineas": d["parsed"] + d["unparsed"],
            "analizadas": d["parsed"],
            "ilegibles": d["unparsed"],
            "ips": d["unique_ips"],
            "fallidos": d["failed_logins"],
            "fuerza_bruta": d["brute_force_attempts"],
            "amenazas": sum(d["event_counts"][e] for e in THREAT_EVENTS),
            "tipos": tipos,
            "desde": d["first"],
            "hasta": d["last"],
        },
    }
    for nombre, contenido in ficheros.items():
        with open(os.path.join(out_dir, nombre), "w", encoding="utf-8") as f:
            json.dump(contenido, f, ensure_ascii=False, indent=1)
    return list(ficheros)


if __name__ == "__main__":
    import sys

    datos = analyze("security_logs.txt")
    with open("security_analysis_report.md", "w", encoding="utf-8") as f:
        f.write(build_report(datos))
    print("Security Log Analysis complete. Report saved to security_analysis_report.md.")

    # Optional second argument: where to drop the JSON for the dashboard.
    if len(sys.argv) > 1:
        for nombre in export_json(datos, sys.argv[1]):
            print("  %s" % nombre)
