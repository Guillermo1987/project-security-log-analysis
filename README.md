# Security Log Analysis — SIEM Simulation

> **Cybersecurity Portfolio Project** · Python · SIEM · Threat Detection
> **Status:** Finished · Portfolio showcase (2026-04)

[![Portfolio](https://img.shields.io/badge/Portfolio-proyectos--personales.web.app-60a5fa?style=for-the-badge&logo=firebase&logoColor=white)](https://proyectos-personales.web.app)
[![ISC2 CC](https://img.shields.io/badge/ISC2-Certified%20in%20Cybersecurity-00A651?style=for-the-badge&logo=isc2&logoColor=white)](.)
[![SIEM](https://img.shields.io/badge/Tool-SIEM%20Simulation-000000?style=for-the-badge&logo=splunk&logoColor=white)](.)

---

## Project Status

| Phase | Status |
|---|---|
| Synthetic log generation (5,000 lines) | Done |
| Parser + regex-based event extraction | Done |
| Brute-force & anomaly detection | Done |
| Incident report generation | Done |

**Current phase:** portfolio showcase — valida la aplicación práctica de la certificación ISC2 CC.

---

## Project Overview

Este proyecto demuestra competencia como **Analista de Ciberseguridad** aplicando los principios de un sistema **SIEM (Security Information and Event Management)**. Analiza logs de seguridad simulados para identificar patrones de ataque, usuarios comprometidos y actividades anómalas.

Valida en la práctica la certificación **ISC2 Certified in Cybersecurity (CC)** con experiencia real en detección de amenazas.

---

## Skills Demostradas

- **Análisis de Logs:** Python + regex para parsear grandes volúmenes de logs
- **Detección de Amenazas:** identificación de fuerza bruta y escaneo de puertos
- **Reporte de Incidentes:** informe estructurado con métricas clave y topología de ataque
- **Programación defensiva:** Python (`re`, `collections`)
- **Conceptos SIEM:** correlación de eventos y triaje de IPs sospechosas

---

## Hallazgos Clave

- Alto volumen de intentos de login fallidos con patrón de **fuerza bruta** desde IPs específicas
- Distribución de eventos: `LOGIN_SUCCESS`, `ACCESS_DENIED`, `PORT_SCAN`, etc.
- Top 5 IPs sospechosas identificadas → listas para blocklist inmediata
- Ver detalle completo en [`security_analysis_report.md`](security_analysis_report.md)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| Libraries | `re`, `collections` (stdlib) |
| Output | Markdown report |

---

## Repository Structure

```
project-security-log-analysis/
├── security_logs.txt              # 5,000 líneas de logs sintéticos
├── generate_logs.py               # generador del dataset
├── log_analysis.py                # script principal de análisis
└── security_analysis_report.md    # reporte final de incidentes
```

---

## How to Run

```bash
git clone https://github.com/Guillermo1987/project-security-log-analysis.git
cd project-security-log-analysis

python log_analysis.py
# Output: security_analysis_report.md con eventos + IPs sospechosas
```

---

## Links

- **Portfolio:** [proyectos-personales.web.app](https://proyectos-personales.web.app)
- **LinkedIn:** [Guillermo Ubeda Garay](https://www.linkedin.com/in/guillermo-alejandro-%C3%BA-027a3a120/?locale=en_US)
- **Email:** guille.ubeda.garay@gmail.com

---

*Built by [Guillermo Ubeda](https://github.com/Guillermo1987) · Data & BI Analyst · MBA · ISC2 CC*
