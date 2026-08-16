# Security Log Analysis — SIEM Simulation

> **Cybersecurity portfolio project** · Python · Log analysis · Threat detection
> **Status:** Finished
> A lightweight SIEM-style analyzer that parses raw security logs, detects failed logins and brute-force patterns, and produces a threat report — the core loop of any Security Operations workflow.

> 🇬🇧 **English version first.** · 🇪🇸 **La versión en español está más abajo** → [ir a Español](#-español).

[![Ficha del proyecto](https://img.shields.io/badge/Ficha%20del%20proyecto-mindset--code.com-2c4a6e?style=for-the-badge&logo=firefoxbrowser&logoColor=white)](https://mindset-code.com/es/codigo)
[![Stack](https://img.shields.io/badge/Stack-Python%20%C2%B7%20stdlib-3776AB?style=for-the-badge&logo=python&logoColor=white)](.)
[![Domain](https://img.shields.io/badge/Domain-Cybersecurity%20%C2%B7%20SIEM-16a34a?style=for-the-badge)](.)
[![ISC2 CC](https://img.shields.io/badge/Author-ISC2%20CC-0a66c2?style=for-the-badge)](.)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

---

## The problem this solves

Every server generates thousands of log lines a day; an attack hides in the noise. The first job of a Security Operations Center is to **turn raw logs into signal** — counting failed logins, spotting brute-force bursts and ranking the IPs worth blocking. This project simulates that pipeline end to end, mirroring what a SIEM (Splunk, Wazuh, Sentinel) does at scale.

Built by an **ISC2 Certified in Cybersecurity (CC)** holder, it demonstrates log parsing, anomaly detection and threat reporting with zero external dependencies.

---

## How it works

1. **Generate** — `generate_logs.py` produces a realistic security-log file with normal and malicious traffic.
2. **Parse** — `log_analysis.py` reads each line with regex, classifying events (`LOGIN_FAILED`, etc.).
3. **Detect** — counts failed logins, flags **brute-force attempts**, and ranks the **top offending IPs** with `collections.Counter`.
4. **Report** — writes a Markdown threat report (`security_analysis_report.md`).

| Detection | Method |
|-----------|--------|
| Failed logins | event classification |
| Brute-force attempts | repeated failures per source |
| Top attacker IPs | frequency ranking (top 5) |

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.12 (standard library only — `re`, `collections`) |
| Output | Markdown threat report |
| Domain | Cybersecurity · SIEM · Log analysis |

---

## Getting started

```bash
git clone https://github.com/mindset-code/project-security-log-analysis.git
cd project-security-log-analysis

python generate_logs.py     # build a sample security log
python log_analysis.py      # analyze and write security_analysis_report.md
```

No third-party dependencies required.

---

## Repository structure

```
project-security-log-analysis/
├── generate_logs.py   # synthetic security-log generator
├── log_analysis.py    # parser + anomaly detection + report
├── LICENSE            # MIT
└── README.md
```

---

## License & contact

Released under the **[MIT License](LICENSE)**.

- **Portfolio:** [proyectos-mindset-code.web.app](https://proyectos-mindset-code.web.app)
- **Web:** [mindset-code.com](https://mindset-code.com/es)
- **Email:** contacto@mindset-code.com

---

# 🇪🇸 Español

# Security Log Analysis — Simulación SIEM

> **Proyecto de portafolio de Ciberseguridad** · Python · Análisis de logs · Detección de amenazas
> **Estado:** Terminado
> Analizador estilo SIEM ligero que parsea logs de seguridad en bruto, detecta logins fallidos y patrones de fuerza bruta, y produce un informe de amenazas — el bucle central de cualquier flujo de Security Operations.

> 🇪🇸 Traducción al español. La versión en inglés está al inicio → [ir a English](#security-log-analysis--siem-simulation).

---

## El problema que resuelve

Cada servidor genera miles de líneas de log al día; un ataque se esconde en el ruido. La primera tarea de un Centro de Operaciones de Seguridad es **convertir logs en bruto en señal** — contar logins fallidos, detectar ráfagas de fuerza bruta y rankear las IPs que conviene bloquear. Este proyecto simula ese pipeline de principio a fin, reflejando lo que un SIEM (Splunk, Wazuh, Sentinel) hace a escala.

Construido por un titular de **ISC2 Certified in Cybersecurity (CC)**, demuestra parsing de logs, detección de anomalías e informes de amenazas sin dependencias externas.

---

## Cómo funciona

1. **Generar** — `generate_logs.py` produce un archivo de log de seguridad realista con tráfico normal y malicioso.
2. **Parsear** — `log_analysis.py` lee cada línea con regex, clasificando eventos (`LOGIN_FAILED`, etc.).
3. **Detectar** — cuenta logins fallidos, marca **intentos de fuerza bruta** y rankea las **IPs más ofensivas** con `collections.Counter`.
4. **Informar** — escribe un informe de amenazas en Markdown (`security_analysis_report.md`).

| Detección | Método |
|-----------|--------|
| Logins fallidos | clasificación de eventos |
| Intentos de fuerza bruta | fallos repetidos por origen |
| IPs atacantes top | ranking de frecuencia (top 5) |

---

## Stack técnico

| Capa | Tecnología |
|------|-----------|
| Lenguaje | Python 3.12 (solo librería estándar — `re`, `collections`) |
| Salida | Informe de amenazas en Markdown |
| Dominio | Ciberseguridad · SIEM · Análisis de logs |

---

## Cómo empezar

```bash
git clone https://github.com/mindset-code/project-security-log-analysis.git
cd project-security-log-analysis

python generate_logs.py     # genera un log de seguridad de ejemplo
python log_analysis.py      # analiza y escribe security_analysis_report.md
```

Sin dependencias de terceros.

---

## Estructura del repositorio

```
project-security-log-analysis/
├── generate_logs.py   # generador de logs de seguridad sintéticos
├── log_analysis.py    # parser + detección de anomalías + informe
├── LICENSE            # MIT
└── README.md
```

---

## Licencia y contacto

Publicado bajo la **[Licencia MIT](LICENSE)**.

- **Portafolio:** [proyectos-mindset-code.web.app](https://proyectos-mindset-code.web.app)
- **Web:** [mindset-code.com](https://mindset-code.com/es)
- **Email:** contacto@mindset-code.com

---

*Mindset & Code · asesoría fiscal y tecnológica · [mindset-code.com](https://mindset-code.com/es)*
