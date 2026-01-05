# 🛡️ Proyecto 2: Análisis de Logs de Seguridad (SIEM Simulation)

## Resumen del Proyecto
Este proyecto demuestra mi competencia en el rol de **Analista de Ciberseguridad** y mi manejo de los principios de un sistema **SIEM (Security Information and Event Management)**. El objetivo es analizar logs de seguridad simulados para identificar patrones de ataque, usuarios comprometidos y actividades anómalas.

Este ejercicio valida mi certificación **ISC2 Certified in Cybersecurity (CC)** con experiencia práctica en la detección de amenazas.

## Habilidades Demostradas
*   **Análisis de Logs:** Uso de Python y expresiones regulares para parsear y analizar grandes volúmenes de datos de logs.
*   **Detección de Amenazas:** Identificación de intentos de fuerza bruta y escaneo de puertos.
*   **Reporte de Incidentes:** Generación de un informe estructurado con métricas clave y topologías de ataque.
*   **Programación:** Uso de Python (re, collections).
*   **Conceptos de SIEM:** Simulación de la correlación de eventos y la identificación de IPs sospechosas.

## Estructura del Repositorio
*   `security_logs.txt`: 5000 líneas de logs de seguridad sintéticos.
*   `generate_logs.py`: Script utilizado para generar los logs.
*   `log_analysis.py`: Script principal de Python para el análisis y la generación del reporte.
*   `security_analysis_report.md`: Reporte detallado con el resumen de eventos y las IPs más activas/sospechosas.

## Hallazgos Clave (Ver `security_analysis_report.md` para detalles)
El análisis identificó un alto volumen de intentos de login fallidos y **múltiples intentos de fuerza bruta** provenientes de IPs específicas. El reporte detalla la distribución de eventos (LOGIN_SUCCESS, ACCESS_DENIED, etc.) y las 5 IPs más sospechosas, lo que permite una acción de bloqueo inmediata.

## Cómo Ejecutar
1.  Clonar el repositorio.
2.  Ejecutar el script de análisis: `python log_analysis.py`
3.  Revisar el reporte generado: `security_analysis_report.md`
