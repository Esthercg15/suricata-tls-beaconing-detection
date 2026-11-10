# suricata-tls-beaconing-detection

Laboratorio de detección de beaconing C2 sobre TLS con certificado autofirmado (Suricata + Wazuh), documentado como caso de triage SOC L1 para el portfolio de ciberseguridad de la usuaria.

**Antes de trabajar en este proyecto, lee `PROJECT.md`** — contiene el estado actual, la arquitectura, las decisiones tomadas, los errores ya resueltos y la limitación conocida (regla personalizada validada con `wazuh-logtest` pero no disparándose en vivo) que no hay que volver a investigar desde cero.

## Resumen rápido

- `README.md` (inglés, principal) y `README_es.md` (español, secundario) son los entregables del portfolio — Markdown puro, nunca HTML con imágenes en base64.
- Las capturas van en `img/`, referenciadas como `![alt](img/nombre.png)`.
- Sigue la plantilla de la casa: enlace de idioma con bandera arriba, mapeo MITRE ATT&CK, sección de "Conceptos Clave" con formato pregunta-respuesta, secciones numeradas separadas por `---`.
- Detección principal documentada: alerta de volumen anómalo de Wazuh (`rule.id: 11`), no la regla de contenido personalizada (`100100`), que quedó como limitación conocida.
