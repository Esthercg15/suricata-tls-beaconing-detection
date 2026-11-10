# Documento de proyecto — suricata-tls-beaconing-detection

> Estado, decisiones y errores ya resueltos de este laboratorio. Adjúntalo al inicio de la conversación cuando retomes este proyecto en vez de depender de la memoria entre chats.

## Objetivo

Simular el patrón de tráfico de red de un equipo infectado "llamando a casa" a su centro de mando (C2): conexiones HTTPS periódicas (beaconing) usando un certificado TLS autofirmado, y comprobar que Suricata + Wazuh lo detectan y lo correlacionan como sospechoso.

No se simula una intrusión ni toma de control real — solo el patrón de comunicación de red que generaría un host ya comprometido.

## Arquitectura

| Rol | Máquina | IP |
|---|---|---|
| C2 (servidor que espera llamadas) | Kali Linux | `192.168.18.155` |
| Víctima "infectada" (hace el beaconing) + sensor Suricata | Ubuntu-lab (hostname `ubuntu-lab`) | `192.168.18.54` |
| SIEM | Wazuh manager (`esther-ubuntu`) | `192.168.18.113` |

La dirección de la comunicación es: **`Ubuntu-lab` llama a Kali**, no al revés — Kali solo escucha, pasivo.

## Estado actual (07/11/2026)

Completado:
- Certificado autofirmado generado en Kali con OpenSSL (`cert.pem` + `key.pem`), Common Name `telemetria-segura.com`.
- Servidor C2 en Kali: script `c2_server.py` (Python, `http.server` + `ssl`), escuchando en el puerto 443, usando ese certificado.
- Script de beaconing en `Ubuntu-lab`: `beacon.sh` (bash), bucle infinito que llama a `https://192.168.18.155` cada 30 segundos con `curl -k`.
- Hostname de la VM víctima cambiado de `esther-VirtualBox` a `ubuntu-lab`, para que coincida con el nombre del agente registrado en Wazuh.
- Suricata instalado en `Ubuntu-lab`, configurado para escuchar en la interfaz `enp0s3` (la que tiene la IP `192.168.18.54`).
- Confirmado con `tail -f /var/log/suricata/eve.json` que Suricata captura el tráfico TLS del beaconing, generando eventos `"event_type":"tls"` con huella **JA4** (no JA3 — las versiones recientes de Suricata lo traen activado por defecto, sin configuración extra).

Completado (añadido):
- `extended: yes` ya estaba activo en `/etc/suricata/suricata.yaml`, pero se confirmó que con TLS 1.3 el certificado va cifrado en el handshake y Suricata (sensor pasivo) no puede ver `subject`/`issuer` — se decide dejarlo así, apoyando la detección en JA4 (ver "Decisiones tomadas").
- Agente de Wazuh en `Ubuntu-lab` configurado para leer `/var/log/suricata/eve.json`: añadido bloque `<localfile><log_format>json</log_format><location>/var/log/suricata/eve.json</location></localfile>` dentro de su propio `<ossec_config>` en `/var/ossec/etc/ossec.conf`. Confirmado con `sudo tail -n 50 /var/ossec/logs/ossec.log | grep -i suricata` → `wazuh-logcollector: INFO: (1950): Analyzing file: '/var/log/suricata/eve.json'.`
- Confirmado en el dashboard de Wazuh (Threat Hunting → Events, query `agent.name: "Ubuntu-lab" and data.event_type: "tls"`) que los eventos de Suricata llegan correctamente al manager, tanto antes como después de apagar/encender las VMs (probado dos sesiones distintas, 07/11 y 09/11).

Pendiente:
- **Siguiente paso inmediato: crear una regla personalizada en Wazuh** (en el **manager** `esther-ubuntu`, no en el agente) para que estos eventos TLS dejen de caer en la regla genérica (`rule.id: 11`, nivel 4, sin descripción) y se clasifiquen con un nivel de severidad más alto y una descripción propia (ej. detección de beaconing / certificado autofirmado). Ruta confirmada del archivo de reglas personalizadas: `/var/ossec/etc/rules/local_rules.xml` (incluir esta ruta en el README final). Pendiente: escribir la regla (sintaxis básica ya explicada: `<rule id="100100" level="10"><if_sid>...</if_sid><field name="...">...</field><description>...</description></rule>` dentro de un `<group name="suricata,">`).
- Verificar/crear la alerta correspondiente en el dashboard de Wazuh (dependiente del punto anterior).
- Capturas de pantalla: servidor C2 con las conexiones periódicas (ya conseguida), evento TLS con JA4 en `eve.json`, alerta final en Wazuh.
- Mapeo MITRE ATT&CK a confirmar — candidatos: [T1573] Encrypted Channel, [T1071.001] Web Protocols (C2 sobre HTTPS).
- Redactar README bilingüe (inglés principal, español secundario) siguiendo la plantilla del portfolio, una vez cerrado el laboratorio. **Importante:** este lab está pensado para principiantes y también le servirá a la usuaria para refrescar conceptos en el futuro, así que el README debe incluir una sección de conceptos clave explicados con detalle (qué es un certificado autofirmado y por qué se considera "falso"/sospechoso, qué es el beaconing, qué es un C2, qué es JA3/JA4 y por qué JA4 y no JA3, por qué TLS no evita la detección aunque cifre el contenido), usando un formato de pregunta-respuesta del estilo "¿Por qué te importa esto para este lab en concreto?" después de cada concepto, para conectarlo con su propósito práctico dentro del laboratorio y no dejarlo como definición abstracta.
- Publicar como repositorio independiente en GitHub (nombre propuesto: `suricata-tls-beaconing-detection`, en inglés, siguiendo la convención ya adoptada para todos los repos del portfolio) y enlazarlo desde el perfil/LinkedIn.

## Decisiones tomadas

- El dominio falso del certificado es solo texto decorativo dentro del propio certificado — no está registrado en ningún DNS público, no es alcanzable desde fuera del laboratorio. El beaconing llama directamente a la IP de Kali, no al nombre de dominio.
- Puerto 443 (no uno alternativo tipo 8443), para mayor realismo — requiere `sudo` en Kali al estar por debajo de 1024.
- El certificado autofirmado no es un mecanismo para "despistar" a Wazuh/Suricata — al contrario, es precisamente la señal que delata el tráfico como sospechoso, combinada con el patrón de beaconing. El cifrado TLS sirve para ocultar el contenido de la comunicación, no para pasar desapercibido ante los sistemas de detección.
- El servidor usa TLS 1.3 (versión por defecto en Python `ssl`), por lo que el certificado viaja cifrado dentro del handshake y Suricata (sensor pasivo, sin las claves) **no puede** extraer `subject`/`issuer`, aunque `extended: yes` esté activo — es una limitación real de TLS 1.3, no un fallo de configuración. Se decide dejarlo así (más realista) en vez de forzar TLS 1.2: la detección de este lab se apoya en la huella **JA4** + el patrón de beaconing, no en leer el certificado en claro. Esto es, de hecho, el punto pedagógico clave del lab: explica por qué JA3/JA4 existen como técnica moderna de detección.

## Errores ya cometidos y cómo se resolvieron (no repetir)

- **Reloj desincronizado tras apagar la VM:** al reiniciar `Ubuntu-lab` después de tenerla apagada un tiempo, el reloj del sistema se atrasó significativamente (~11 días), haciendo que `apt update` fallara con errores de "archivo de publicación no válido todavía". Se resolvió con `sudo timedatectl set-ntp true`. Comprobar `date` nada más encender la VM, antes de instalar o actualizar nada.
- **`mkdir` en vez de crear un archivo:** al intentar crear el script `c2_server.py`, se usó por error `mkdir nombre.py`, lo que crea una **carpeta**, no un archivo. Un archivo de texto se crea directamente abriéndolo con un editor (`nano nombre.py`), nunca con `mkdir`.
- **Variable con nombre inconsistente en el script de Python:** al editar `c2_server.py`, la variable del servidor se renombró a medias (`https` en una línea, `httpd` en otra), causando un `NameError`. Usar siempre el mismo nombre de variable en todo el script.
- **Bloqueo de `apt` tras el salto de reloj:** al corregir la fecha, un proceso automático de `apt.systemd.daily` se disparó en segundo plano y bloqueó `apt update` durante un rato. No es un fallo real, solo hay que esperar a que ese proceso termine solo.
- **Reloj desincronizado en `Ubuntu-lab` tras reiniciar la VM (segunda vez, 10/11):** mismo problema que la primera vez. `timedatectl set-ntp true` no sincronizó (sin salida a NTP en ese momento) — se corrigió a mano con `sudo date -s "YYYY-MM-DD HH:MM:SS"` (la zona horaria de la VM coincide con Europe/Madrid, así que se puede poner la hora local directamente sin conversión).
- **Regla personalizada (`local_rules.xml`) que no se disparaba:** se escribió una regla usando `<field name="event_type">tls</field>` (y también probando con `<field name="location">...`) pero nunca se activaba, ni siquiera quitando esas condiciones una a una. Diagnosticado con `sudo /var/ossec/bin/wazuh-logtest -v < archivo.json`: el decodificador genérico `json` decodifica el evento pero **no expone sus campos internos individuales** (`event_type`, `src_ip`, etc.) para que las reglas los evalúen con `<field name="...">` — esos campos solo aparecen "aplanados" más adelante, en el formateo para el indexador/dashboard, no durante la evaluación de reglas. **Solución:** usar `<match>"event_type":"tls"</match>` en vez de `<field>` — busca el texto literal dentro del log completo en bruto, sin depender de la extracción de campos. Regla final funcional:
  ```xml
  <group name="suricata,">
    <rule id="100100" level="10">
      <decoded_as>json</decoded_as>
      <match>"event_type":"tls"</match>
      <description>Suricata: conexión TLS detectada (posible beaconing con certificado autofirmado)</description>
    </rule>
  </group>
  ```
  Archivo: `/var/ossec/etc/rules/local_rules.xml` en el manager (`esther-ubuntu`). Confirmado con `wazuh-logtest`: `**Phase 3: Completed filtering (rules). id: '100100' ... **Alert to be generated.` Pendiente: confirmar que también se dispara con tráfico real en vivo (no solo en `logtest`) y que aparece en el dashboard.

## Plantilla de la casa (house style del portfolio)

Misma que en el resto de laboratorios — ver `PROJECT.md` de `ssh-bruteforce-wazuh` para la referencia completa (enlace de idioma con bandera, mapeo MITRE ATT&CK, secciones numeradas separadas por `---`, capturas en `img/`, nombre de repo en inglés).
