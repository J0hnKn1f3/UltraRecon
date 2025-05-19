# UltraRecon

**UltraRecon** es una herramienta de escaneo de puertos y detección de vulnerabilidades con integración automática a Metasploit. Diseñada por **Johnknife**, ofrece una solución rápida, visual y potente para tareas de reconocimiento en pruebas de penetración.

---

## 🚀 Características

- Escaneo de puertos TCP (1-1024)
- Detección de vulnerabilidades comunes (basadas en CVE)
- Clasificación por criticidad (color rojo/amarillo)
- Sugerencias automáticas de payloads
- Generación de scripts `.rc` para Metasploit
- Ejecución directa de Metasploit desde el script
- Detección automática del sistema operativo y LHOST

---

## 🔧 Requisitos

- Linux (recomendado: Kali Linux)
- Python 3.x
- Metasploit Framework instalado y accesible con `msfconsole`
- Permisos de red

---

## 🧠 Uso

```bash
python3 ultrarecon.py
