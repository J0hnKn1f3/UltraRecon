# UltraRecon

**UltraRecon** es una herramienta de escaneo de puertos y detección de vulnerabilidades con integración automática a Metasploit. Diseñada para ofrecer una solución rápida, visual y potente para tareas de reconocimiento en pruebas de penetración.

---

## 🚀 Características

- Escaneo de puertos TCP (1-4024)
- Detección de vulnerabilidades comunes (basadas en CVE)
- Clasificación por criticidad (color rojo/amarillo)Update 
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
sudo su
apt update && apt upgrade
apt install git
apt install python3
git clone https://github.com/J0hnKn1f3/UltraRecon.git
cd UltraRecon
python3 ultrarecon.py
```

---

## 📂 Ejemplo de salida
```bash
[+] Escaneando 192.168.1.10...

[*] Puerto 22 abierto
[!] CVE-2020-14145 (Debilidad en autenticación OpenSSH) en el puerto 22
    Payload sugerido: linux/x86/shell_reverse_tcp
...
[+] Script Metasploit generado: autopwn.rc
[+] Lanzando Metasploit automáticamente...
```

---

Necesitas cambiar el escaneo de puertos? en el archivo UltraRecon.py busca la línea 122
``` Bash
puertos = list(range(1, 4024))  # puedes cambiarlo hasta 65535
```

Por si me querés apoyar
**BTC**: 1EhrtTerdT3FckqUoPFEpbE2tiNrmjQNND
