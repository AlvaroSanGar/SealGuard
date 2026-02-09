import subprocess
import sys
import json
import platform
from collections import defaultdict

# Esta función sirve para realizar una consulta con OSqueryi
def ejecutar_consulta(query):
    try:
        resultado = subprocess.run(
            ["osqueryi", "--json", query],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(resultado.stdout)
    
    except FileNotFoundError:
        print("[ERROR] No se ha encontrado osqueryi")
        sys.exit(1)
    except Exception as e:
        print("[ERROR] Fallo al ejecutar consulta Osquery: "+str(e))
        return []
    
    
# Para el módulo de networking
def obtener_interfaces_red():
    try:
        # ejecuta ip -o addr show y lo guardamos en formato stirng
        resultado = subprocess.run(
            ["ip", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            check=True
        )
    except Exception as e:
        print("[ERROR] Fallo al listar las interfaces del sistema: "+e+"\n")
        sys.exit(1)

    interfaces = defaultdict(list)
    for linea in resultado.stdout.splitlines():
        partes = linea.split() # segmentamos en trocitos cada línea
        
        if len(partes) >= 4:
            nombreIn = partes[1]
            tipo = partes[2] # IPv4 o IPv6
            ipEnmascarada = partes[3]
            ip = ipEnmascarada.split('/')[0]

            interfaces[nombreIn].append({
                "tipo": tipo,
                "ip": ip
            })
            
    return dict(interfaces)


# Obtener info básica
def info_sis():
    info = {
        "hostname": platform.node(),
        "sistema": platform.system(),
        "distro": "Desconocida",
        "version": "Desconocida",
        "kernel": platform.release(),
        "arquitectura": platform.machine()
    }
    data = ejecutar_consulta("SELECT name, version FROM os_version;")
    if data and len(data) > 0:
        info["distro"] = data[0].get("name", "Linux")
        info["version"] = data[0].get("version", "")
    return info



# Obtener paquetes instalados
def paquetes_instalados():
    query = "SELECT name, version FROM deb_packages;"
    resultado = ejecutar_consulta(query)
    return resultado