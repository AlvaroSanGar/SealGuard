import subprocess
import sys
from collections import defaultdict

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