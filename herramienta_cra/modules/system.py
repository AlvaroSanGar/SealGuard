import subprocess   # Ejecutar comandos por consola
import json
import platform     # Sacar info del sistema
from collections import defaultdict

# Esta función sirve para realizar una consulta con OSqueryi, devolvemos una lista de diccionarios,
# así es mucho más fácil a la hora de recibir los datos, ponemos todos los parametros para que se capture el texto en vez
# de mostrarlo por pantalla, que se codifique en texto (JSON que luego tratamos con loads) y que compruebe si hay un error.
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
        return []
        
    except Exception as e:
        print("[ERROR] Fallo al ejecutar consulta Osquery: "+str(e))
        return []
    
    
# Para el módulo de networking
def obtener_interfaces():
    try:
        # Con el -o aseguramos que cada interfaz esté en una sola línea
        # Además, metemos los mismos parámetros que en la ejecución de antes (ejecutar_consulta)
        resultado = subprocess.run(
            ["ip", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            check=True
        )
    except Exception as e:
        print("[ERROR] Fallo al listar las interfaces del sistema: "+str(e)+"\n")
        return {}

    interfaces = defaultdict(list)
    for linea in resultado.stdout.splitlines(): # cada línea es una interfaz
        partes = linea.split() # segmentamos en trocitos cada línea
        #print(partes)
        
        if len(partes) >= 4:    # Por seguridad comprobamos, además si no no podemos sacar la info de esta forma
            nombreIn = partes[1]
            tipo = partes[2] # IPv4 o IPv6
            ipEnmascarada = partes[3] # Tiene la mascara en formato x.x.x.x/y
            ip = ipEnmascarada.split('/')[0]

            interfaces[nombreIn].append({
                "tipo": tipo,
                "ip": ip
            })
            
    return dict(interfaces)


# Obtener info básica
def info_sis():
    info = {
        "hostname": platform.node(),    # Nombre de la máquina
        "sistema": platform.system(),   # SO base (Linux)
        "dist": "Linux",
        "version": "versión desconocida",
        "kernel": platform.release(),   # Nombre y versión
        "arquitectura": platform.machine()  # Arquitectura del procesador
    }
    data = ejecutar_consulta("SELECT name, version FROM os_version;")
    if data and len(data) > 0:  # Por si acaso devuelve fallo la consulta
        # Los sacamos por el nombre de las columnas
        info["dist"] = data[0]["name"] 
        info["version"] = data[0]["version"]
    return info


# Paquetes instalados con APT
def paquetes_instalados():
    query = "SELECT name, version FROM deb_packages;"
    resultado = ejecutar_consulta(query)
    for p in resultado:
        # Añadimos estas claves en el diccionario para poder catalogar los paquetes más tarde en el módulo vulns
        p['ecosystem'] = 'Debian'
        p['type'] = 'System (APT)'
    return resultado

# Paquetes de Python con pip
def paquetes_python():
    query = "SELECT name, version FROM python_packages;"
    resultado = ejecutar_consulta(query)        
    # Igual que antes
    for p in resultado:
        p['ecosystem'] = 'PyPI'
        p['type'] = 'Python (PIP)'
    return resultado





def ESCANEO_info_Simple(verbose):
    # Info del sistema
    info = info_sis() # Es un diccionario 
    if verbose:
        print("[+] Información del sistema: ")
        print("     [i] Hostname:      "+info['hostname'])
        print("     [i] Sistema:       "+info['dist']+" "+info['version'])
        print("     [i] Kernel:        "+info['kernel'])
        print("     [i] Arquitectura:  "+info['arquitectura']+"\n")
    return info