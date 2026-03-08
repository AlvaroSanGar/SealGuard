import os
from modules.system import ejecutar_consulta
from config.settings import config


def auditar_suid_sgid(verbose):
    print(" [+] Buscando binarios peligrosos (SUID/SGID)...")
    resultados = {
        "seguros": 0,
        "peligrosos": []
    }
    critical_dir = config["hardening"]["suid_sgid"]["critical_directories"]
    critical_per = config["hardening"]["suid_sgid"]["forviden_permissions"]
    
    # Obtenemos todas las columnas suid_bin y la columna mode de file (indica los permisos)
    query = '''SELECT s.path, s.username, s.groupname, s.permissions, f.mode 
    FROM suid_bin AS s LEFT JOIN file AS f ON s.path = f.path;'''
    res_consulta = ejecutar_consulta(query)
    
    # Clasificamos cada resultado de la consulta
    for proceso in res_consulta:
        ruta = proceso.get("path")
        permisos = proceso.get("mode")
        
        # Comprobamos si en algún trozo de la ruta (substring) hay un directorio crítico/vulnerable
        vulnerable_dir = any(directorio in ruta for directorio in critical_dir)
        
        # Comprobamos directamente si se cumple que el archivo tiene permisos (por si acaso pero debería) y acto seguido si los permisos del
        # grupo "otros" (dueño-grupo-otros) está en critical_per (obtenemos dichos permisos con permisos[-1])
        if ((permisos and (permisos[-1] in critical_per)) or vulnerable_dir):
            resultados["peligrosos"].append(proceso)
            if verbose and vulnerable_dir:
                print("     [X] Se ha detectado un proceso con el bit SUID/GUID activo en: "+str(proceso["path"]))
            elif verbose:
              print("     [X] Se ha detectado un proceso con el bit SUID/GUID activo y permisos peligrosos: "+str(proceso["path"]))  
                
        else:
            resultados["seguros"] += 1
        
    # Info en caso de verbose
    if verbose:
        procesos_tot = len(res_consulta)
        print("   [i] De los "+str(procesos_tot)+" procesos con SUID/GUID activos, "+str(resultados.get("seguros"))+" de ellos se han catalogado como seguros")
            
    
    return resultados










#########################################################################################################

def auditar_archivos_criticos(verbose):
    print(" [+] Auditando permisos y propietarios de archivos críticos")
    # Cargamos datos e inicializamos variables
    archivos_yaml = config["hardening"]["critical_files"]
    resultados =[]
    
    # Cargamos las rutas para poder ponerlas en formato SQL
    archivos_criticos = []
    for archivo_esp in archivos_yaml:
        archivos_criticos.append(archivo_esp["path"])    # Creamos una lista para acceder más fácil a los archivos criticos
    criticos_sql = ",".join([f"'{n}'" for n in archivos_criticos]) 
    
    condicion = ''
    if criticos_sql:
        condicion = 'WHERE f.path IN ('+criticos_sql+')'

    query = 'SELECT f.path, f.mode, u.username FROM file AS f LEFT JOIN users AS u ON f.uid = u.uid '+condicion+';'
    resultado_busqueda = ejecutar_consulta(query)
    
    # Iteramos sobre cada archivo crítico y comprobamos si se cumplen los requisitos esperados
    for archivo_esp in archivos_yaml:
        # Creamos un dic aux, debe ser dentro del bucle
        formato = {
            "estado": None,
            "archivo": None,
            "problemas": []
        }
        
        # Obtenemos los valores de cada archivo real obtenido con OSquery
        permisos_esp = archivo_esp.get("max_permissions")
        dueño_esp = archivo_esp.get("owner")
        archivo = archivo_esp.get("path")
        
        archivo_obt = None
        # Buscamos el archivo esperado entre los obtenidos por OSquery
        for esp in resultado_busqueda:
            if esp.get("path") == archivo:
                archivo_obt = esp
                break
        
        # Comprobamos si el archivo existe
        if not archivo_obt:
            print("     [ERROR] El archivo "+str(archivo)+" no se ha encontrado en el sistema")
            formato["archivo"] = str(archivo)
            formato["estado"] = 'NO ENCONTRADO'
            formato["problemas"] = ["El archivo no ha sido encontrado en el sistema"]
            resultados.append(formato)
            continue
        
        # Vamos a comprobar si tiene problemas el archivo
        problemas = []
        
        # Comprobamos si el owner coincide
        if dueño_esp != archivo_obt.get("username"):
            problemas.append("El dueño esperado es "+str(dueño_esp)+" pero en su lugar, el dueño del archivo es "+str(archivo_obt.get('owner')))
        
        # Comprobamos si los permisos son menores a los indicados por config
        permisos_reales = archivo_obt.get("mode", "")
        permisos_limpios = permisos_reales[-3:] if len(permisos_reales) >= 3 else permisos_reales # Osquery devuelve un 0 o 1 delante para indicar el suid
        
        try:
            # Convertimos ambos strings a base 8 (octal) para compararlos matemáticamente
            if int(permisos_limpios, 8) > int(permisos_esp, 8):
                problemas.append("Los permisos actuales ("+str(permisos_limpios)+") son más permisivos que el máximo tolerado ("+str(permisos_esp)+")")
                
        except TypeError:
            problemas.append("No se ha definido el permiso máximo en el archivo YAML para este archivo.")
        except ValueError:
            problemas.append("Error al leer o convertir los permisos reales de Osquery ("+str(permisos_reales)+")")
        
        
        # Clasificamos el archivo
        if len(problemas) > 0:
            formato["archivo"] = archivo
            formato["estado"] = "PELIGROSO"
            formato["problemas"] = problemas
            resultados.append(formato)
            if verbose:
                print("     [X] El archivo "+str(archivo)+" no cumple los requisitos de seguridad establecidos | Fallos de seguridad detectados:")
                for p in problemas:
                    print("         - "+str(p))
        
        else: 
            formato["archivo"] = archivo
            formato["estado"] = "SEGURO"
            formato["problemas"] = "Ninguno, el archivo es seguro"
            resultados.append(formato)
            if verbose:
                print("     [V] El archivo "+str(archivo)+" cumple con los requisitos de seguridad indicados")
            
    return resultados











###################################################################################################################################

def auditar_ssh(verbose):
    print(" [+] Auditando configuración de seguridad SSH...")
    ssh_yaml = config["hardening"]["ssh"]
    reporte_ssh = {}
    
    # Aquí reutilizaremos tu función de buscar en /etc/ssh/sshd_config
    # para ver si root puede hacer login o si se permiten contraseñas.
    
    return reporte_ssh

from config.settings import config # Asegúrate de tener esto importado arriba del todo

def auditar_firewall(verbose):
    print(" [+] Comprobando el estado del Cortafuegos (Firewall)...")
    
    resultado = {
        "estado": "PELIGROSO",
        "firewall_activo": "Ninguno",
        "detalles": [],
        "alertas": []
    }

    # --- 1. CAPA GESTOR: Leemos los servicios desde el YAML ---
    try:
        gestores_config = config["hardening"]["firewall_services"]
    except KeyError:
        print("     [ERROR] No se ha encontrado la clave 'hardening -> firewall_services' en settings.yaml")
        gestores_config = [] # Evitamos que el programa pete si falta la config

    servicios_activos = []
    
    if gestores_config:
        # Formateamos la lista para SQL: 'ufw.service', 'firewalld.service', ...
        servicios_sql = ", ".join([f"'{s}'" for s in gestores_config])
        query_servicios = f"SELECT id, active_state FROM systemd_units WHERE id IN ({servicios_sql});"
        
        res_servicios = ejecutar_consulta(query_servicios) # Usa mSystem.ejecutar_consulta si lo tienes en otro archivo

        if res_servicios:
            for servicio in res_servicios:
                if servicio.get("active_state") == "active":
                    # Limpiamos el nombre (ej. 'ufw.service' -> 'ufw') para que quede más limpio en el reporte
                    nombre_limpio = servicio.get("id", "").replace(".service", "")
                    servicios_activos.append(nombre_limpio)

    # --- 2. CAPA KERNEL: Buscamos si hay REGLAS EFECTIVAS de bloqueo (Agnóstico al gestor) ---
    query_reglas = "SELECT count(*) AS total FROM iptables WHERE chain = 'INPUT' AND target IN ('DROP', 'REJECT');"
    res_reglas = ejecutar_consulta(query_reglas)

    reglas_bloqueo = 0
    if res_reglas and len(res_reglas) > 0:
        try:
            reglas_bloqueo = int(res_reglas[0].get("total", 0))
        except ValueError:
            pass

    ##################### Clasificación #########################################################################
    if reglas_bloqueo > 0:
        resultado["estado"] = "SEGURO"
        
        gestor = " / ".join(servicios_activos) if len(servicios_activos) > 0 else "Reglas manuales en Kernel"
        resultado["firewall_activo"] = gestor
        
        resultado["detalles"].append("Gestor detectado: " + gestor)
        resultado["detalles"].append("Se han detectado " + str(reglas_bloqueo) + " reglas restrictivas (DROP/REJECT) en el tráfico de entrada.")
        
        if verbose:
            print("     [V] Firewall activo (" + gestor + ") y bloqueando tráfico correctamente.")

    elif len(servicios_activos) > 0:
        resultado["firewall_activo"] = " / ".join(servicios_activos)
        alerta = "El servicio (" + resultado["firewall_activo"] + ") está encendido, pero NO hay reglas de bloqueo (DROP/REJECT) aplicadas en la cadena INPUT."
        resultado["alertas"].append(alerta)
        
        if verbose:
            print("     [!] ATENCIÓN: " + alerta)
            print("         - El servidor NO está filtrando el tráfico entrante.")

    else:
        alerta = "No se ha detectado ningún demonio de firewall activo ni reglas de bloqueo en el kernel."
        resultado["alertas"].append(alerta)
        
        if verbose:
            print("     [X] PELIGRO: El perímetro de red del servidor está totalmente expuesto.")

    return resultado













#######################################################################################################################
def auditar_aslr(verbose):
    print(" [+] Comprobando si ASLR en el Kernel")
    resultado = {
        "estado": "PELIGROSO",
        "valor": 0,
    }
    query = 'SELECT current_value FROM system_controls WHERE name = "kernel.randomize_va_space";'
    res = ejecutar_consulta(query)
    val = int(res[0].get('current_value'))
    match val:
        case 1:
            resultado["valor"] = 1
            if verbose:
                print("     [!] El kernel tiene activadas protecciones por ASLR limitadas (no está randomizando la pila)")

        case 2:
            resultado["estado"] = "SEGURO"
            resultado["valor"] = 2
            if verbose:
                print("     [V] El kernel tiene activadas las protecciones por ASLR correctamente")
                
        case _:
            if verbose:
                print("     [X] El kernel no tinene activadas las protecciones por ASLR, por favor revise su configuración del sistema")
    
    return resultado











#################################################################################################################################
def auditar_mac(verbose):
    print(" [+] Comprobando Control de Acceso Obligatorio (AppArmor/SELinux)...")
    resultado = {
        "estado": "PELIGROSO",
        "mac_activo": None,
        "detalles": [],
        "alertas": []
    }
    
    seguro = False
    
    # Pre-check AppArmor: Miramos si existe la carpeta de perfiles de AppArmor
    query_precheck_aa = "SELECT path FROM file WHERE path = '/etc/apparmor.d';"
    res_precheck_aa = ejecutar_consulta(query_precheck_aa)
    
    # Solo entramos a consultar AppArmor si el pre-check encontró el directorio
    if res_precheck_aa and len(res_precheck_aa) > 0:
        query = 'SELECT mode, count(*) AS total FROM apparmor_profiles GROUP BY mode;'
        res_AppArmor = ejecutar_consulta(query)
        
        if res_AppArmor:
            # Inicializamos los contadores de cada posible tipo (los unconfined los ignoramos)
            enforce = 0
            complain = 0
            
            if verbose:
                print("     [i] Se ha detectado AppArmor como sistema de Control de Acceso Obligatorio")
            for linea in res_AppArmor:
                modo = linea.get("mode")
                tot = linea.get("total",0)
                
                # Clasificamos los procesos
                if modo == 'enforce':
                    enforce = int(tot)
                if modo == 'complain':
                    complain = int(tot)
        
            if enforce > 0:
                resultado["estado"] = "SEGURO"
                resultado["mac_activo"] = "AppArmor"
                resultado["detalles"].append(str(enforce) + " perfiles de AppArmor en modo 'enforce' (Activos)")
                seguro = True
                if verbose:
                    print("         - Se han detectado "+str(enforce)+" procesos marcados en modo 'enforce'")
                    
            if complain > 0:
                resultado["mac_activo"] = "AppArmor"
                alerta = "Se han detectado "+str(complain)+" procesos marcados en modo 'complain'"
                resultado["alertas"].append(alerta)
                if verbose:
                    print("         - "+alerta)
            
    # Ahora lo comprobamos con SELinux (Redhat)
    # Pre-check: Miramos si existe el archivo de SELinux para no lanzar la consulta si no lo tenemos instalado
    query_precheck = "SELECT path FROM file WHERE path = '/etc/selinux/config';"
    res_precheck = ejecutar_consulta(query_precheck)
    
    # Solo entramos a consultar SELinux si el pre-check encontró el archivo
    if res_precheck and len(res_precheck) > 0:
        query_selinux = "SELECT value FROM selinux_settings WHERE name = 'enforce';"
        res_selinux = ejecutar_consulta(query_selinux)
        
        if res_selinux and len(res_selinux) > 0:
            valor_selinux = str(res_selinux[0].get("value", ""))
            
            if valor_selinux == "1":
                resultado["estado"] = "SEGURO"
                if seguro:
                    resultado["mac_activo"] += " y SELinux"
                else:
                    resultado["mac_activo"] = "SELinux"
                resultado["detalles"].append("SELinux activo en modo 'enforcing' (Bloqueando amenazas)")
                seguro = True # Ponemos seguro a True para que no salte el print final de error
                
            elif valor_selinux == "0":
                alerta = "ATENCIÓN: SELinux está en modo 'permissive' (Solo avisa, no bloquea)"
                resultado["alertas"].append(alerta)
                if verbose:
                    print("     [!] " + alerta)
                
    
    if not seguro:
        print("     [X] No se ha encontrado ningún servicio de Control de Acceso Obligatorio activo (AppArmor o SELinux)")
    return resultado








##################################################################################################################################
def auditar_certificados():
    resultados = {}
    
    return resultados


def auditar_cifrado():
    resultados = {}
    
    return resultados



def ESCANER_hardening(verbose):
    datos_reporte = {
        "archivos_criticos": [],
        "ssh": {},
        "firewall": {},
        "suid_sgid": [],
        "kernel_aslr": {},
        "mac": {}
    }

    print("\n--- [ FASE 5: BASTIONADO DEL SISTEMA (HARDENING) ] ---")
    
    # 1. Permisos y Archivos
    datos_reporte["archivos_criticos"] = auditar_archivos_criticos(verbose)
    
    # 2. Servicios de Red
    datos_reporte["ssh"] = auditar_ssh(verbose)
    if config["hardening"]["firewall"]["check_active"]:
        datos_reporte["firewall"] = auditar_firewall(verbose)
    
    # 3. Protecciones de Sistema Operativo
    if config["hardening"]["system_checks"]["check_suid_sgid"]:
        datos_reporte["suid_sgid"] = auditar_suid_sgid(verbose)
        
    if config["hardening"]["system_checks"]["check_aslr"]:
        datos_reporte["kernel_aslr"] = auditar_aslr(verbose)
        
    if config["hardening"]["system_checks"]["check_mac"]:
        datos_reporte["mac"] = auditar_mac(verbose)

    print("[-] Finalizando módulo de bastionado")
    
    return datos_reporte