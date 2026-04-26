import os
import stat
import pwd
import time
import subprocess
import re
from modules.system import ejecutar_consulta
from config.settings import config


def auditar_suid_sgid(verbose):
    print("[+] Buscando binarios peligrosos (SUID/SGID)")
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
        
        vulnerable_dir = any(directorio in ruta for directorio in critical_dir)
        
        # Miramos los permisos otros [-1] y de grupo [-2]
        if permisos and len(permisos) >= 3 and (permisos[-1] in critical_per or permisos[-2] in critical_per) or vulnerable_dir:
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
    print("[+] Auditando permisos y propietarios de archivos críticos")
    # Cargamos datos e inicializamos variables
    try:
        archivos_yaml = config["hardening"]["critical_files"]
    except KeyError:
        # Si borran la sección entera en el YAML, creamos una lista vacía
        archivos_yaml = [] 
        
    resultados = []

    # Extraemos solo las rutas que haya puesto el usuario para comprobar
    rutas_existentes = [archivo.get("path") for archivo in archivos_yaml]    
    # Si el archivo del GRUB no está, lo forzamos metiéndolo en la lista
    if "/etc/default/grub" not in rutas_existentes:
        archivos_yaml.append({
            "path": "/etc/default/grub",
            "max_permissions": "644",
            "owner": "root"
        })
    
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
        
        # Obtenemos los valores de cada archivo esperado
        permisos_esp = archivo_esp.get("max_permissions")
        dueno_esp = archivo_esp.get("owner") 
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
        if dueno_esp != archivo_obt.get("username"): 
            problemas.append("El dueño esperado es "+str(dueno_esp)+" pero en su lugar, el dueño del archivo es "+str(archivo_obt.get('username'))) 
        
        # Comprobamos si los permisos son menores a los indicados por config
        permisos_reales = archivo_obt.get("mode", "")
        permisos_limpios = permisos_reales[-3:] if len(permisos_reales) >= 3 else permisos_reales # Osquery devuelve un 0 o 1 delante para indicar el suid
        
        try:
            perm_actual = int(permisos_limpios, 8)
            perm_max = int(permisos_esp, 8)
            if (perm_actual & ~perm_max) != 0: # Igual que en certificados
                problemas.append("Los permisos actuales ("+str(oct(perm_actual))+") son más permisivos que el máximo tolerado (0o"+str(permisos_esp)+")")
                
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
                print("     [X] El archivo "+str(archivo)+" no cumple los requisitos de seguridad establecidos ")
                print("         | Fallos de seguridad detectados:")
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
    print("[+] Auditando configuración de seguridad SSH")
    resultados =  {
        "estado": "PELIGROSO",
        "detalles": [],
        "alertas": []
    }
    
    # Cargamos los datos del .yaml
    try:
        ssh_params = config["hardening"]["ssh"]["secure_params"]
        ssh_usu = config["hardening"]["ssh"]["allowed_users"]
    
    except Exception:
        ssh_params = {'PermitRootLogin': 'no', 'PermitEmptyPasswords': 'no', 'PasswordAuthentication': 'no', 'MaxAuthTries': '4', 'MaxSessions': '2'}
        ssh_usu = None
        
        
        
    # Comprobamos si ssh está instalado, en caso de que no lo esté marcamos el servicio como seguro
    if not os.path.exists('/etc/ssh/sshd_config'):
        resultados["estado"] = "SEGURO"
        resultados["detalles"] = "El servicio ssh no está instalado en el sistema, por lo que no puede ser vulnerable"
        if verbose:
            print("     [i] "+str(resultados.get("detalles")))
        return resultados



    # Obtenemos el archivo ssh y lo leemos en busqueda de los parametros de config indicados en el .yaml
    contenido_ssh = {}
    try:
        with open('/etc/ssh/sshd_config', "r") as f:
            for linea in f:
                linea = linea.strip()
                # Ignoramos líneas vacías o comentadas
                if not linea or linea.startswith("#"):
                    continue
                
                # Separamos clave y valor
                partes = linea.split()
                if len(partes) >= 2:
                    clave = partes[0]
                    valor = " ".join(partes[1:]) # Por si el valor tiene espacios
                    contenido_ssh[clave] = valor
    except Exception as e:
        print("     [ERROR] Fallo al leer '/etc/ssh/sshd_config': "+str(e))
        resultados["alertas"] = "No se ha logrado leer el archivo de configuración"
        return resultados
    
    
    # Comprobamos para cada valor de ssh_params si está en la configuración del servicio ssh
    for atributo in ssh_params:
        if atributo in contenido_ssh:   
            # En caso de que esté comprobamos si tiene el mismo valor
            if contenido_ssh[atributo].lower() == ssh_params[atributo].lower():
                detalle = 'El parametro '+str(atributo)+' cumple la política de seguridad indicada ('+str(ssh_params[atributo])+')'
                resultados["detalles"].append(detalle)
                if verbose:
                    print("     [V] "+str(detalle))
            
            # En caso de que no tenga el mismo valor lo indicamos
            else:
                alerta = 'El parametro '+str(atributo)+' no cumple la política de seguridad indicada ('+str(ssh_params[atributo])+')'
                resultados["alertas"].append(alerta)
                if verbose:
                    print("     [X] "+str(alerta))
        
        # Si no aparece en la configuración lo indicamos
        else:
            alerta = 'El parametro '+str(atributo)+' no está configurado en el servicio ssh'
            resultados["alertas"].append(alerta)
            if verbose:
                print("     [!] "+str(alerta))
                
                
    # Comprobamos que no se ejecuta en el puerto 22 (para evitar ataques de bots)
    if contenido_ssh.get("Port", "22") == "22":
        alerta = 'El puerto en el que se está ejecutando SSH es por defecto (22), es vulnerable a ataques de bots automatizados'
        resultados["alertas"].append(alerta)
        if verbose:
            print("     [X] "+str(alerta))
        
    else: # En caso de que no se ejecute en el p22
        detalle = 'El servicio se está ejecutando en el puerto '+str(contenido_ssh.get("Port"))
        resultados["detalles"].append(detalle)
        if verbose:
            print("     [V] "+str(detalle))
    
    
    ##################### Comprobamos los usuarios
    if ssh_usu:
        usuarios_actuales_str = contenido_ssh.get("AllowUsers", "")
        lista_actuales = usuarios_actuales_str.split() # Lo convertimos en lista separando por espacios
        
        # Comprobamos si coinciden exactamente (ni faltan ni sobran usuarios)
        faltan = [u for u in ssh_usu if u not in lista_actuales]
        sobran = [u for u in lista_actuales if u not in ssh_usu]
        
        if not faltan and not sobran and usuarios_actuales_str:
            detalle = 'La directiva AllowUsers coincide exactamente con los usuarios permitidos en la política.'
            resultados["detalles"].append(detalle)
            if verbose:
                print("     [V] " + str(detalle))
        else:
            alerta = 'La lista de usuarios permitidos (AllowUsers) no coincide. Esperado: ' + " ".join(ssh_usu) + ' | Actual: ' + usuarios_actuales_str
            resultados["alertas"].append(alerta)
            if verbose:
                print("     [X] " + str(alerta))
    
    
    # Catalogamos el resultado final
    if len(resultados["alertas"]) == 0:
        resultados["estado"] = 'SEGURO'
        if verbose:
            print("     [V] Se cumplen todas las políticas de seguridad en ssh")
    elif verbose:
        print("     [!] Se han detectado "+str(len(resultados["alertas"]))+" configuraciones catalogadas como no seguras")
    
    return resultados


















#########################################################################################################################################################
def auditar_firewall(verbose):
    print("[+] Comprobando el estado del Firewall")
    
    resultado = {
        "estado": "PELIGROSO",
        "servicios": [], 
        "kernel": {
            "reglas_bloqueo": 0,
            "politica_accept": False,
            "bloqueo_output": False,
            "bloqueo_forward": False,
            "tipo_filtro": "Desconocido"
        },
        "alertas": []
    }
    
    try:
        lista_firewalls = config["hardening"]["firewall_services"]
    except KeyError:
        print("     [ERROR] No se han podido cargar los firewalls de la config.yaml")
        lista_firewalls = []
        
    servicios_activos = []
    
    #################### Comprobación de firewalls en systemd #########################################################
    if lista_firewalls:
        # Preparamos la consulta SQL
        firewalls_sql = ",".join([f"'{n}'" for n in lista_firewalls])
        query_fir = 'SELECT id, active_state, unit_file_state FROM systemd_units WHERE id IN ('+firewalls_sql+');'
        resultado_consulta = ejecutar_consulta(query_fir)        
        
        # Comprobamos si exsten los firewalls en el sistema e iteramos sobre la respuesta
        if resultado_consulta:
            for servicio in resultado_consulta:
                # Limpiamos el nombre por comodidad ya que todos terminan en .service
                nombre = servicio.get("id").replace(".service", "") 
                estado_actu = servicio.get("active_state")
                estado_arranque = servicio.get("unit_file_state")
                
                esta_activo = (estado_actu == 'active') # Equivalente a un if, si se cumple la condición esta_activo será true, por el contrario false
                
                # Comprobamos si está activo y si por defecto se inicia al arrancar el sistema 
                if esta_activo:
                    servicios_activos.append(nombre)
                    
                    # Comprobamos si no está configurado para arrancar al iniciar el sistema
                    if estado_arranque != 'enabled':
                        alerta = "El gestor '" + nombre + "' está encendido ahora, pero no arrancará tras un reinicio (estado: " + str(estado_arranque) + ")"
                        resultado["alertas"].append(alerta)
                        if verbose:
                            print("     [!] " + alerta)
                    else:
                        if verbose:
                            print("     [V] El gestor '" + nombre + "' está ACTIVO y habilitado de forma persistente (enabled)")
                            
                # Caso de que esté configurado para arrancar siempre, pero actualmente está apagado o caído
                elif estado_arranque == 'enabled' and estado_actu != 'active':
                    alerta = "El gestor '" + nombre + "' debería estar encendido de forma persistente (enabled), pero actualmente está APAGADO."
                    resultado["alertas"].append(alerta)
                    if verbose:
                        print("     [!] " + alerta)

                resultado["servicios"].append({
                    "nombre": nombre,
                    "activo": esta_activo,
                    "arranque": estado_arranque
                })

    ############## Comprobación de si ay normas activas (de bloquear y descartar) ########################################
    reglas_bloqueo = 0
    politica_accept = False
    bloqueo_output = False
    bloqueo_forward = False
    tipo_encontrado = "Desconocido" 
    
    iptables_funciona = False 
    nftables_funciona = False 
    
    # Tratamos de obtener las normas actuales del sistema con iptables -S (similar a las interfaces de networking)
    # de esta forma buscamos las políticas que hemos obtenido y rechazan o bloquean peticiones (si no hay ninguna de este
    # timpo, el firewall no estará filtrando nada, por lo que en la práctica sería como si no estuviese activo)
    try:
        # Leemos todas las posibles cadenas (OUTPUT, FORWARD, etc.)
        res_iptables = subprocess.run(["iptables", "-S"], capture_output=True, text=True, timeout=2)
        if res_iptables.returncode == 0:
            tipo_encontrado = "IPtables"
            iptables_funciona = True 
            for linea in res_iptables.stdout.splitlines():
                # Buscamos políticas por defecto permisivas
                if "-P INPUT ACCEPT" in linea: 
                    politica_accept = True
                    
                # Buscamos reglas generales de bloqueo
                if "-P INPUT DROP" in linea or "-j DROP" in linea or "-j REJECT" in linea: 
                    reglas_bloqueo += 1
                    
                # Buscamos reglas de OUTPUT y FORWARD
                if "OUTPUT" in linea and ("DROP" in linea or "REJECT" in linea): 
                    bloqueo_output = True
                if "FORWARD" in linea and ("DROP" in linea or "REJECT" in linea): 
                    bloqueo_forward = True
        elif verbose:
            print("     [DEBUG] iptables devolvió error: " + res_iptables.stderr.strip().replace('\n', ' '))
    except FileNotFoundError:
        # Falla si los comandos iptables no están instalados en el sistema
        pass
    except Exception as e:
        if verbose:
            print("     [i] No se pudieron comprobar las reglas del kernel directamente: " + str(e))
            
    # En algunos sistemas podemos no tener la opción anterior, por lo que lo volvemos a intentar esta vez
    # con Nftables (versión más moderna)
    if not iptables_funciona:
        try:
            res_nft = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=2)
            if res_nft.returncode == 0:
                tipo_encontrado = "Nftables"
                nftables_funciona = True
                
                # Convertimos toda la salida a minúsculas para buscar fácilmente
                salida_nft = res_nft.stdout.lower()
                
                if "policy accept" in salida_nft: politica_accept = True
                if "drop" in salida_nft or "reject" in salida_nft: reglas_bloqueo += 1
                if "output" in salida_nft and ("drop" in salida_nft or "reject" in salida_nft): bloqueo_output = True
                if "forward" in salida_nft and ("drop" in salida_nft or "reject" in salida_nft): bloqueo_forward = True
            elif verbose:
                print("     [DEBUG] nft devolvió error: " + res_nft.stderr.strip().replace('\n', ' '))
        except FileNotFoundError:
            # Falla si los comandos nft no están instalados en el sistema
            pass
        except Exception as e:
            if verbose:
                print("     [i] No se pudieron comprobar las reglas del kernel directamente: " + str(e))

    if not iptables_funciona and not nftables_funciona:
        alerta_desc = "No se ha detectado IPtables ni Nftables instalados en el sistema (Estado de red desconocido)"
        resultado["alertas"].append(alerta_desc)
        if verbose:
            print("     [?] " + alerta_desc)

    resultado["kernel"]["tipo_filtro"] = tipo_encontrado
    resultado["kernel"]["reglas_bloqueo"] = reglas_bloqueo
    resultado["kernel"]["politica_accept"] = politica_accept
    resultado["kernel"]["bloqueo_output"] = bloqueo_output
    resultado["kernel"]["bloqueo_forward"] = bloqueo_forward
    
    ########### Clasificamos los resultados obtenidos ################################################################
    if reglas_bloqueo > 0:
        resultado["estado"] = "SEGURO"
        # Caso de que el firewall está en systemd y tiene reglas de bloqueo en el kernel
        if len(servicios_activos) > 0:
            fw_activo = " / ".join(servicios_activos)
            if verbose:
                print("     [V] El sistema está protegido por " + fw_activo + " y por " + str(reglas_bloqueo) + " reglas de bloqueo")
        # Caso de que el firewall no se está ejecutando pero hay reglas en el kernel
        else:
            if verbose:
                print("     [V] No se ha detectado ningún servicio de gestión activo, pero el sistema está protegido por " + str(reglas_bloqueo) + " reglas de bloqueo")
    
    # Caso de que aunque está activo un firewall no hay reglas de bloqueo en el kernel, por lo que no se filtra
    elif len(servicios_activos) > 0:
        alerta = 'Aunque se han detectado servicios de firewall activos en el sistema, no existen reglas de bloqueo, por lo que no se está ejerciendo ningún filtro real'
        resultado["alertas"].append(alerta)
        if verbose:
            print("     [!] " + alerta)
            
    # No hay ni firewall ni reglas
    else:
        if iptables_funciona or nftables_funciona:
            alerta = 'No se han detectado ni firewalls ni reglas de bloqueo activas, el sistema se encuentra expuesto a la red'
            resultado["alertas"].append(alerta)
            if verbose:
                print("     [X] " + alerta)
            
    ############## Alertas extra ####################################################################################
    # Solo alertamos si el firewall está activo o hay reglas, porque si está apagado ya lo hemos dicho arriba.
    if reglas_bloqueo > 0 or len(servicios_activos) > 0:
        if politica_accept:
            alerta_pol = "El firewall tiene políticas por defecto permisivas (ACCEPT). Se recomienda 'Default Deny'"
            resultado["alertas"].append(alerta_pol)
            if verbose:
                print("     [!] " + alerta_pol)
                
        if not bloqueo_output:
            alerta_out = "No se han detectado reglas de bloqueo en la cadena OUTPUT"
            resultado["alertas"].append(alerta_out)
            if verbose:
                print("     [!] " + alerta_out)
                
        if not bloqueo_forward:
            alerta_fwd = "No se han detectado reglas de bloqueo en la cadena FORWARD"
            resultado["alertas"].append(alerta_fwd)
            if verbose:
                print("     [!] " + alerta_fwd)
    
    return resultado














#######################################################################################################################
def auditar_aslr(verbose):
    print("[+] Comprobando si ASLR en el Kernel")
    resultado = {
        "estado": "PELIGROSO",
        "valor": 0,
    }
    query = 'SELECT current_value FROM system_controls WHERE name = "kernel.randomize_va_space";'
    res = ejecutar_consulta(query)
    
    val = 0
    if res and len(res) > 0: # Lo hacemos de forma segura
        try:
            val = int(res[0].get("current_value"))
        except ValueError:
            val = 0
            
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
                print("     [X] El kernel no tinene activadas las protecciones por ASLR")
    
    return resultado











#################################################################################################################################
def auditar_mac(verbose):
    print("[+] Comprobando Control de Acceso Obligatorio (AppArmor/SELinux)...")
    
    # Nuevo esquema de datos: Estructurado y limpio para tabular
    resultado = {
        "estado": "PELIGROSO",
        "apparmor": {"activo": False, "enforce": 0, "complain": 0},
        "selinux": {"activo": False, "modo": "Deshabilitado"}
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
                tot = linea.get("total", 0)
                
                # Clasificamos los procesos
                if modo == 'enforce': 
                    enforce = int(tot)
                if modo == 'complain': 
                    complain = int(tot)
            
            # Guardamos 
            resultado["apparmor"]["activo"] = True
            resultado["apparmor"]["enforce"] = enforce
            resultado["apparmor"]["complain"] = complain
            
            if enforce > 0:
                resultado["estado"] = "SEGURO"
                seguro = True # Ponemos seguro a True para que no salte el print final de error
                if verbose:
                    print("         - Se han detectado " + str(enforce) + " procesos marcados en modo 'enforce'")
                    
            if complain > 0 and verbose:
                print("         - Se han detectado " + str(complain) + " procesos marcados en modo 'complain'")
                
    # Ahora lo comprobamos con SELinux (Redhat)
    # Pre-check: Miramos si existe el archivo de SELinux para no lanzar la consulta si no lo tenemos instalado
    query_precheck = "SELECT path FROM file WHERE path = '/etc/selinux/config';"
    res_precheck = ejecutar_consulta(query_precheck)
    
    if res_precheck and len(res_precheck) > 0:
        query_selinux = "SELECT value FROM selinux_settings WHERE name = 'enforce';"
        res_selinux = ejecutar_consulta(query_selinux)
        
        # Solo entramos a consultar SELinux si el pre-check encontró el archivo
        if res_selinux and len(res_selinux) > 0:
            valor_selinux = str(res_selinux[0].get("value", ""))
            resultado["selinux"]["activo"] = True
            
            if valor_selinux == "1":
                resultado["estado"] = "SEGURO"
                resultado["selinux"]["modo"] = "Enforcing"
                seguro = True # Ponemos seguro a True para que no salte el print final de error
                
                if verbose:
                    print("         - SELinux activo en modo 'enforcing' (Bloqueando amenazas)")
                    
            elif valor_selinux == "0":
                resultado["selinux"]["modo"] = "Permissive"
                if verbose:
                    print("     [!] SELinux está en modo 'permissive' (Solo avisa, no bloquea)")
                    
    if not seguro:
        print("     [X] No se ha encontrado ningún servicio MAC activo (AppArmor o SELinux)")
        
    return resultado








##################################################################################################################################
def auditar_certificados(verbose):
    print("[+] Comprobando Certificados y Claves")
    resultados = {
        "estado": "PELIGROSO",
        "detalles": [],
        "alertas": []
    }
    
    #Obtenemos la info  de settings.yaml 
    try:
        cert_config = config["hardening"]["certificados"]
        dias_aviso = cert_config["dias_aviso_caducidad"]
        min_rsa = cert_config["min_rsa_key_size"]
        algoritmos_permitidos = cert_config["algoritmos_permitidos"]
        rutas_criticas = cert_config["rutas_criticas"]
    
    except Exception:
        dias_aviso = 30
        min_rsa = 2048
        algoritmos_permitidos = ["sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption", "ecdsa-with-SHA256", "ecdsa-with-SHA384"]
        rutas_criticas = []

    # En caso de que no se hayan definido rutas, lo marcamos como seguro, a que no hay certificados
    if not rutas_criticas:
        resultados["estado"] = "SEGURO"
        resultados["detalles"] = "No hay rutas críticas de certificados definidas para auditar"
        if verbose:
            print("     [i] "+str(resultados["detalles"]))
        return resultados


    #################### Comprobamos los permisos ###################################################
    for archivo in rutas_criticas:
        ruta = archivo.get("path")
        tipo = archivo.get("tipo")
        max_permisos_esp = archivo.get("max_permissions")
        dueno_esp = archivo.get("owner")

        # Comprobamos si el archivo existe realmente
        if not os.path.exists(ruta):
            alerta = "No se encuentra el hash: "+str(ruta)
            resultados["alertas"].append(alerta)
            if verbose:
                print("     [!] "+str(alerta))
            continue

        file_stat = os.stat(ruta) # Guardamos todos los metadatos del archivo ()
        
        
        # Comprobamos el propietario del archivo
        try:
            dueno_actu = pwd.getpwuid(file_stat.st_uid).pw_name 
            if dueno_actu != dueno_esp:
                alerta = "El archivo "+str(ruta)+" no tiene el dueño esperado. Actual: "+str(dueno_actu)+" | Esperado: "+str(dueno_esp)
                resultados["alertas"].append(alerta)
                if verbose:
                    print("     [X] "+str(alerta))
        except KeyError:
            pass 
            
            
        # Comprobamos los permisos (usamos operadores a nivel de bits para validar el máximo permitido)
        perm_actual = stat.S_IMODE(file_stat.st_mode) # Deja los bits limpios de permisos (sin tipo de archivo)
        perm_max = int(max_permisos_esp, 8) # De formato string a octal
        
        # Comprobación a nivel de bits, calculamos el inverso de los bits de los permisos max (donde hay un 0 ponemos un 1 y al revés)
        # Y aplicamos el operador AND entre los permisos de archivo y el inverso del máximo, de esa forma si hay algún bit que represente un permiso excesivo
        # el resultado de la operación será distinto de 0
        if (perm_actual & ~perm_max) != 0: 
            alerta = "El archivo "+str(ruta)+" tiene permisos excesivos. Actual: "+str(oct(perm_actual))+" | Máximo permitido: 0o"+str(max_permisos_esp)
            resultados["alertas"].append(alerta)
            if verbose:
                print("     [X] "+str(alerta))
        else:
            detalle = "El archivo "+str(ruta)+" tiene los permisos y propietario correctos"
            resultados["detalles"].append(detalle)
            if verbose:
                print("     [V] "+str(detalle))

        # Si el archivo es una clave privada, pasamos al siguiente 
        if tipo == "privado":
            continue


        #################### Evaluamos el contenido criptográfico (solo públicos) ########################
        query = "SELECT not_valid_after, signing_algorithm, issuer, subject FROM certificates WHERE path = '"+str(ruta)+"';"
        res_osquery = ejecutar_consulta(query) # Asegúrate de que usas tu función de DB correspondiente

        if res_osquery:
            datos = res_osquery[0]
            
            ################# Comprobamos la caducidad #######################################################
            try:
                # Calculamos el número de días que quedan hasta que caduque el certificado
                timestamp_caducidad = int(datos.get("not_valid_after", 0))
                dias_restantes = int((timestamp_caducidad - time.time()) / 86400)
                
                # Caso de que ya haya caducado
                if dias_restantes < 0:
                    alerta = "El certificado "+str(ruta)+" ha caducado hace "+str(abs(dias_restantes))+" días"
                    resultados["alertas"].append(alerta)
                    if verbose:
                        print("     [X] "+str(alerta))
                        
                # Caso de que falte poco para que caduque 
                elif dias_restantes <= dias_aviso:
                    alerta = "El certificado "+str(ruta)+" caduca pronto (en "+str(dias_restantes)+" días)"
                    resultados["alertas"].append(alerta)
                    if verbose:
                        print("     [!] "+str(alerta))
                        
                # Caso de que aún quede tiempo
                else:
                    detalle = "El certificado "+str(ruta)+" está en vigor. Caduca en "+str(dias_restantes)+" días"
                    resultados["detalles"].append(detalle)
                    if verbose:
                        print("     [V] "+str(detalle))
                        
            except Exception:
                pass

            ############ Comparamos el algoritmo con la white_list ############################################
            algo_actual = datos.get("signing_algorithm", "")
            if algo_actual not in algoritmos_permitidos:
                alerta = "El certificado "+str(ruta)+" usa un algoritmo no permitido: "+str(algo_actual)
                resultados["alertas"].append(alerta)
                if verbose:
                    print("     [X] "+str(alerta))
            else:
                detalle = "El certificado "+str(ruta)+" usa un algoritmo seguro ("+str(algo_actual)+")"
                resultados["detalles"].append(detalle)
                if verbose:
                    print("     [V] "+str(detalle))


            ################ Verificamos si es autofirmado ########################################################
            if datos.get("issuer") == datos.get("subject"):
                alerta = "El certificado "+str(ruta)+" está AUTOFIRMADO (Peligro en producción)"
                resultados["alertas"].append(alerta)
                if verbose:
                    print("     [!] "+str(alerta))

        # Consultamos el tamaño de la clave y el EKU ejecutando openssl
        try:
            res_ssl = subprocess.run(['openssl', 'x509', '-in', ruta, '-text', '-noout'], capture_output=True, text=True)
            if res_ssl.returncode == 0:
                salida_ssl = res_ssl.stdout
                
                # Obtenemos el tamaño de la clave con una expresión regular
                match_size = re.search(r'Public-Key: \((\d+) bit\)', salida_ssl)
                if match_size:
                    tamano = int(match_size.group(1))
                    if tamano < min_rsa:
                        alerta = "El certificado "+str(ruta)+" tiene una clave insuficiente: "+str(tamano)+" bits (Min: "+str(min_rsa)+")"
                        resultados["alertas"].append(alerta)
                        if verbose:
                            print("     [X] "+str(alerta))
                    else:
                        detalle = "El tamaño de la clave del certificado "+str(ruta)+" es robusto ("+str(tamano)+" bits)"
                        resultados["detalles"].append(detalle)
                        if verbose:
                            print("     [V] "+str(detalle))

                # Obtenemos el permiso EKU
                if "TLS Web Server Authentication" not in salida_ssl:
                    alerta = "El certificado "+str(ruta)+" no tiene el permiso 'Server Authentication'"
                    resultados["alertas"].append(alerta)
                    if verbose:
                        print("     [X] "+str(alerta))
                else:
                    detalle = "El certificado "+str(ruta)+" tiene el propósito 'Server Authentication' válido"
                    resultados["detalles"].append(detalle)
                    if verbose:
                        print("     [V] "+str(detalle))
        except Exception:
            pass


    #################### Catalogamos el resultado final ############################################
    if len(resultados["alertas"]) == 0:
        resultados["estado"] = 'SEGURO'
        if verbose:
            print("     [V] Se cumplen todas las políticas de seguridad en certificados")
    elif verbose:
        print("     [!] Se han detectado "+str(len(resultados["alertas"]))+" configuraciones catalogadas como no seguras")
    
    return resultados












#################################################################################################################################
def auditar_cifrado(verbose):
    print("[+] Comprobando el cifrado de discos (LUKS/FDE)...")
    resultados = {
        "estado": "PELIGROSO",
        "detalles": [],
        "alertas":[]
    }
    
    # Cargamos la config del .yaml
    try:
        req_algoritmo = config["hardening"]["encryption"]["algoritmo"]
        critical_mounts = config["hardening"]["encryption"]["critical_mounts"]
    except KeyError:
        print("     [ERROR] No se ha encontrado la configuración de cifrado en config.yaml")
        req_algoritmo = "sha256"
        critical_mounts = ["/", "/home", "/var"]
        
    
    query = '''
        SELECT m.device, m.device_alias, m.path, m.type, de.encryption_status, de.encrypted
        FROM mounts m
        LEFT JOIN disk_encryption de ON de.name = m.device_alias
        WHERE m.device LIKE '/dev/%' AND m.device NOT LIKE '/dev/loop%'
        ORDER BY m.device;
    '''
    res_consulta = ejecutar_consulta(query)
    tot_particiones = 0
    tot_cifradas = 0
    
    # Listas para llevar la cuenta de los montajes críticos del YAML
    criticos_encontrados = []
    criticos_cifrados = []
    
    if res_consulta:
        for linea in res_consulta:
            tot_particiones += 1
            dispositivo = linea.get('device_alias', '')
            ruta = linea.get('path', '')
            
            # Comprobamos si la ruta es una de las marcadas en el .yaml
            if ruta in critical_mounts:
                criticos_encontrados.append(ruta)
            
            # Comprobamos si la partición está cifrada (se indica en 2 campos)
            if (str(linea.get('encrypted', '0')) == '1') or (str(linea.get('encryption_status', '')) == 'encrypted'):
                tot_cifradas += 1
                if ruta in critical_mounts:
                    criticos_cifrados.append(ruta)
                    
                algoritmo = "desconocido"
                
                # Vamos a tratar de obtener el algoritmo usado para el cifrado de la partición
                try:
                    res_crypt = subprocess.run(["cryptsetup", "status", dispositivo], capture_output=True, text=True)
                    if res_crypt.returncode == 0:
                        for l in res_crypt.stdout.splitlines():
                            if "cipher:" in l.lower():
                                algoritmo = l.split(":")[1].strip()
                except Exception:
                    pass
                
                # Comprobamos si usa el algo de cifrado especificado en el .yaml                
                advertencia_algo = ""
                if (req_algoritmo.lower() not in algoritmo.lower()) and (algoritmo != "desconocido"):
                    advertencia_algo =" (Usa "+algoritmo+", se recomienda "+req_algoritmo+")"
                    resultados["alertas"].append("El dispositivo "+dispositivo+" no usa el algoritmo recomendado: "+algoritmo)

                
                # Completamos el campo detalles con la info obtenida
                detalle = "El dispositivo "+str(dispositivo)+" tiene una partición cifrada con punto de montaje en "+str(ruta)+" usando el algoritmo '"+str(algoritmo)+"'"+advertencia_algo
                resultados["detalles"].append(detalle)
                
                if advertencia_algo != "" and verbose:
                    print("     [!] "+str(detalle))
                elif verbose: 
                    print("     [V] "+str(detalle))
        
        
            # En el caso de que la partición no esté cifrada
            else:
                alerta = "El dispositivo "+str(dispositivo)+" tiene una partición sin cifrar con punto de montaje en "+str(ruta)
                resultados["alertas"].append(alerta)
                if verbose:
                    print("     [X] "+str(alerta))
     
     
                    
    ######################## Catalogamos los resultados ######################################################################################
    
    # Sacamos las particiones críticas que existen en el sistema pero no están cifrados
    criticos_vulnerables = [m for m in criticos_encontrados if m not in criticos_cifrados]
    
    if tot_particiones == 0:
        resultados["alertas"].append("No se detectaron particiones físicas válidas para auditar.")
        if verbose: print("     [!] No se detectaron particiones físicas válidas.")
        
    # Si no hay críticos vulnerables y hemos encontrado al menos uno crítico, es SEGURO
    elif len(criticos_vulnerables) == 0 and len(criticos_encontrados) > 0:
        resultados["estado"] = "SEGURO"
        resumen = f"Todos los montajes críticos detectados ({', '.join(criticos_encontrados)}) están cifrados."
        resultados["detalles"].append(resumen)
        if verbose: print("     [V] " + resumen)
        
    else:
        # Falla si falta algún crítico por cifrar o si no hay ninguno cifrado
        alerta_peligro = "Falta cifrado en puntos de montaje críticos: " + ", ".join(criticos_vulnerables) if criticos_vulnerables else f"Ninguna de las {tot_particiones} particiones físicas está cifrada."
        resultados["alertas"].append(alerta_peligro)
        if verbose: print("     [X] PELIGRO: " + alerta_peligro)
        
    
    return resultados



        









#################################################################################################################################
def ESCANER_hardening(verbose):
    datos_reporte = {
        "archivos_criticos": [],
        "ssh": {},
        "firewall": {},
        "suid_sgid": [],
        "kernel_aslr": {},
        "mac": {},
        "certificados": {},
        "cifrado": {}
    }

    print("\n--- [ FASE 5: HARDENING DEL SISTEMA ] ---")
    print("[+] Iniciando módulo de hardening")
    
    datos_reporte["suid_sgid"] = auditar_suid_sgid(verbose)
    datos_reporte["archivos_criticos"] = auditar_archivos_criticos(verbose)
    datos_reporte["ssh"] = auditar_ssh(verbose)
    datos_reporte["firewall"] = auditar_firewall(verbose)
    datos_reporte["kernel_aslr"] = auditar_aslr(verbose)
    datos_reporte["mac"] = auditar_mac(verbose)
    datos_reporte["certificados"] = auditar_certificados(verbose)
    datos_reporte["cifrado"] = auditar_cifrado(verbose)

    print("[-] Finalizando módulo de hardening")
    
    return datos_reporte