import subprocess
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


















#########################################################################################################################################################
def auditar_firewall(verbose):
    print(" [+] Comprobando el estado del Firewall")
    
    resultado = {
        "estado": "PELIGROSO",
        "firewall_activo": "Ninguno",
        "detalles": [],
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
                nombre = servicio.get("id").replace(".service", "") # Limpiamos el nombre por comodidad ya que todos terminan en .service
                estado_actu = servicio.get("active_state")
                estado_arranque = servicio.get("unit_file_state")
                
                # Comprobamos si está activo y si por defecto se inicia al arrancar el sistema 
                if estado_actu == 'active':
                    servicios_activos.append(nombre)
                    
                    # Comprobamos si no está configurado para arrancar al iniciar el sistema
                    if estado_arranque != 'enabled':
                        alerta = "El gestor '" + nombre + "' está encendido ahora, pero no arrancará tras un reinicio (estado: " + str(estado_arranque) + ")"
                        resultado["alertas"].append(alerta)
                        if verbose:
                            print("     [!] " + alerta)
                            
                # Caso de que estéconfigurado para arrancar siempre, pero actualmente está apagado o caído
                elif estado_arranque == 'enabled' and estado_actu != 'active':
                    alerta = "El gestor '" + nombre + "' debería estar encendido de forma persistente (enabled), pero actualmente está APAGADO."
                    resultado["alertas"].append(alerta)
                    if verbose:
                        print("     [!] " + alerta)

    ############## Comprobación de si ay normas activas (de bloquear y descartar) ########################################
    reglas_bloqueo = 0
    politica_accept = False
    bloqueo_output = False
    bloqueo_forward = False
    
    # Tratamos de obtener las normas actuales del sistema con iptables -S (similar a las interfaces de networking)
    # de esta forma buscamos las políticas que hemos obtenido y rechazan o bloquean peticiones (si no hay ninguna de este
    # timpo, el firewall no estará filtrando nada, por lo que en la práctica sería como si no estuviese activo)
    try:
        # Leemos todas las posibles cadenas (OUTPUT, FORWARD, etc.)
        res_iptables = subprocess.run(["iptables", "-S"], capture_output=True, text=True)
        if res_iptables.returncode == 0:
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
    if reglas_bloqueo == 0:
        try:
            res_nft = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
            if res_nft.returncode == 0:
                # Convertimos toda la salida a minúsculas para buscar fácilmente
                salida_nft = res_nft.stdout.lower()
                
                if "policy accept" in salida_nft:
                    politica_accept = True
                if "drop" in salida_nft or "reject" in salida_nft:
                    reglas_bloqueo += 1
                if "output" in salida_nft and ("drop" in salida_nft or "reject" in salida_nft):
                    bloqueo_output = True
                if "forward" in salida_nft and ("drop" in salida_nft or "reject" in salida_nft):
                    bloqueo_forward = True
            elif verbose:
                print("     [DEBUG] nft devolvió error: " + res_nft.stderr.strip().replace('\n', ' '))
        except FileNotFoundError:
            # Falla si los comandos nft no están instalados en el sistema
            pass
        except Exception as e:
            if verbose:
                print("     [i] No se pudieron comprobar las reglas del kernel directamente: " + str(e))
    
    ########### Clasificamos los resultados obtenidos ################################################################
    if reglas_bloqueo > 0:
        resultado["estado"] = "SEGURO"
        # Caso de que el firewall está en systemd y tiene reglas de bloqueo en el kernel
        if len(servicios_activos) > 0:
            resultado["firewall_activo"] = " / ".join(servicios_activos)
            resultado["detalles"].append('El sistema está protegido por '+resultado["firewall_activo"]+' y por '+str(reglas_bloqueo)+' reglas de bloqueo')
            if verbose:
                print("     [V] "+resultado["detalles"][-1])
        
        # Caso de que el firewall no se está ejecutando pero hay reglas en el kernel
        else:
            resultado["firewall_activo"] = "Reglas de bloqueo manuales"
            resultado["detalles"].append('No se ha detectado ningún servicio de getión activo, pero el sistema está protegido por '+str(reglas_bloqueo)+' reglas de bloqueo')
            if verbose:
                print("     [V] "+resultado["detalles"][-1])
    
    # Caso de que aunque está activo un firewall no hay reglas de bloqueo en el kernel, por lo que no se filtra
    elif len(servicios_activos) > 0:
        resultado["firewall_activo"] = " / ".join(servicios_activos)
        resultado["alertas"].append('Aunque se han detectado servicios de firewall activos en el sistema, no existen reglas de bloqueo, por lo que no se está ejerciendo ningún filtro real')
        if verbose:
            print('     [!] Aunque se han detectado servicios de firewall activos en el sistema, no existen reglas de bloqueo, por lo que no se está ejerciendo ningún filtro real')
    
    # No hay ni firewall ni reglas
    else:
        resultado["alertas"].append('No se han detectado ni firewalls ni reglas de bloqueo activas, el sistema se encentra expuesto a la red')
        if verbose:
            print('     [X] No se han detectado ni firewalls ni reglas de bloqueo activas, el sistema se encentra expuesto a la red')
            
    ############## Alertas extra ####################################################################################
    # Solo alertamos si el firewall está activo o hay reglas, porque si está apagado ya lo hemos dicho arriba.
    if reglas_bloqueo > 0 or len(servicios_activos) > 0:
        if politica_accept:
            alerta_pol = "El firewall tiene políticas por defecto permisivas (ACCEPT). Se recomienda un enfoque 'Default Deny'"
            resultado["alertas"].append(alerta_pol)
            if verbose:
                print("     [!] " + alerta_pol)
                
        if not bloqueo_output:
            alerta_out = "No se han detectado reglas de bloqueo en la cadena OUTPUT"
            resultado["alertas"].append(alerta_out)
            if verbose:
                print("     [!] " + alerta_out)
                
        if not bloqueo_forward:
            alerta_fwd = "No se han detectado reglas de bloqueo en la cadena FORWARD. Riesgo de enrutamiento no deseado"
            resultado["alertas"].append(alerta_fwd)
            if verbose:
                print("     [!] " + alerta_fwd)
    
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












#################################################################################################################################
def auditar_cifrado(verbose):
    print(" [+] Comprobando el cifrado de discos (LUKS/FDE)...")
    resultados = {
        "estado": "PELIGROSO",
        "detalles": [],
        "alertas":[]
    }
    
    # Cargamos la config del .yaml
    try:
        req_algoritmo = config["hardening"]["encryption"]["algoritmo"]
        comp_luks = config["hardening"]["encryption"]["comp_luks"]
        critical_mounts = config["hardening"]["encryption"]["critical_mounts"]
    except KeyError:
        print("     [ERROR] No se ha encontrado la configuración de cifrado en config.yaml")
        req_algoritmo = "sha256"
        comp_luks = True
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
                    advertencia_algo ="(Usa "+algoritmo+", se recomienda "+req_algoritmo+")"
                    resultados["alertas"].append("El dispositivo "+dispositivo+" no usa el algoritmo recomendado: "+algoritmo)

                
                # Completamos el campo detalles con la info obtenida
                detalle = "El dispositivo "+str(dispositivo)+" tiene una partición cifrada con punto de montaje en "+str(ruta)+" usando el algoritmo '"+str(algoritmo)+"'"+advertencia_algo
                resultados["detalles"].append(detalle)
                if (advertencia_algo != "") and verbose:
                    print("     [V] "+str(detalle))
                else: 
                    print("     [!] "+str(resultados["alertas"][-1]))
        
        
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