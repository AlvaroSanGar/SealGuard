import os
from modules.system import ejecutar_consulta
from config.settings import config



###########################################################################################################################
def auditar_backups(verbose):
    print("[+] Auditando políticas de copias de seguridad (Resiliencia)")
    resultados = {
        "backups_activos": False,
        "mecanismos_encontrados": [],
        "detalles": [],
        "alertas": []
    }
    #Sacamos los datos del .yaml
    try:
        palabras_clave = config["disponibilidad"]
    except KeyError:
        print("     [ERROR] No se han podido cargar la configuración de disponibilidad de config.yaml")
        palabras_clave = ["backup", "rsync", "tar", "snapshot", "aws s3", "rclone"]
    
    # Usamos las condiciones de esta forma en vez de como lo hemos hecho normalmente ya que debemos usar LIKE no IN, y como LIKE solo acepta 
    # un único string, no podemos pasarle directamente la lista como en otros casos
    condiciones_desc = " OR ".join(["description LIKE '%"+str(kw)+"%'" for kw in palabras_clave])
    condiciones_id = " OR ".join(["id LIKE '%"+str(kw)+"%'" for kw in palabras_clave])
    condiciones_cron = " OR ".join(["command LIKE '%"+str(kw)+"%'" for kw in palabras_clave])
    
    ######## Busqueda de crons ##################################################################################
    query_cron = "SELECT command, path FROM crontab WHERE "+str(condiciones_cron)+";"
    res_cron = ejecutar_consulta(query_cron)
    
    if res_cron:
        for tarea in res_cron:
            comando = str(tarea.get('command'))
            ruta_cron = str(tarea.get('path'))
            
            detalle = "Se ha detectado una tarea programada de backup en "+str(ruta_cron)+": "+str(comando[:50])
            resultados["detalles"].append(detalle)
            resultados["mecanismos_encontrados"].append(str("cron: "+ruta_cron))
            if verbose:
                print("     [i] "+str(detalle))
    else:
        alerta = "No se han detectado tareas de backup en crontab"
        resultados["alertas"].append(alerta)
        if verbose:
            print("     [!] "+alerta)
    
    #### Buscamos unidades de systemd ############################################################################
    query_untis = 'SELECT * FROM systemd_units WHERE '+condiciones_desc+' OR '+condiciones_id+';'
    res_units = ejecutar_consulta(query_untis)
    if not res_units:
        alerta = 'No hay unidades de systemd asociadas a tareas de copias de seguridad'
        resultados["alertas"].append(alerta)
        if verbose:
            print("     [!] "+alerta)
    else:
        servicios_timer = []
        for unidad in res_units:
            # Obtenemos datos de cada resultado de la consulta
            nombre_uni = str(unidad.get('id')).lower()
            descrip_uni = str(unidad.get('description')).lower()
            estado_uni = str(unidad.get('sub_state')).lower()
            
            # Hay dos timpos de unidades, las timer y las action o service. Las timer deben estar activas ya que son las que dada una 
            # condición (eje: son las 12:00), activan al servicio. Por otra parte, los actuadores suelen estar inactivos, ya que son los 
            # timers los que los activan
            if nombre_uni.endswith('.timer'):
                # Caso de que la unidad esté activa o en estado de espera
                if estado_uni == 'active' or estado_uni == 'waiting':
                    detalle = 'Se ha detectado la unidad de backup activa: '+str(nombre_uni)+' | '+str(descrip_uni)
                    resultados["detalles"].append(detalle)
                    resultados["mecanismos_encontrados"].append(nombre_uni.removesuffix('.timer'))
                    if verbose: print("     [V] "+str(detalle))
                
                else:
                    alerta = 'Se ha detectado la unidad de backup en estado '+str(estado_uni)+': '+str(nombre_uni)+' | '+str(descrip_uni)
                    resultados["alertas"].append(alerta)
                    if verbose: print("     [i] "+str(alerta))
                
            elif nombre_uni.endswith('.service'):
                if estado_uni == 'fail' and (nombre_uni.removesuffix('.service') in resultados["mecanismos_encontrados"]):
                    alerta = 'La unidad '+str(nombre_uni)+' ha fallado en su ejecución'
                    resultados["alertas"].append(str(alerta))
                    if verbose: print("     [!] "+str(alerta))
                elif not nombre_uni.removesuffix('.service') in resultados["mecanismos_encontrados"]:
                    alerta = 'Se ha detectado la unidad '+str(nombre_uni)+' la cual no tiene ningún timer asociado'
                    resultados["alertas"].append(str(alerta))
                    if verbose: print("     [!] "+str(alerta))
                    
    # evaluamos el resultado
    if len(resultados["mecanismos_encontrados"]) > 0:
        resultados["backups_activos"] = True
    
    return resultados














##########################################################################################################################
def auditar_protecciones_dos(verbose):
    print("[+] Auditando protecciones del kernel contra Denegación de Servicio (DoS)")
    resultados = {
        "estado": "PELIGROSO",
        "tcp_syncookies": False,
        "rp_filter": False,
        "tcp_max_syn_backlog": False,
        "icmp_echo_ignore_broadcasts": False,
        "detalles": [],
        "alertas": []
    }
    
    # Cargamos la lista de nomres en una consulta a OSquery
    nombres = [
        "net.ipv4.tcp_syncookies", 
        "net.ipv4.conf.all.rp_filter", 
        "net.ipv4.tcp_max_syn_backlog",
        "net.ipv4.icmp_echo_ignore_broadcasts"
    ]
    nombres_sql = ",".join([f"'{n}'" for n in nombres])
    query = str('SELECT name, current_value FROM system_controls WHERE name IN ("'+nombres_sql+'");')
    res = ejecutar_consulta(query)
    
    # Guardamos los resultados en un diccionario 
    valores = {}
    if res:
        for item in res:
            # Si no obtenemos ningún valor ponemos 0 ya que en todos los casos es el equivalente a que esté desactivado
            valores[item["name"]] = str(item.get("current_value", "0"))
            
    
    ############### tcp_syncookies ##################################################################################################
    if "net.ipv4.tcp_syncookies" in valores:
        val_syncookies = valores["net.ipv4.tcp_syncookies"]
        if val_syncookies == "1":
            resultados["tcp_syncookies"] = True
            detalle = "SYN Cookies está activado con normalidad. El kernel enviará cookies solo cuando la cola esté llena"
            resultados["detalles"].append(detalle)
            if verbose: print("     [V] " + detalle)
        elif val_syncookies == "2":
            resultados["tcp_syncookies"] = True 
            alerta = "SYN Cookies está activado en modo forzado. Aunque da protección, no se recomienda ya que aumenta la carga de CPU"
            resultados["alertas"].append(alerta)
            if verbose: print("     [!] " + alerta)
        else: 
            alerta = "SYN Cookies está desactivado. El servidor dejará de aceptar conexiones si la cola se llena"
            resultados["alertas"].append(alerta)
            if verbose: print("     [X] " + alerta)
    else:
        resultados["alertas"].append("No se ha podido comprobar net.ipv4.tcp_syncookies")

    ########## rp_filter ################################################################################################################
    if "net.ipv4.conf.all.rp_filter" in valores:
        val_rpfilter = valores["net.ipv4.conf.all.rp_filter"]
        if val_rpfilter == "1":
            resultados["rp_filter"] = True
            detalle = "Reverse Path Filter está en activado en modo estricto"
            resultados["detalles"].append(detalle)
            if verbose: print("     [V] " + detalle)
        elif val_rpfilter == "2":
            resultados["rp_filter"] = True
            alerta = "Reverse Path Filter está activado en modo perdida. Solo verifica si la IP es alcanzable"
            resultados["alertas"].append(alerta)
            if verbose: print("     [!] " + alerta)
        else: 
            alerta = "Reverse Path Filter  está desactivado. El sistema no valida la ruta de origen"
            resultados["alertas"].append(alerta)
            if verbose: print("     [X] " + alerta)
    else:
        resultados["alertas"].append("No se ha podido comprobar net.ipv4.conf.all.rp_filter")

    ########## tcp_max_syn_backlog ########################################################################################################
    if "net.ipv4.tcp_max_syn_backlog" in valores:
        try:
            val_backlog = int(valores["net.ipv4.tcp_max_syn_backlog"])
            if val_backlog >= 2048:
                resultados["tcp_max_syn_backlog"] = True
                detalle = "El tamaño de la cola SYN es seguro ("+str(val_backlog)+" bytes)"
                resultados["detalles"].append(detalle)
                if verbose: print("     [V] " + detalle)
            else:
                alerta = "El tamaño de la cola SYN es insuficiente ("+str(val_backlog)+" bytes)"
                resultados["alertas"].append(alerta)
                if verbose: print("     [X] " + alerta)
        except ValueError:
            resultados["alertas"].append("El valor de tcp_max_syn_backlog no es numérico")
    else:
        resultados["alertas"].append("No se ha podido comprobar net.ipv4.tcp_max_syn_backlog")

    ########## icmp_echo_ignore_broadcasts ################################################################################################
    if "net.ipv4.icmp_echo_ignore_broadcasts" in valores:
        val_icmp = valores["net.ipv4.icmp_echo_ignore_broadcasts"]
        if val_icmp == "1":
            resultados["icmp_echo_ignore_broadcasts"] = True
            detalle = "Ignorar ICMP Broadcast está activado"
            resultados["detalles"].append(detalle)
            if verbose: print("     [V] " + detalle)
        else:
            alerta = "Ignorar ICMP Broadcast está desactivado. El sistema responderá a pings broadcast y podría usarse para amplificar ataques DDoS"
            resultados["alertas"].append(alerta)
            if verbose: print("     [X] " + alerta)
    else:
        resultados["alertas"].append("No se ha podido comprobar net.ipv4.icmp_echo_ignore_broadcasts")


    ########## Evaluamos el estado global del módulo #####################################################################################
    fallos_criticos = 0
    if valores.get("net.ipv4.tcp_syncookies", "0") == "0": fallos_criticos += 1
    if valores.get("net.ipv4.conf.all.rp_filter", "0") == "0": fallos_criticos += 1
    if valores.get("net.ipv4.icmp_echo_ignore_broadcasts", "0") == "0": fallos_criticos += 1
    if not resultados["tcp_max_syn_backlog"]: fallos_criticos += 1

    if fallos_criticos > 0:
        alerta = 'La configuración del kernel en cuanto a ataques DoS presenta fallos críticos ('+str(fallos_criticos)+')'
        resultados["alertas"].append(alerta)
        if verbose:
            print("     [X] "+str(alerta))
        
    elif len(resultados["alertas"]) > 0:
        alerta = "Aunque el kerenl no presenta una configuración con fallos críticos, se recomienda revisar la configuración"
        resultados["alertas"].append(alerta)
        resultados["estado"] = "ADVERTENCIA"
        if verbose:
            print("     [i] "+alerta)
    
    else:
        resultados["estado"] = "SEGURO"
        detalle = "El sistema cuenta con protecciones bien configuradas contra DoS"
        resultados["detalles"].append(detalle)
        if verbose: 
            print("     [V] "+detalle)
        
    return resultados












###########################################################################################################################
def auditar_limites_recursos(verbose):
    print("[+] Auditando límites de recursos de usuario")
    resultados = {
        "estado": "PELIGROSO",
        "detalles": [],
        "alertas": []
    }
    
    # Vamos a comprobar los archivos de configuración en los que se definen los límites de los recursos de cada usuario
    archivos_limits = ['/etc/security/limits.conf']
    
    # Añadimos los archivos del directorio limits.d si existe
    if os.path.exists('/etc/security/limits.d'):
        for archivo in os.listdir('/etc/security/limits.d'):
            if archivo.endswith('.conf'):
                archivos_limits.append(str('/etc/security/limits.d/'+str(archivo)))
                
    limites_encontrados = {
        "nproc": False,
        "core": False
    }

    # Leemos los archivos buscando los límites "hard" o "-" (hard y soft)
    for ruta in archivos_limits:
        try:
            with open(ruta, 'r') as f:
                for linea in f:
                    linea = linea.strip()
                    # Ignoramos líneas vacías o comentadas
                    if not linea or linea.startswith('#'):
                        continue
                        
                    partes = linea.split()
                    # El formato es ===> domain type item value
                    if len(partes) >= 4:
                        dominio = partes[0]
                        tipo = partes[1].lower()
                        item = partes[2].lower()
                        valor = partes[3]
                        
                        # Buscamos un dominio global (*) o general para proteger el sistema
                        if dominio == '*' and tipo in ['hard', '-']:
                            if item == 'nproc':
                                limites_encontrados["nproc"] = True
                                detalle = "Límite global de procesos (nproc) detectado en "+str(ruta)+": "+str(valor)
                                resultados["detalles"].append(str(detalle))
                                if verbose: print("     [V] "+str(detalle))
                                
                            elif item == 'core':
                                limites_encontrados["core"] = True
                                detalle = "Límite global de volcados de memoria (core) detectado en "+str(ruta)+": "+str(valor)
                                resultados["detalles"].append(detalle)
                                if verbose: print("     [V] "+str(detalle))
                                
        except Exception as e:
            alerta = "No se puede leer el archivo "+str(ruta)+": "+str(e)
            resultados["alertas"].append(str(alerta))
            if verbose: print("     [ERROR] "+str(alerta))


    ##### Evaluamos los resultados
    if limites_encontrados["nproc"] and limites_encontrados["core"]:
        resultados["estado"] = "SEGURO"
        if verbose: 
            print("     [V] El sistema se encuentra protegido frente a Fork Bombs y volcados masivos")
            
    elif limites_encontrados["nproc"]:
        resultados["estado"] = "ADVERTENCIA"
        alerta = "Protección contra Fork Bombs activa, pero falta limitar los volcados de memoria"
        resultados["alertas"].append(alerta)
        if verbose: 
            print("     [!] "+str(alerta))
            
    else:
        resultados["estado"] = "PELIGROSO"
        alerta = "Riesgo crítico de denegación de servicio por agotamiento de tabla de procesos"
        resultados["alertas"].append(alerta)
        if verbose: 
            print("     [X] "+str(alerta))
            
    return resultados





###########################################################################################################################
def ESCANER_disponibilidad(verbose):
    datos_reporte = {
        "backups": {},
        "protecciones_dos": {},
        "limites_recursos": {}
    }
    
    print("\n--- [ FASE 7: AUDITORÍA DE DISPONIBILIDAD ] ---")
    print("[+] Iniciando módulo de disponibilidad...")
    
    datos_reporte["backups"] = auditar_backups(verbose)
    datos_reporte["protecciones_dos"] = auditar_protecciones_dos(verbose)
    datos_reporte["limites_recursos"] = auditar_limites_recursos(verbose)
    
    print("[-] Finalizando módulo de disponibilidad")
    return datos_reporte