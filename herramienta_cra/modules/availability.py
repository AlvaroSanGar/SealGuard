# SealGuard - Herramienta de Auditoria CRA
# Copyright (C) 2026 Alvaro Sanchez Garijo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
import os
from modules.system import ejecutar_consulta
from config.settings import config
from core.colores_terminal import print_c, mostrar_subtitulos






###########################################################################################################################
def auditar_backups(verbose):
    print("")
    print_c("[+] Auditando políticas de copias de seguridad")
    resultados = {
        "backups_activos": False,
        "mecanismos_encontrados": [],
        "detalles": [],
        "alertas": [],
        "tabla_backups": [], 
        "huerfanos": []
    }
    #Sacamos los datos del .yaml
    try:
        palabras_clave = config["disponibilidad"]
    except KeyError:
        print_c("     [ERROR] No se han podido cargar la configuración de disponibilidad de config.yaml")
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
            
            resultados["tabla_backups"].append({
                "nombre": comando[:40] + "...", 
                "tipo": "Cron", 
                "estado": "ACTIVO", 
                "estado_color": "OK",
                "ruta": ruta_cron
            })
            
            if verbose:
                print_c("     [i] "+str(detalle))
    else:
        alerta = "No se han detectado tareas de backup en crontab"
        resultados["alertas"].append(alerta)
        if verbose:
            print_c("     [!] "+alerta)
    
    #### Buscamos unidades de systemd ############################################################################
    query_untis = 'SELECT * FROM systemd_units WHERE '+condiciones_desc+' OR '+condiciones_id+';'
    res_units = ejecutar_consulta(query_untis)
    if not res_units:
        alerta = 'No hay unidades de systemd asociadas a tareas de copias de seguridad'
        resultados["alertas"].append(alerta)
        if verbose:
            print_c("     [!] "+alerta)
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
                    
                    resultados["tabla_backups"].append({
                        "nombre": nombre_uni, "tipo": "Systemd Timer", "estado": estado_uni.upper(), "estado_color": "OK", "ruta": descrip_uni
                    })
                    
                    if verbose: print_c("     [Ok] "+str(detalle))
                
                else:
                    alerta = 'Se ha detectado la unidad de backup en estado '+str(estado_uni)+': '+str(nombre_uni)+' | '+str(descrip_uni)
                    resultados["alertas"].append(alerta)
                    
                    resultados["tabla_backups"].append({
                        "nombre": nombre_uni, "tipo": "Systemd Timer", "estado": estado_uni.upper(), "estado_color": "RIESGO", "ruta": descrip_uni
                    })
                    
                    if verbose: print_c("     [i] "+str(alerta))
                
            elif nombre_uni.endswith('.service'):
                if estado_uni == 'fail' and (nombre_uni.removesuffix('.service') in resultados["mecanismos_encontrados"]):
                    alerta = 'La unidad '+str(nombre_uni)+' ha fallado en su ejecución'
                    resultados["alertas"].append(str(alerta))
                    if verbose: print_c("     [!] "+str(alerta))
                elif not nombre_uni.removesuffix('.service') in resultados["mecanismos_encontrados"]:
                    alerta = 'Se ha detectado la unidad '+str(nombre_uni)+' la cual no tiene ningún timer asociado'
                    resultados["alertas"].append(str(alerta))
                    
                    resultados["huerfanos"].append(nombre_uni)
                    
                    if verbose: print_c("     [!] "+str(alerta))
                    
    # evaluamos el resultado
    if len(resultados["mecanismos_encontrados"]) > 0:
        resultados["backups_activos"] = True
    
    return resultados
















##########################################################################################################################
def auditar_protecciones_dos(verbose):
    print("")
    print_c("[+] Auditando protecciones del kernel contra Denegación de Servicio")
    resultados = {
        "estado": "PELIGROSO",
        "tcp_syncookies": False,
        "rp_filter": False,
        "tcp_max_syn_backlog": False,
        "icmp_echo_ignore_broadcasts": False,
        "detalles": [],
        "alertas": [],
        "tabla_dos": [] 
    }
    
    nombres = [
        "net.ipv4.tcp_syncookies", 
        "net.ipv4.conf.all.rp_filter", 
        "net.ipv4.tcp_max_syn_backlog",
        "net.ipv4.icmp_echo_ignore_broadcasts"
    ]
    nombres_sql = ",".join([f"'{n}'" for n in nombres])
    query = str('SELECT name, current_value FROM system_controls WHERE name IN ('+nombres_sql+');')
    res = ejecutar_consulta(query)
    
    # [CORRECCIÓN] Inicializamos por defecto en 0. Si OSquery falla o no los lista, asumimos que son vulnerables.
    valores = {
        "net.ipv4.tcp_syncookies": "0",
        "net.ipv4.conf.all.rp_filter": "0",
        "net.ipv4.tcp_max_syn_backlog": "0",
        "net.ipv4.icmp_echo_ignore_broadcasts": "0"
    }
    
    if res:
        for item in res:
            valores[item["name"]] = str(item.get("current_value", "0"))
            
    
    ############### tcp_syncookies ##################################################################################################
    val_syncookies = valores["net.ipv4.tcp_syncookies"]
    if val_syncookies == "1":
        resultados["tcp_syncookies"] = True
        detalle = "SYN Cookies está activado con normalidad. El kernel enviará cookies solo cuando la cola esté llena"
        resultados["detalles"].append(detalle)
        resultados["tabla_dos"].append({"param": "tcp_syncookies", "estado_color": "OK", "desc": detalle}) 
        if verbose: print_c("     [Ok] " + detalle)
    elif val_syncookies == "2":
        resultados["tcp_syncookies"] = True 
        alerta = "SYN Cookies está activado en modo forzado. Aunque da protección, no se recomienda ya que aumenta la carga de CPU"
        resultados["alertas"].append(alerta)
        resultados["tabla_dos"].append({"param": "tcp_syncookies", "estado_color": "ADVERTENCIA", "desc": alerta}) 
        if verbose: print_c("     [!] " + alerta)
    else: 
        alerta = "SYN Cookies está desactivado. El servidor dejará de aceptar conexiones si la cola se llena"
        resultados["alertas"].append(alerta)
        resultados["tabla_dos"].append({"param": "tcp_syncookies", "estado_color": "PELIGRO", "desc": alerta}) 
        if verbose: print_c("     [X] " + alerta)

    ########## rp_filter ################################################################################################################
    val_rpfilter = valores["net.ipv4.conf.all.rp_filter"]
    if val_rpfilter == "1":
        resultados["rp_filter"] = True
        detalle = "Reverse Path Filter está activado en modo estricto"
        resultados["detalles"].append(detalle)
        resultados["tabla_dos"].append({"param": "rp_filter", "estado_color": "OK", "desc": detalle}) 
        if verbose: print_c("     [Ok] " + detalle)
    elif val_rpfilter == "2":
        resultados["rp_filter"] = True
        alerta = "Reverse Path Filter está activado en modo perdida. Solo verifica si la IP es alcanzable"
        resultados["alertas"].append(alerta)
        resultados["tabla_dos"].append({"param": "rp_filter", "estado_color": "ADVERTENCIA", "desc": alerta}) 
        if verbose: print_c("     [!] " + alerta)
    else: 
        alerta = "Reverse Path Filter está desactivado. El sistema no valida la ruta de origen"
        resultados["alertas"].append(alerta)
        resultados["tabla_dos"].append({"param": "rp_filter", "estado_color": "PELIGRO", "desc": alerta}) 
        if verbose: print_c("     [X] " + alerta)

    ########## tcp_max_syn_backlog ########################################################################################################
    try:
        val_backlog = int(valores["net.ipv4.tcp_max_syn_backlog"])
        if val_backlog >= 2048:
            resultados["tcp_max_syn_backlog"] = True
            detalle = "El tamaño de la cola SYN es seguro ("+str(val_backlog)+" bytes)"
            resultados["detalles"].append(detalle)
            resultados["tabla_dos"].append({"param": "tcp_max_syn_backlog", "estado_color": "OK", "desc": detalle}) 
            if verbose: print_c("     [Ok] " + detalle)
        else:
            alerta = "El tamaño de la cola SYN es insuficiente ("+str(val_backlog)+" bytes)"
            resultados["alertas"].append(alerta)
            resultados["tabla_dos"].append({"param": "tcp_max_syn_backlog", "estado_color": "PELIGRO", "desc": alerta}) 
            if verbose: print_c("     [X] " + alerta)
    except ValueError:
        alerta = "El valor de tcp_max_syn_backlog no es numérico"
        resultados["alertas"].append(alerta)
        resultados["tabla_dos"].append({"param": "tcp_max_syn_backlog", "estado_color": "PELIGRO", "desc": alerta})

    ########## icmp_echo_ignore_broadcasts ################################################################################################
    val_icmp = valores["net.ipv4.icmp_echo_ignore_broadcasts"]
    if val_icmp == "1":
        resultados["icmp_echo_ignore_broadcasts"] = True
        detalle = "Ignorar ICMP Broadcast está activado"
        resultados["detalles"].append(detalle)
        resultados["tabla_dos"].append({"param": "icmp_echo_ignore_broadcasts", "estado_color": "OK", "desc": detalle}) 
        if verbose: print_c("     [Ok] " + detalle)
    else:
        alerta = "Ignorar ICMP Broadcast está desactivado. El sistema responderá a pings broadcast y podría usarse para amplificar ataques DDoS"
        resultados["alertas"].append(alerta)
        resultados["tabla_dos"].append({"param": "icmp_echo_ignore_broadcasts", "estado_color": "PELIGRO", "desc": alerta}) 
        if verbose: print_c("     [X] " + alerta)


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
            print_c("     [X] "+str(alerta))
        
    elif len(resultados["alertas"]) > 0:
        alerta = "Aunque el kerenl no presenta una configuración con fallos críticos, se recomienda revisar la configuración"
        resultados["alertas"].append(alerta)
        resultados["estado"] = "ADVERTENCIA"
        if verbose:
            print_c("     [i] "+alerta)
    
    else:
        resultados["estado"] = "SEGURO"
        detalle = "El sistema cuenta con protecciones bien configuradas contra DoS"
        resultados["detalles"].append(detalle)
        if verbose: 
            print_c("     [Ok] "+detalle)
        
    return resultados

###########################################################################################################################
def auditar_limites_recursos(verbose):
    print("")
    print_c("[+] Auditando límites de recursos de usuario")
    resultados = {
        "estado": "PELIGROSO",
        "detalles": [],
        "alertas": [],
        "tabla_limites": [],
        "ningun_limite": False
    }
    
    # Vamos a comprobar los archivos de configuración en los que se definen los límites de los recursos de cada usuario
    archivos_limits = ['/etc/security/limits.conf']
    
    # Añadimos los archivos del directorio limits.d si existe
    if os.path.exists('/etc/security/limits.d'):
        for archivo in os.listdir('/etc/security/limits.d'):
            if archivo.endswith('.conf'):
                archivos_limits.append(str('/etc/security/limits.d/'+str(archivo)))
                
    estado_limites = {
        "nproc": {"encontrado": False, "valor": "-", "archivo": "-", "desc_riesgo": "Agotamiento de tabla de procesos (Fork Bomb)"},
        "core": {"encontrado": False, "valor": "-", "archivo": "-", "desc_riesgo": "Llenado de disco por volcados de memoria masivos"},
        "nofile": {"encontrado": False, "valor": "-", "archivo": "-", "desc_riesgo": "Agotamiento de descriptores (Too many open files)"}
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
                            if item in estado_limites:
                                estado_limites[item]["encontrado"] = True
                                estado_limites[item]["valor"] = valor
                                estado_limites[item]["archivo"] = ruta
                                detalle = "Límite global ("+str(item)+") detectado en "+str(ruta)+": "+str(valor)
                                resultados["detalles"].append(str(detalle))
                                if verbose: print_c("     [Ok] "+str(detalle))
                                
        except Exception as e:
            alerta = "No se puede leer el archivo "+str(ruta)+": "+str(e)
            resultados["alertas"].append(str(alerta))
            if verbose: print_c("     [ERROR] "+str(alerta))

    limites_faltantes = []
    limites_encontrados_contador = 0
    for param, info in estado_limites.items():
        resultados["tabla_limites"].append({
            "param": param,
            "encontrado": info["encontrado"],
            "valor": info["valor"],
            "archivo": info["archivo"],
            "riesgo": info["desc_riesgo"]
        })
        if not info["encontrado"]:
            limites_faltantes.append(param)
        else:
            limites_encontrados_contador += 1

    # Lógica de si no hay ninguno
    if limites_encontrados_contador == 0:
        resultados["ningun_limite"] = True

    ##### Evaluamos los resultados
    if not limites_faltantes:
        resultados["estado"] = "SEGURO"
        if verbose: 
            print_c("     [Ok] El sistema se encuentra protegido frente a Fork Bombs, Agotamiento de FDs y volcados masivos")
            
    elif limites_encontrados_contador > 0:
        resultados["estado"] = "ADVERTENCIA"
        alerta = "Protección parcial. Faltan límites para: " + ", ".join(limites_faltantes)
        resultados["alertas"].append(alerta)
        if verbose: 
            print_c("     [!] "+str(alerta))
            
    else:
        resultados["estado"] = "PELIGROSO"
        alerta = "Riesgo crítico de denegación de servicio. No se detectó ningún límite."
        resultados["alertas"].append(alerta)
        if verbose: 
            print_c("     [X] "+str(alerta))
            
    return resultados








###########################################################################################################################
def ESCANER_disponibilidad(verbose):
    datos_reporte = {
        "backups": {},
        "protecciones_dos": {},
        "limites_recursos": {}
    }

    mostrar_subtitulos("Disponibilidad")    
    print("")
    print_c("[+] Iniciando módulo de disponibilidad")
    
    datos_reporte["backups"] = auditar_backups(verbose)
    datos_reporte["protecciones_dos"] = auditar_protecciones_dos(verbose)
    datos_reporte["limites_recursos"] = auditar_limites_recursos(verbose)
    
    print("")
    print_c("[-] Finalizando módulo de disponibilidad")
    return datos_reporte