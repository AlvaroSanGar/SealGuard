import os
from modules.system import ejecutar_consulta
from config.settings import config
from core.colores_terminal import print_c, mostrar_subtitulos


###########################################################################################################################

def auditar_integridad_firmware(verbose):
    print("")
    print_c("[+] Auditando integridad del firmware y del kernel")
    resultados = {
        "secure_boot": False,
        "kernel_seguro": False,
        "detalles": [],
        "alertas": [],
        "sb_estado": "PELIGROSO",
        "sb_msg": "",
        "tainted_flags": []
    }
    
    # Cargamos los datos del .yaml
    try:
        white_list = config["boot"]["integridad_kernel"]["white_list"]
        warning_list = config["boot"]["integridad_kernel"]["warning_list"]
        black_list = config["boot"]["integridad_kernel"]["black_list"]
        
    except KeyError:
        print_c("     [ERROR] No se ha encontrado la configuración de parametros del kernel en config.yaml")
        resultados["detalles"].append(msg)
        white_list = [["P", 1, "Módulo propietario"], ["O", 4096, "Módulo externo"]]
        warning_list = [["W", 512, "Warning"], ["C", 1024, "Staging"], ["K", 32768, "Live patched"]]
        black_list = [["F", 2, "Forzado"], ["R", 8, "Forzado unload"], ["D", 128, "OOPS/BUG"], ["A", 256, "ACPI"], ["E", 8192, "No firmado"]]
        
    ########## Secure Boot ########################################################################################
    
    # Comprobamos que el Secure Boot está activo con OSquery, (si no obtenemos tabla significa que el sistema arrancó en modo Legacy y no puede tenerlo activo)
    query = 'SELECT secure_boot FROM secureboot;'
    respuesta = ejecutar_consulta(query)
    # En caso de que la tabla contenga algún registro
    if len(respuesta) > 0:
        resul_SB = respuesta[0].get('secure_boot')
        if resul_SB == 1:
            resultados["secure_boot"] = True
            detalle = 'El sistema tiene activado Secure Boot con el modo Full-Security'
            resultados["detalles"].append(str(detalle))
            resultados["sb_estado"] = "SEGURO"
            resultados["sb_msg"] = detalle
            if verbose:
                print_c("     [Ok] "+str(detalle))
        
        elif resul_SB == 2:
            alerta = 'El sistema tiene activado Secure Boot con el modo Medium-Security, este modo no otorga una protección aceptable'
            resultados["alertas"].append(alerta)
            resultados["sb_estado"] = "ADVERTENCIA"
            resultados["sb_msg"] = alerta
            if verbose:
                print_c("     [X] "+str(alerta))
        
        else:
            alerta = 'El sistema no tiene activado Secure Boot'
            resultados["alertas"].append(alerta)
            resultados["sb_estado"] = "PELIGROSO"
            resultados["sb_msg"] = alerta
            if verbose:
                print_c("     [X] "+str(alerta))
    
    # La tabla no tiene registros por lo que está en modo Legacy
    else:
        alerta = 'El sistema arranco en modo Legacy, por lo que no tiene Secure Boot'
        resultados["alertas"].append(alerta)
        resultados["sb_estado"] = "PELIGROSO"
        resultados["sb_msg"] = alerta
        if verbose:
            print_c("     [X] "+str(alerta))

    ######## Tainted kernel ##############################################################################
    query = 'SELECT current_value FROM system_controls WHERE name = "kernel.tainted";'
    problemas_tai = 0
    warning_tai = 0
    respuesta = ejecutar_consulta(query)
    if len(respuesta) > 0:
        resul_tai = int(respuesta[0].get('current_value'))
        
        # En caso de que no se haya manchado el kernel
        if resul_tai == 0:
            resultados["kernel_seguro"] = True
            detalle = 'El kernel no ha sido alterado en el proceso de boot'
            resultados["detalles"].append(detalle)
            if verbose:
                print_c("     [Ok] "+detalle)
            return resultados
        
        # Comprobamos las flags haciendo XOR ya que cada una es una potencia de dos
        else:
            for val in (white_list+black_list+warning_list):
                if len(val) < 3:
                    continue
                val_bit = val[1]
                val_desc = val[2]
                if resul_tai & val_bit:
                    # La flag se ha activado en el proceso de boot, sacamos a que proceso pertenece
                    # White_list
                    if val in warning_list:
                        warning_tai += 1
                        alerta = 'Se ha detectado la flag '+str(val[0])+' en el estado del kernel, la cual se considera de peligrosidad media'
                        resultados["alertas"].append(str(alerta))
                        resultados["tainted_flags"].append({"flag": val[0], "desc": val_desc, "riesgo": "MEDIO"})
                        if verbose:
                            print_c("     [!] "+str(alerta))
                    
                    elif val in black_list:
                        alerta = 'Se ha detectado la flag '+str(val[0])+' en el estado del kernel, la cual se considera un fallo crítico'
                        resultados["alertas"].append(str(alerta))
                        resultados["tainted_flags"].append({"flag": val[0], "desc": val_desc, "riesgo": "CRITICO"})
                        problemas_tai += 1
                        if verbose:
                            print_c("     [X] "+str(alerta))
                    
                    else:
                        # Es o "P" o "O", es decir white_list
                        detalle = 'Se ha detectado la flag '+str(val[0])+' en el estado del kernel, la cual se considera segura'
                        resultados["detalles"].append(str(detalle))
                        resultados["tainted_flags"].append({"flag": val[0], "desc": val_desc, "riesgo": "INFO"})
                        if verbose:
                            print_c("     [Ok] "+str(detalle))
        
    # La consulta no de puede realizar
    else:
        alerta = 'No se ha logrado obtener el valor "tainted" del kernel, por lo que no se sabe si el kernel ha sido alterado'
        resultados["alertas"].append(alerta)
        problemas_tai += 1
        if verbose:
            print_c("     [ERROR] "+str(alerta))
        
    # Evaluamos el estado del kernel
    if problemas_tai == 0:
        resultados["kernel_seguro"] = True
        if warning_tai == 0:
            detalle = 'Todas las flags del kernel se consideran seguras'
            resultados["detalles"].append(detalle)
            if verbose:
                print_c("     [Ok] "+str(detalle))
        else:
            alerta = 'Se han detectado '+str(warning_tai)+' flags de peligrosidad media, revise los módulos cargados'
            resultados["alertas"].append(alerta)
            if verbose:
                print_c("     [!] "+str(alerta))

    else:
        alerta = 'Se han detectado '+str(problemas_tai)+' flags consideradas como fallos críticos'
        resultados["alertas"].append(alerta)
        if verbose:
            print_c("     [X] "+str(alerta))
    return resultados






###########################################################################################################################
def auditar_parametros_kernel(verbose):
    print("")
    print_c("[+] Verificando parámetros de seguridad en el arranque del Kernel")
    resultados = {
        "estado": "PELIGROSO",
        "detalles": [],
        "alertas": [],
        "fallos": [],
        "prohibido": [],
        "parametros_tabla": []
    }
    # Cargamos los datos del .yaml
    try:
        white_list = config["boot"]["param_kernel"]["white_list"]
        black_list = config["boot"]["param_kernel"]["black_list"]
    
    except KeyError:
        print_c("     [ERROR] No se ha encontrado la configuración de parametros del kernel en config.yaml")
        white_list = [["apparmor=1", "selinux=1", "enforcing=1"], "audit=1", "slab_nomerage=1", "page_poison=1"]
        black_list = [["init=/bin/bash", "init=single", "single"], "nokaslr", ["mitigations=off", "nopti"]]
    
    # Comprobamos si el archivo existe
    if not os.path.exists('/etc/default/grub'):
        resultados["estado"] = "NO ENCONTRADO"
        resultados["alertas"].append("Archivo no encontrado")
        return resultados
    
    # Obtenemos el archivo grub y lo agrupamos en contenido_grub
    grub = str("")
    grub_def = str("")
    try:
        with open('/etc/default/grub', "r") as f:
            for linea in f:
                linea = linea.strip()
                # Ignoramos líneas vacías o comentadas
                if not linea or linea.startswith("#"):
                    continue
                
                # [NUEVO] Lógica de parseo robusta que elimina comillas y espacios
                if linea.startswith("GRUB_CMDLINE_LINUX="):
                    grub = linea.split('=', 1)[1].strip(' "\'')
                    
                elif linea.startswith("GRUB_CMDLINE_LINUX_DEFAULT="):
                    grub_def = linea.split('=', 1)[1].strip(' "\'')
                
    except Exception as e:
        print_c("     [ERROR] Fallo al leer '/etc/default/grub': "+str(e))
        resultados["alertas"].append("No se ha logrado leer el archivo /etc/default/grub")
        return resultados
    
    ########### Comprobamos si los parametros de la white_list (que consideramos obligatorios) están en grub y grub_default ###########################################
    for parametro in white_list:
        
        if isinstance(parametro, list):
            op = ""
            aparece_grub = False
            aparece_default = False
            for opcion in parametro:
                if opcion in grub:
                    aparece_grub = True
                    op = opcion
                    break
                    
                if opcion in grub_def:
                    aparece_default = True
                    op = opcion
            
            nombre_param = " o ".join(parametro) if not op else op
            
            # Caso de que aparezca en grub
            if aparece_grub:
                detalle = "El parametro "+str(op)+" aparece en los parametros mandados al kernel por GRUB_CMDLINE_LINUX"
                resultados["detalles"].append(str(detalle))
                resultados["parametros_tabla"].append({"param": nombre_param, "estado": "OK", "desc": "Parámetro obligatorio configurado correctamente"})
                if verbose:
                    print_c("     [Ok] "+str(detalle))
                    
            # Caso de que aparezca en grub_default
            elif aparece_default:
                detalle = '''El parametro '''+str(op)+''' aparece en los parametros mandados al kernel por GRUB_CMDLINE_LINUX_DEFAULT y no por 
                GRUB_CMDLINE_LINUX, esto supone un problema de seguridad'''
                resultados["alertas"].append(str(detalle))
                resultados["parametros_tabla"].append({"param": nombre_param, "estado": "ADVERTENCIA", "desc": "Configurado en DEFAULT (no persistente en rescate)"})
                if verbose:
                    print_c("     [!] "+str(detalle))
            
            # Caso de que no aparezca
            else:
                detalle = "No se le pasa al kernel ningún parámetro del grupo "+str(parametro)+", esto supone un fallo de seguridad"
                resultados["fallos"].append(str(detalle))
                resultados["parametros_tabla"].append({"param": " / ".join(parametro), "estado": "FALTA", "desc": "Parámetro de seguridad obligatorio no encontrado"})
                if verbose:
                    print_c("     [X] "+str(detalle))
                    
        else: 
            if parametro in grub:
                detalle = "El parametro "+str(parametro)+" aparece en los parametros mandados al kernel por GRUB_CMDLINE_LINUX"
                resultados["detalles"].append(str(detalle))
                resultados["parametros_tabla"].append({"param": parametro, "estado": "OK", "desc": "Parámetro obligatorio configurado correctamente"})
                if verbose:
                    print_c("     [Ok] "+str(detalle))
                    
            elif parametro in grub_def:
                detalle = '''El parametro '''+str(parametro)+''' aparece en los parametros mandados al kernel por GRUB_CMDLINE_LINUX_DEFAULT y no por 
                GRUB_CMDLINE_LINUX, esto supone un problema de seguridad'''
                resultados["alertas"].append(str(detalle))
                resultados["parametros_tabla"].append({"param": parametro, "estado": "ADVERTENCIA", "desc": "Configurado en DEFAULT (no persistente en rescate)"})
                if verbose:
                    print_c("     [!] "+str(detalle))
            
            else:
                detalle = "El parámetro "+str(parametro)+" no se le pasa al kernel, esto supone un fallo de seguridad"
                resultados["fallos"].append(str(detalle))
                resultados["parametros_tabla"].append({"param": parametro, "estado": "FALTA", "desc": "Parámetro de seguridad obligatorio no encontrado"})
                if verbose:
                    print_c("     [X] "+str(detalle))
            
    ######## Comprobamos la black_list #####################################################################################
    
    grub_tot = str(grub+" "+grub_def)
    for parametro in black_list:
        if isinstance(parametro, list):
            for opcion in parametro:
                if opcion in grub_tot:
                    detalle = "Se ha encontrado el parámetro "+str(opcion)+" el cual está prohibido, esto supone un fallo de seguridad crítico"
                    resultados["prohibido"].append(detalle)
                    resultados["parametros_tabla"].append({"param": opcion, "estado": "PROHIBIDO", "desc": "Parámetro inseguro detectado activo"})
                    if verbose:
                        print_c("     [X] "+str(detalle))
            
        elif parametro in grub_tot:
            detalle = "Se ha encontrado el parámetro "+str(parametro)+" el cual está prohibido, esto supone un fallo de seguridad crítico"
            resultados["prohibido"].append(detalle)
            resultados["parametros_tabla"].append({"param": parametro, "estado": "PROHIBIDO", "desc": "Parámetro inseguro detectado activo"})
            if verbose:
                print_c("     [X] "+str(detalle))
                
    ####### Calificamos resultados ################################################################################################
    
    if len(resultados["fallos"]) > 0 or len(resultados["prohibido"]) > 0:
        resultados["estado"] = "PELIGROSO"
        if verbose:
            print_c("     [X] Los parametros del kernel son peligrosos y suponen un fallo crítico de seguridad")
    
    elif len(resultados["alertas"]) > 0:
        resultados["estado"] = "ADVERTENCIA"
        if verbose:
            print_c("     [!] Los parametros del kernel no lo protegen en caso de arranque de rescate")
        
    else:
        resultados["estado"] = "SEGURO"
        if verbose:
            print_c("     [Ok] Los parametros del kernel se consideran seguros")
            
    return resultados












###########################################################################################################################

def auditar_seguridad_grub(verbose, datos_grub):
    print("")
    print_c("[+] Comprobando la seguridad del gestor de arranque")
    resultados = {
        "estado": "PELIGROSO",
        "protegido": False,
        "permisos_ok": False,
        "detalles": [],
        "alertas": [],
        "archivo_estado": "PELIGROSO",
        "archivo_msg": "",
        "pass_estado": "PELIGROSO",
        "pass_msg": ""
    }
    
      # Cargamos los datos del .yaml
    try:
        contra = config["boot"]["contra_fisica"]
    
    except KeyError:
        contra = False
    
    # Comprobamos si datos_grub_hardening existe y tiene datos significativos (es decir, que se ha analizado correctamente)
    if not datos_grub or datos_grub.get("estado") == "NO ENCONTRADO":
        alerta = "El archivo de configuración de GRUB no fue encontrado por el módulo de hardening"
        resultados["archivo_estado"] = "NO ENCONTRADO"
        resultados["archivo_msg"] = alerta
        resultados["alertas"].append(str(alerta))
        if verbose:
            print_c("     [X] "+str(alerta))
        return resultados
        
    # Caso de que el dueño y los permisos sean correctos
    if datos_grub.get("estado") == "SEGURO":
        resultados["permisos_ok"] = True
        detalle = "Los permisos y el propietario del archivo " + str(datos_grub.get('archivo')) + " son correctos"
        resultados["archivo_estado"] = "SEGURO"
        resultados["archivo_msg"] = detalle
        resultados["detalles"].append(str(detalle))
        if verbose:
            print_c("     [Ok] " + str(detalle))
    
    # Caso de que no sean correctos
    else:
        problemas = datos_grub.get("problemas")
        resultados["archivo_estado"] = "PELIGROSO"
        resultados["archivo_msg"] = " / ".join(problemas)
        for p in problemas:
            resultados["alertas"].append(p)
            if verbose:
                print_c("     [X] " + p)
    
    
    ##### Comprobamos si el arranque requiere contraseña ###################################
    # Comprobamos si existe el archivo compilado
    path = ''
    if os.path.exists('/boot/grub/grub.cfg'):
        path =  '/boot/grub/grub.cfg'
        
    elif os.path.exists('/boot/grub2/grub.cfg'): # Sistemas RedHat
        path = '/boot/grub2/grub.cfg'
    
    else:
        alerta = "No se encontró el archivo compilado de GRUB en " + str(path)
        resultados["pass_estado"] = "PELIGROSO"
        resultados["pass_msg"] = alerta
        resultados["alertas"].append(alerta)
        if verbose: 
            print_c("     [!] " + alerta)
    
    # Si existe lo abrimos y buscamos si usa contraseña
    if path:
        try:
            with open(path, "r") as f:
                for linea in f:
                    linea = linea.strip()
                    # Ignoramos líneas vacías o comentadas
                    if not linea or linea.startswith("#"):
                        continue
                    # Comprobamos si usa contraseña
                    if "password_pbkdf2" in linea:
                        resultados["protegido"] = True
                        detalle = "El gestor de arranque requiere una contraseña física cifrada "
                        resultados["pass_estado"] = "SEGURO"
                        resultados["pass_msg"] = detalle
                        resultados["detalles"].append(detalle)
                        if verbose: 
                            print_c("     [Ok] " + detalle)
                        break
                
                if not resultados["protegido"]:
                    alerta = "El GRUB no se ha configurado para que requiera de contraseña física, puede ser vulnerable a ataques físicos"
                    resultados["pass_estado"] = "ADVERTENCIA"
                    resultados["pass_msg"] = alerta
                    resultados["alertas"].append(alerta)
                    if verbose: 
                        print_c("     [!] " + alerta)
                    
        except Exception as e:
            if verbose: 
                print_c("     [ERROR] Fallo al leer '"+str(path)+"': "+str(e))


    ######### Catalogamos el resultado final #####################################################
    # Caso de que todo esté correcto
    if resultados["protegido"] and resultados["permisos_ok"]:
        resultados["estado"] = "SEGURO"
    
    # Caso de que algo falle   
    elif resultados["permisos_ok"] and not contra:
        resultados["estado"] = "SEGURO"
    
    else:
        resultados["estado"] = "PELIGROSO" 

    return resultados









###########################################################################################################################

def ESCANER_booting(verbose, datos_grub):
    resultados = {
        "integridad": {},
        "parametros": {},
        "grub": {},
    }
    
    mostrar_subtitulos("Booting")
    print("")
    print_c("[+] Iniciando módulo de escaneo de arranque")
    resultados["integridad"] = auditar_integridad_firmware(verbose)
    resultados["parametros"] = auditar_parametros_kernel(verbose)
    resultados["grub"] = auditar_seguridad_grub(verbose,  datos_grub)
    print("")    
    print_c("[-] Finalizando módulo de escaneo de arranque")
    return resultados