import os
from modules.system import ejecutar_consulta
from config.settings import config

###########################################################################################################################

def auditar_integridad_firmware(verbose):
    print("[+] Auditando integridad del firmware y del kernel")
    resultados = {
        "secure_boot": False,
        "kernel_seguro": False,
        "detalles": [],
        "alertas": []
    }
    
    # Cargamos los datos del .yaml
    try:
        white_list = config["boot"]["integridad_kernel"]["white_list"]
        warning_list = config["boot"]["integridad_kernel"]["warning_list"]
        black_list = config["boot"]["integridad_kernel"]["black_list"]
        
    except KeyError:
        print("     [ERROR] No se ha encontrado la configuración de parametros del kernel en config.yaml")
        white_list = [["P", 1], ["O", 4096]]
        warning_list = [["W", 512], ["C", 1024], ["K", 32768]]
        black_list = [["F", 2], ["R", 8], ["D", 128], ["A", 256], ["E", 8192]]
        
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
            if verbose:
                print("     [V] "+str(detalle))
        
        elif resul_SB == 2:
            alerta = 'El sistema tiene activado Secure Boot con el modo Medium-Security, este modo no otorga una protección aceptable'
            resultados["alertas"].append(alerta)
            if verbose:
                print("     [X] "+str(alerta))
        
        else:
            alerta = 'El sistema no tiene activado Secure Boot'
            resultados["alertas"].append(alerta)
            if verbose:
                print("     [X] "+str(alerta))
    
    # La tabla no tiene registros por lo que está en modo Legacy
    else:
        alerta = 'El sistema arranco en modo Legacy, por lo que no tiene Secure Boot'
        resultados["alertas"].append(alerta)
        if verbose:
            print("     [X] "+str(alerta))

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
                print("     [V] "+detalle)
            return resultados
        
        # Comprobamos las flags haciendo XOR ya que cada una es una potencia de dos
        else:
            for val in (white_list+black_list+warning_list):
                val_bit = val[1]
                if resul_tai & val_bit:
                    # La flag se ha activado en el proceso de boot, sacamos a que proceso pertenece
                    # White_list
                    if val in warning_list:
                        warning_tai += 1
                        alerta = 'Se ha detectado la flag '+str(val[0])+' en el estado del kernel, la cual se considera de peligrosidad media'
                        resultados["alertas"].append(str(alerta))
                        if verbose:
                            print("     [!] "+str(alerta))
                    
                    elif val in black_list:
                        alerta = 'Se ha detectado la flag '+str(val[0])+' en el estado del kernel, la cual se considera un fallo crítico'
                        resultados["alertas"].append(str(alerta))
                        problemas_tai += 1
                        if verbose:
                            print("     [X] "+str(alerta))
                    
                    else:
                        # Es o "P" o "O", es decir white_list
                        detalle = 'Se ha detectado la flag '+str(val[0])+' en el estado del kernel, la cual se considera segura'
                        resultados["detalles"].append(str(detalle))
                        if verbose:
                            print("     [V] "+str(detalle))
        
    # La consulta no de puede realizar
    else:
        alerta = 'No se ha logrado obtener el valor "tainted" del kernel, por lo que no se sabe si el kernel ha sido alterado'
        resultados["alertas"].append(alerta)
        problemas_tai += 1
        if verbose:
            print("     [ERROR] "+str(alerta))
        
    # Evaluamos el estado del kernel
    if problemas_tai == 0:
        resultados["kernel_seguro"] = True
        if warning_tai == 0:
            detalle = 'Todas las flags del kernel se consideran seguras'
            resultados["detalles"].append(detalle)
            if verbose:
                print("     [V] "+str(detalle))
        else:
            alerta = 'Se han detectado '+str(warning_tai)+' flags de peligrosidad media, revise los módulos cargados'
            resultados["alertas"].append(alerta)
            if verbose:
                print("     [!] "+str(alerta))

    else:
        alerta = 'Se han detectado '+str(problemas_tai)+' flags consideradas como fallos críticos'
        resultados["alertas"].append(alerta)
        if verbose:
            print("     [X] "+str(alerta))
    return resultados






###########################################################################################################################

def auditar_parametros_kernel(verbose):
    print("[+] Verificando parámetros de seguridad en el arranque del Kernel")
    resultados = {
        "estado": "PELIGROSO",
        "detalles": [],
        "alertas": [],
        "fallos": [],
        "prohibido": []
    }
    # Cargamos los datos del .yaml
    try:
        white_list = config["boot"]["param_kernel"]["white_list"]
        black_list = config["boot"]["param_kernel"]["black_list"]
    
    except KeyError:
        print("     [ERROR] No se ha encontrado la configuración de parametros del kernel en config.yaml")
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
                
                # Nos quedamos solo los parametros de GRUB_CMDLINE_LINUX Y GRUB_CMDLINE_LINUX_DEFAULT
                if linea.startswith("GRUB_CMDLINE_LINUX="):
                    grub = str(linea[20:-1])
                    
                elif linea.startswith("GRUB_CMDLINE_LINUX_DEFAULT="):
                    grub_def = str(linea[28:-1])  
                
    except Exception as e:
        print("     [ERROR] Fallo al leer '/etc/default/grub': "+str(e))
        resultados["alertas"].append("No se ha logrado leer el archivo /etc/default/grub")
        return resultados
    
    ########### Comprobamos si los parametros de la white_list (que consideramos obligatorios) están en grub y grub_default ###########################################
    for parametro in white_list:
        
        # Comprobamos si el parámetro es único (string) o de opción (list), si es único con que se encuentre uno entre los parámetros
        # lo consideramos seguro (ya que son opciones equivalentes), en caso de que sea único, es obligatorio que se encuentre entre los 
        # parámetros.
        if isinstance(parametro, list):
            op = ""
            aparece_grub = False
            aparece_default = False
            # Buscamos si hay alguno de los parametros en grub o en default
            for opcion in parametro:
                if opcion in grub:
                    aparece_grub = True
                    op = opcion
                    break # Al final es el más importante
                    
                if opcion in grub_def:
                    aparece_default = True
                    op = opcion
            
            # Caso de que aparezca en grub
            if aparece_grub:
                detalle = "El parametro "+str(op)+" aparece en los parametros mandados al kernel por GRUB_CMDLINE_LINUX"
                resultados["detalles"].append(str(detalle))
                if verbose:
                    print("     [V] "+str(detalle))
                    
            # Caso de que aparezca en grub_default
            elif aparece_default:
                detalle = '''El parametro '''+str(op)+''' aparece en los parametros mandados al kernel por GRUB_CMDLINE_LINUX_DEFAULT y no por 
                GRUB_CMDLINE_LINUX, esto supone un problema de seguridad'''
                resultados["alertas"].append(str(detalle))
                if verbose:
                    print("     [!] "+str(detalle))
            
            # Caso de que no aparezca
            else:
                detalle = "No se le pasa al kernel ningún parámetro del grupo "+str(parametro)+", esto supone un fallo de seguridad"
                resultados["fallos"].append(str(detalle))
                if verbose:
                    print("     [X] "+str(detalle))
                    
        # En caso de que sea un parametro único (string)
        else: 
            if parametro in grub:
                detalle = "El parametro "+str(parametro)+" aparece en los parametros mandados al kernel por GRUB_CMDLINE_LINUX"
                resultados["detalles"].append(str(detalle))
                if verbose:
                    print("     [V] "+str(detalle))
                    
            # Caso de que aparezca en grub_default
            elif parametro in grub_def:
                detalle = '''El parametro '''+str(parametro)+''' aparece en los parametros mandados al kernel por GRUB_CMDLINE_LINUX_DEFAULT y no por 
                GRUB_CMDLINE_LINUX, esto supone un problema de seguridad'''
                resultados["alertas"].append(str(detalle))
                if verbose:
                    print("     [!] "+str(detalle))
            
            # Caso de que no aparezca
            else:
                detalle = "El parámetro "+str(parametro)+" no se le pasa al kernel, esto supone un fallo de seguridad"
                resultados["fallos"].append(str(detalle))
                if verbose:
                    print("     [X] "+str(detalle))
            
    ######## Comprobamos la black_list #####################################################################################
    
    # Vamos a juntar los dos parametros de grubs ya que si hay un parametro prohibido en algun grub, lo marcaremos como peligroso igualmente
    grub_tot = str(grub+" "+grub_def)
    for parametro in black_list:
        # Hacemos lo mismo que antes
        if isinstance(parametro, list):
            for opcion in parametro:
                if opcion in grub_tot:
                    detalle = "Se ha encontrado el parámetro "+str(opcion)+" el cual está prohibido, esto supone un fallo de seguridad crítico"
                    resultados["prohibido"].append(detalle)
                    if verbose:
                        print("     [X] "+str(detalle))
            
        elif parametro in grub_tot:
            detalle = "Se ha encontrado el parámetro "+str(parametro)+" el cual está prohibido, esto supone un fallo de seguridad crítico"
            resultados["prohibido"].append(detalle)
            if verbose:
                print("     [X] "+str(detalle))
                
    ####### Calificamos resultados ################################################################################################
    
    if len(resultados["fallos"]) > 0 or len(resultados["prohibido"]) > 0:
        resultados["estado"] = "PELIGROSO"
        if verbose:
            print("     [X] Los parametros del kernel son peligrosos y suponen un fallo crítico de seguridad")
    
    elif len(resultados["alertas"]) > 0:
        resultados["estado"] = "ADVERTENCIA"
        if verbose:
            print("     [!] Los parametros del kernel no lo protegen en caso de arranque de rescate")
        
    else:
        resultados["estado"] = "SEGURO"
        if verbose:
            print("     [V] Los parametros del kernel se consideran seguros")
            
    return resultados












###########################################################################################################################

def auditar_seguridad_grub(verbose, datos_grub):
    print("[+] Comprobando la seguridad del gestor de arranque")
    resultados = {
        "estado": "PELIGROSO",
        "protegido": False,
        "permisos_ok": False,
        "detalles": [],
        "alertas": []
    }
    
      # Cargamos los datos del .yaml
    try:
        contra = config["boot"]["contra_fisica"]
    
    except KeyError:
        contra = False
    
    # Comprobamos si datos_grub_hardening existe y tiene datos significativos (es decir, que se ha analizado correctamente)
    if not datos_grub or datos_grub.get("estado") == "NO ENCONTRADO":
        alerta = "El archivo de configuración de GRUB no fue encontrado por el módulo de hardening"
        resultados["alertas"].append(str(alerta))
        if verbose:
            print("     [X] "+str(alerta))
        return resultados
        
    # Caso de que el dueño y los permisos sean correctos
    if datos_grub.get("estado") == "SEGURO":
        resultados["permisos_ok"] = True
        detalle = "Los permisos y el propietario del archivo " + str(datos_grub.get('archivo')) + " son correctos"
        resultados["detalles"].append(str(detalle))
        if verbose:
            print("     [V] " + str(detalle))
    
    # Caso de que no sean correctos
    else:
        problemas = datos_grub.get("problemas")
        for p in problemas:
            resultados["alertas"].append(p)
            if verbose:
                print("     [X] " + p)
    
    
    ##### Comprobamos si el arranque requiere contraseña ###################################
    # Comprobamos si existe el archivo compilado
    path = ''
    if os.path.exists('/boot/grub/grub.cfg'):
        path =  '/boot/grub/grub.cfg'
        
    elif os.path.exists('/boot/grub2/grub.cfg'): # Sistemas RedHat
        path = '/boot/grub2/grub.cfg'
    
    else:
        alerta = "No se encontró el archivo compilado de GRUB en " + str(path)
        resultados["alertas"].append(alerta)
        if verbose: 
            print("     [!] " + alerta)
    
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
                        resultados["detalles"].append(detalle)
                        if verbose: 
                            print("     [V] " + detalle)
                        break
                
                if not resultados["protegido"]:
                    alerta = "El GRUB no se ha configurado para que requiera de contraseña física, puede ser vulnerable a ataques físicos"
                    resultados["alertas"].append(alerta)
                    if verbose: 
                        print("     [!] " + alerta)
                    
        except Exception as e:
            if verbose: 
                print("     [ERROR] Fallo al leer '"+str(path)+"': "+str(e))


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
    
    print("\n--- [ FASE 6: AUDITORÍA DE ARRANQUE ] ---")
    print("[+] Iniciando módulo de escaneo de arranque...")
    resultados["integridad"] = auditar_integridad_firmware(verbose)
    resultados["parametros"] = auditar_parametros_kernel(verbose)
    resultados["grub"] = auditar_seguridad_grub(verbose,  datos_grub)    
    print("[-] Finalizando módulo de escaneo de arranque")
    return resultados