import os
import datetime
import modules.system as mSystem
from config.settings import config

def info_usuarios_base(verbose, uid_min):
    print("[+] Recopilando información base de usuarios")
    ######################## Obtenemos la info necesaria de settings.yaml ###################################
    resultado = []
    critical_groups = config["users"]["critical_groups"]
    if verbose:
        print("     [i] Grupos marcados como críticos: "+str(critical_groups))
    
    
    ################# Obtenemos los usuarios que pertenecen a grupos críticos ################################
    # Formateamos los grupos para meterlos en la consulta
    groups_sql = ",".join([f"'{g}'" for g in critical_groups])
    
    query = '''SELECT u.username, g.groupname FROM users AS u 
    INNER JOIN user_groups AS ug ON u.uid = ug.uid 
    INNER JOIN groups AS g ON ug.gid = g.gid  
    WHERE g.groupname IN ('''+groups_sql+''');'''
    usu_grupos_criticos = mSystem.ejecutar_consulta(query)
   
    if verbose:
        print("     [i] Usuarios detectados en grupos críticos: ")
        for u in usu_grupos_criticos:
            print("         - Usuario: "+str(u.get("username"))+" / Grupo: "+str(u.get("groupname")))
            

    #################### Obtenemos los usuarios relevantes (por uid, grupo o root) ########################
    # Preparamos los nombres de los usuarios en grupos críticos para inyectarlos en la consulta, condicion lo ponemos así por
    # si nombres_criticos está vacío, ya que no crearía criticos_sql y petaría
    nombres_criticos = [u.get("username") for u in usu_grupos_criticos]
    condicion = ""
    if nombres_criticos:
        criticos_sql = ",".join([f"'{n}'" for n in nombres_criticos])
        condicion = '''OR username IN ('''+criticos_sql+''')'''
    
    query = '''SELECT uid, gid, username, description, directory, shell FROM users 
    WHERE uid >= '''+str(int(uid_min))+''' OR uid = 0 '''+condicion+''' ORDER BY uid DESC;'''
    usuarios = mSystem.ejecutar_consulta(query)
    
    if verbose:
        print("\n     [i] Información extraída de los usuarios relevantes: ")
        for u in usuarios:
            print("         - Usuario: "+str(u.get("username"))+" / uid: "+str(u.get("uid"))+" / shell: "+str(u.get("shell")))
    
    ##################### Obtenemos las políticas individuales ############################################
    
    nombres_usuarios = [u.get("username") for u in usuarios]
    shadow_sql = ""
    condicion_s = ""
    if nombres_usuarios:
        shadow_sql = ",".join([f"'{n}'" for n in nombres_usuarios])
        condicion_s = "WHERE username IN ("+shadow_sql+")"
    query = "SELECT username, last_change, min, max, warning, expire FROM shadow "+condicion_s+";"
    datos_shadow = mSystem.ejecutar_consulta(query)
    
    if verbose:
        print("\n     [i] Políticas de contraseñas extraídos del archivo shadow.")

    #################### Unificamos datos ##############################################################
    resultado = juntar_datos(usuarios, usu_grupos_criticos, datos_shadow)
    # Lista de diccionarios donde cada elemento es un usuario con todos sus campos
    return resultado




def juntar_datos(usuarios, usu_grupos_criticos, datos_shadow):
    usuarios_final = {}

    # Cargamos los usuarios y les creamos una entrada grupos_criticos
    for u in usuarios or []:
        nombre = u.get('username')
        usuarios_final[nombre] = u
        usuarios_final[nombre]['grupos_criticos'] = []
        usuarios_final[nombre]['politica'] = {}
                
    for registro in usu_grupos_criticos or []:
        nombre = registro.get('username')
        grupo = registro.get('groupname')
        
        # Nunca debería entrar aquí pero por si acaso
        if nombre not in usuarios_final:
            usuarios_final[nombre] = {
                'username': nombre, 
                'uid': 'SISTEMA/ANÓMALO', 
                'shell': 'DESCONOCIDO',
                'grupos_criticos': []
            }
        
        if grupo not in usuarios_final[nombre]['grupos_criticos']:
            usuarios_final[nombre]['grupos_criticos'].append(grupo)
    
    # Metemos para cada usuario la política particular indicada en el shadow
    for registro in datos_shadow or []:
        nombre = registro.get('username')
        dias_epoch = registro.get('last_change')
        try:
            if dias_epoch and int(dias_epoch) > 0:
                # Sumamos los días a la fecha base 01/01/1970
                fecha = datetime.date(1970, 1, 1) + datetime.timedelta(days=int(dias_epoch))
                fecha_formateada = fecha.strftime("%Y-%m-%d")
            else:
                fecha_formateada = "Nunca / No definido"
        except ValueError:
            fecha_formateada = "Desconocido"
        
        usuarios_final[nombre]['politica'] = {
            'expire': registro.get('expire'),
            'last_change': fecha_formateada,
            'max': registro.get('max'),
            'min': registro.get('min'),
            'warning': registro.get('warning')
             
        }
    
    # Convertimos el diccionario final en la lista que espera tu programa principal
    return list(usuarios_final.values())










##################################################################################################################################

def politicas_passwords(verbose):
    print("[+] Auditando políticas de contraseñas generales")
    politicas = config["users"]["politics"]
    politica_general = {}
    try:
        with open("/etc/login.defs", "r") as f:
            # En cada linea quitamos todos los espacios y comprobamos si empiezan por alguna de las palabars clave de politicas
            # En caso afirmativo partimos el string de la linea en trocitos y nos quedamos con el segundo trozo (que representa 
            # el valor que tiene la política)
            for linea in f:
                linea = linea.strip()
                if not linea.startswith("#"):
                    for clave in politicas:
                        if linea.startswith(clave):
                            partes = linea.split()
                            if len(partes) >= 2:
                                politica_general[clave] = partes[1]
    
    except PermissionError:
        print(" [ERROR] Permisos insuficientes para leer /etc/login.defs")
    
    except FileNotFoundError:
        print(" [ERROR] No se ha encontrado el archivo /etc/login.defs")
    
    except Exception as e:
        print(" [ERROR] Se ha producido un fallo al tratar de leer /etc/login.defs: "+str(e))
        
    return politica_general












###########################################################################################################################


def comp_2FA(verbose, usuarios):
    print("[+] Buscando métodos de doble factor de autentificación")
    modulos_2fa = config["users"]["mfa"]["modulos_pam_2fa"]
    servicios_pam = config["users"]["mfa"]["servicios_pam_a_revisar"]
    params_ssh = ['UsePAM yes', 'ChallengeResponseAuthentication yes', 'KbdInteractiveAuthentication yes']
    mapa_tokens = config["users"]["mfa"]["tokens_requeridos"]
    
    reporte_2fa = {
        'mfa_global': False,
        'servicios': {servicio: {'protegido': False, 'detalles': []} for servicio in servicios_pam},
        'ssh_config_valido': False,
        'usuarios_token': []
    }
    
    #######################################################################################################################
    if os.path.exists("/etc/pam.d/common-auth"):
        modulos_common = comprobar("/etc/pam.d/common-auth", modulos_2fa)
        if modulos_common:
            reporte_2fa["mfa_global"] = True
            if verbose:
                print("     [i] Se han hallado los siguientes módulos en /etc/pam.d/common-auth:")
                for m in modulos_common:
                    print("         - "+str(m))
    else:
        modulos_common = []
    
            
    ################# Comprobamos si los módulos especificados en config.yaml usan la 2fa #################################
    for servicio in servicios_pam:
        arch = str("/etc/pam.d/"+str(servicio))
        
        # [NUEVO] Comprobamos si el servicio PAM existe antes de leerlo
        if os.path.exists(arch):
            comp = modulos_2fa + ['@include common-auth'] #Comprobamos si existen los módulos del yaml o incluye la config del common-auth
            confirmacion = comprobar(arch, comp)
            if (('@include common-auth' in confirmacion) and (reporte_2fa['mfa_global'])) or any(con in modulos_2fa for con in confirmacion):
                reporte_2fa['servicios'][servicio]['protegido'] = True
                reporte_2fa['servicios'][servicio]['detalles'] = confirmacion #Guardamos el módulo que tenga (o el @include common-auth si usa la config general)
        else:
            # Si el servicio no está instalado, se considera seguro (no es un vector de ataque)
            reporte_2fa['servicios'][servicio]['protegido'] = True
            reporte_2fa['servicios'][servicio]['detalles'] = ["Servicio no detectado en el sistema"]
            if verbose:
                print("     [i] El servicio '"+servicio+"' no está instalado en el sistema")
        
    
    ################## Comprobamos si el servicio sshd tiene 2fa ###########################################################
    # [CORREGIDO] Comprobamos que exista el archivo de configuración del servidor SSH, no solo la carpeta
    if os.path.exists("/etc/ssh/sshd_config"):
        comp_sshd = comprobar("/etc/ssh/sshd_config", params_ssh)
        if (params_ssh[0] in comp_sshd) and ((params_ssh[1] in comp_sshd) or (params_ssh[2] in comp_sshd)):
            reporte_2fa["ssh_config_valido"] = True
            if verbose:
                print("     [i] Configuración de SSH válida para aplicar MFA")
        elif verbose:
            print("     [X] Configuración de SSH no válida para aplicar MFA")
    
    else:
        reporte_2fa["ssh_config_valido"] = True
        if verbose:
            print("     [i] El servicio SSH no está instalado en el sistema, por lo que no se le puede aplicar MFA")
    
    

    ################# Comprobamos la existencia de los tokens de autentificación en los dir de cada usu #####################
    if verbose:
        print("     [i] Comprobando la existencia de tokens de autentificación en los directorios de los usuarios")
    
    # Cargamos los módulos activos para después comprobar si los tokens pertenecen a uno de los servicios activos 
    # Lo hacemos en un set para evitar duplicados al recoger los servicios activos de 'detalles'
    modulos_activos = set(modulos_common if modulos_common else [])
    
    # Obtenemos el módulo que protege cada servicio concreto
    for s in reporte_2fa['servicios'].values():
        modulos_activos.update(s['detalles'])
       
    # A continuación vamos a comprobar para la lista de usuarios cuales tienen un token de 2fa activo en su directorio base
    for usu in usuarios or []:
        directorio_home = usu.get("directory")
        nombre = usu.get("username")
        
        if directorio_home and (directorio_home != '/nonexistent'): # Descartamos los usus que no tienen directorio base
            for token_file, modulo_asociado in mapa_tokens.items():
                ruta_token = os.path.join(directorio_home, token_file) 
                
                if os.path.exists(ruta_token): # Comprobamos si la ruta (con el token) existe
                    token_efectivo = modulo_asociado in modulos_activos # Nos quedamos los tokens efectivos
                    
                    reporte_2fa["usuarios_token"].append({
                        "usuario": nombre,
                        "token": token_file,
                        "efectivo": token_efectivo
                    })
                    
                    if verbose:
                        if token_efectivo:
                            print("         - [V] Token '"+token_file+"' configurado y ACTIVO para: "+nombre)
                        else:
                            print("         - [!] Token '"+token_file+"' hallado en "+nombre+", pero su módulo '"+modulo_asociado+"' no está en PAM.")
                            
    return reporte_2fa


# Buscamos una serie de strings clave en el archivo indicado y devolvemos los que hemos encontrado (similar a politicas_password)
def comprobar(archivo, buscar):
    resultado = []
    try:
        with open(archivo, "r") as f:
            for linea in f:
                linea = linea.strip()
                
                # Por si acaso, así nos evitamos problemas si lo han comentado y devolvemos un falso positivo
                if linea and not linea.startswith('#'): 
                    for clave in buscar:
                        if clave in linea:
                            resultado.append(clave)
                        
    except FileNotFoundError as e:
        print(" [ERROR] El archivo "+str(archivo)+" no existe")
    except Exception as e:
        print(" [ERROR] No se ha podido acceder al archivo "+str(archivo)+": "+str(e))
    
    return list(set(resultado)) # Nos evitamos duplicados 




def ESCANER_usuarios(verbose):
    resultados = {
        "politicas": {},
        "usuarios": [],
        "2FA": {}
    }
    
    print("\n--- [ FASE 4: AUDITORÍA DE USUARIOS ] ---")
    print("[+] Iniciando módulo de escaneo de usuarios")
    resultados["politicas"] = politicas_passwords(verbose)
    
    #Comprobamos si hay definido un min uid para los usuarios personas en las políticas, de lo contrario ponemos 1000
    if resultados["politicas"].get("UID_MIN"):
        min_uid = resultados["politicas"].get("UID_MIN")
    else:
        min_uid = 1000
    
    resultados["usuarios"] = info_usuarios_base(verbose, min_uid)
    
    # Comprobamos si existe 2fa
    resultados["2FA"] = comp_2FA(verbose, resultados["usuarios"])
    print("[-] Finalizando módulo de escaneo de usuarios")
    return resultados

    