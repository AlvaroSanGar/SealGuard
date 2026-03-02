import os
import modules.system as mSystem
from config.settings import config

def info_usuarios_base(verbose, uid_min):
    print(" [+] Recopilando información base de usuarios...")
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
    if nombres_usuarios:
        shadow_sql = ",".join([f"'{n}'" for n in nombres_usuarios])
        condicion = "WHERE username IN ("+shadow_sql+")"
    query = "SELECT username, last_change, min, max, warning, expire FROM shadow "+condicion+";"
    datos_shadow = mSystem.ejecutar_consulta(query)
    
    if verbose:
        print("\n     [i] Metadatos de contraseñas extraídos de la tabla shadow (Filtrado).")

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
            
    #print(str(usuarios_final)+"\n\n\n") # [DEBUG]
    
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
        usuarios_final[nombre]['politica'] = {
            'expire': registro.get('expire'),
            'last_change': registro.get('last_change'),
            'max': registro.get('max'),
            'min': registro.get('min'),
            'warning': registro.get('warning')
             
        }
    
    # Convertimos el diccionario final en la lista que espera tu programa principal
    return list(usuarios_final.values())





##################################################################################################################################

def politicas_passwords(verbose):
    print("[+] Auditando políticas de contraseñas generales...")
    politicas = config["users"]["politics"]
    politica_general = {}
    try:
        with open("/etc/login.defs", "r") as f:
            # En cada linea quitamos todos los espacios y comprobamos si empiezan por alguna de las palabars clave de politicas
            # En caso afirmativo partimos el string de la linea en trocitos y nos quedamos con el segundo trozo (que representa 
            # el valor que tiene la política)
            for linea in f:
                linea = linea.strip()
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






def comp_2FA(verbose):
    print("[+] Buscando métodos de doble factor (2FA)...")
    modulos_2fa = config["users"]["mfa"]["modulos_pam_2fa"]
    servicios_pam = config["users"]["mfa"]["servicios_pam_a_revisar"]
    params_ssh = config["users"]["mfa"]["parametros_ssh_requeridos"]
    token_file = config["users"]["mfa"]["fichero_token_usuario"]
    
    reporte_2fa = {
        'mfa_global': False,
        'servicios': {servicio: {'protegido': False, 'detalles': []} for servicio in servicios_pam},
        'ssh_config_valido': False,
        'usuarios_token': []
    }
    
    
    #######################################################################################################################
    # Comprobamos si los modulos_2fa están declarados en /etc/pam.d/common-auth, para comprobar si la 2fa está configurado a 
    # nivel "global"
    modulos_common = comprobar("/etc/pam.d/common-auth", modulos_2fa)
    if modulos_common:
        reporte_2fa["mfa_global"] = True
        if verbose:
            print("     [i] Se han hayado los siguientes módulos en /etc/pam.d/common-auth:")
            for m in modulos_common:
                print("         - "+str(m))
    
            
    ################# Comprobamos si los módulos especificados en config.yaml usan la 2fa #################################
    for servicio in servicios_pam:
        arch = str("/etc/pam.d/"+str(servicio))
        comp = modulos_2fa.append('@include common-auth')
        confirmacion = comprobar(arch, comp)
        
        # Tomaremos como que el servicio tiene 2fa si o bien usa la config global y esta tiene integrado un módulo de 2fa
        # o si el propio servicio tiene integrado un módulo de 2fa (tenga o no la config global)
        if (('@include common-auth' in confirmacion) and (reporte_2fa['mfa_global'])) or any(con in servicios_pam for con in confirmacion):
            reporte_2fa['servicios'][servicio]['protegido'] = True
            reporte_2fa['servicios'][servicio]['detalles'] = confirmacion
        
    
    ################## Comprobamos si el servicio sshd tiene 2fa ###########################################################
    comp_sshd = comprobar("/etc/ssh/sshd_config", params_ssh)
    if ('UsePAM' in comp_sshd) and (''):
    
    return {}


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
                        
    except Exception as e:
        print(" [ERROR] No se ha podido acceder al archivo "+str(archivo)+": "+str(e))
    
    return resultado



'''
def escanear_usuarios_completo(verbose):
    print("\n--- [ INICIANDO AUDITORÍA DE USUARIOS ] ---")
    reporte = {
        "lista_usuarios": auditar_usuarios_base(verbose),
        "politicas": auditar_politicas_passwords(verbose),
        "mfa_activado": auditar_autenticacion_pam(verbose)
    }
    return reporte
    '''