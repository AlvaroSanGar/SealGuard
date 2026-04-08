import sqlite3
import os
import json  
from datetime import datetime 

DDBB_path = 'history/BBDD-local.db'

############# COMPROBAR SI LA BBDD EXISTE #################################################################
def comp_BBDD():
    print("[+] Comprobando si existe una BBDD local")
    try:
        if os.path.exists('history/BBDD-local.db'):
            return 1
        else: 
            return 0
        
    except Exception as e:
        print("[ERROR] No se ha podido detectar la BBDD local: "+str(e))
    return None



############# CREAR BBDD Y TABLAS ##########################################################################
def crear_BBDD():
    # Comprobamos si la BBDD existe, en cuyo caso la borramos
    if os.path.exists(DDBB_path):
        try:
            os.remove(DDBB_path)
            print("[i] Base de datos borrada con éxito")

        except PermissionError:
            print("[ERROR] Fallo al tratar de borrar la BBDD anterior debido a la falta de permisos adecuados")
        except Exception as e:
            print("[ERROR] Fallo al tratar de borrar la BBDD anterior: "+str(e))

    # Creamos la BBDD así como las tablas para los archivos normales y los baseline
    con = sqlite3.connect(DDBB_path)
    # Comenzamos a crear las tablas
    try:
        cursor = con.cursor()
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS reportes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha DATE NOT NULL,
                datos_reporte JSON NOT NULL
                
            );
                       
            CREATE TABLE IF NOT EXISTS baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha DATE NOT NULL,
                datos_baseline JSON NOT NULL                         
            );
        ''')

        con.commit()
        print("[+] Base de datos creada con éxito")

    except Exception as e:
        print("Se ha producido un error durante la creación de la BBDD: "+str(e))

    finally:
        if con:
            con.close()




########### MOSTRAR TABLA ##########################################################################
def mostrar_tabla(tabla):
    # Realizamos las  siguientes comprobaciones previas:
    # Comprobamos si la BBDD existe
    if not os.path.exists(DDBB_path):
        print("[ERROR] No se ha encontrado la BBDD en "+str(DDBB_path))
        return
   
    # Comprobamos si la tabla existe
    if not tabla in ["reportes", "baseline"]:
        print("[ERROR] La tabla indicada no existe")
        return 
    
    con = None
    try:
        con = sqlite3.connect(DDBB_path)
        cursor = con.cursor()
        
        # Ejecutamos la consulta. 
        cursor.execute("SELECT id, fecha FROM "+str(tabla)+";")
        registros = cursor.fetchall()
        
        # Mostramos los resultados
        if not registros:
            print("[i] La tabla '"+str(tabla)+"' existe, pero actualmente está vacía.")
        else:
            print("\n--- [ CONTENIDO DE LA TABLA: "+str(tabla.upper())+" ] ---")
            
            # Cabecera de la tabla estilo PostgreSQL
            print("  id  |           fecha            ")
            print("------+----------------------------")
            
            # Rellenamos las filas
            for fila in registros:
                id_registro = str(fila[0])
                fecha = str(fila[1])
                # {:>4} alinea el ID a la derecha ocupando 4 espacios {:<26} alinea la fecha a la izquierda ocupando 26 espacios
                print(f" {id_registro:>4} | {fecha:<26}")
                
            # Pie de tabla típico de psql
            print("("+str(len(registros))+" filas)\n")

    except sqlite3.Error as e:
        print("[ERROR] Fallo al consultar la tabla '"+str(tabla)+"': "+str(e))
        
    finally:
        if con:
            con.close()

    





########### INSERTAR ELEMENTO ######################################################################
def insertar_elemento(archivo, tipo):
    # Realizamos las  siguientes comprobaciones previas:
    # Comprobamos si la BBDD existe
    if not os.path.exists(DDBB_path):
        print("[ERROR] No se ha encontrado la BBDD en "+str(DDBB_path))
        return
   
    # Comprobamos si la tabla existe
    if not tipo in ["datos_reporte", "datos_baseline"]:
        print("[ERROR] El tipo de archivo no cuadra con los estimados")
        return 
    
    # Obtenemos la fecha y hora actuales
    fecha_actual = datetime.now().strftime("%Y/%m/%d %H:%M")
    
    # Comprobamos que el archivo tiene un formato valido (JSON)
    if isinstance(archivo, (dict, list)):
        datos_json = json.dumps(archivo)
    else:
        datos_json = str(archivo)
    
    con = sqlite3.connect(DDBB_path)
    try:
        cursor = con.cursor()
        
        # 4. Usamos execute con parámetros (?, ?) para evitar que las comillas del JSON rompan el SQL
        query = "INSERT INTO "+str(tipo)+" (fecha, "+str(tipo)+") VALUES (?, ?)"
        cursor.execute(query, (fecha_actual, datos_json))

        con.commit()
        print("[+] Datos insertados con éxito en la tabla '"+str(tipo)+"'")

    except Exception as e:
        print("[ERROR] Se ha producido un error durante la inserción en la BBDD: "+str(e))

    finally:
        if con:
            con.close()






########### BORRAR BBDD ############################################################################
def borrar_BBDD():
    # Comprobamos si la BBDD existe
    if not os.path.exists(DDBB_path):
        print("[ERROR] No se ha encontrado la BBDD en "+str(DDBB_path))
        return
    
    conf = input("¿Seguro que deseas borrar la BBDD? Escribe 'borrar' para confirmar: ")
    if str(conf.lower) == "borrar":
        try:
            os.remove(DDBB_path)
            print("[i] Base de datos borrada con éxito")

        except PermissionError:
            print("[ERROR] Fallo al tratar de borrar la BBDD anterior debido a la falta de permisos adecuados")
        except Exception as e:
            print("[ERROR] Fallo al tratar de borrar la BBDD anterior: "+str(e))
            
    else:
        print("[i] No se ha confirmado la operación")





########## EXTRAER ELEMENTO ########################################################################
def obtener_elemento(id_obj):



########## BORRAR ELEMENTO #########################################################################
def borrar_elemento(id_obj):