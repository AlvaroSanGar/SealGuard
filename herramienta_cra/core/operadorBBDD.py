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
            return True
        else: 
            return False
        
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
        
        # Mostramos los resultados de forma bonita
        if not registros:
            print("[i] La tabla '"+str(tabla)+"' existe, pero actualmente está vacía.")
        else:
            print("\n--- [ CONTENIDO DE LA TABLA: "+str(tabla.upper())+" ] ---")
            print("  id  |           fecha            ")
            print("------+----------------------------")
            
            # Rellenamos las filas
            for fila in registros:
                id_registro = str(fila[0])
                fecha = str(fila[1])
                # {:>4} alinea el ID a la derecha ocupando 4 espacios {:<26} alinea la fecha a la izquierda ocupando 26 espacios
                print(f" {id_registro:>4} | {fecha:<26}")
            # Info extra del num de registros que hay                
            print("("+str(len(registros))+" filas)\n")

    except sqlite3.Error as e:
        print("[ERROR] Fallo al consultar la tabla '"+str(tabla)+"': "+str(e))
        
    finally:
        if con:
            con.close()

    





########### INSERTAR ELEMENTO ######################################################################
def insertar_elemento(archivo, tipo):
    # Comprobamos si la BBDD existe
    if not os.path.exists(DDBB_path):
        print("[ERROR] No se ha encontrado la BBDD en "+str(DDBB_path))
        return
   
    # Comprobamos si la tabla existe
    if not tipo in ["reportes", "baseline"]:
        print("[ERROR] El tipo de archivo no cuadra con los estimados")
        return 
    
    # Obtenemos la fecha y hora 
    fecha_actual = datetime.now().strftime("%Y/%m/%d %H:%M")
    
    # Comprobamos que el archivo tiene un formato valido (JSON)
    if isinstance(archivo, (dict, list)):
        datos_json = json.dumps(archivo)
    else:
        datos_json = str(archivo)
        
    # Seleccionamos el nombre de la columna en función de la tabla que sea
    if tipo == "reportes":
        columna_datos = "datos_reporte"
    else:
        columna_datos = "datos_baseline"
    
    con = sqlite3.connect(DDBB_path)
    try:
        cursor = con.cursor()
        
        # Usamos execute con parámetros (?, ?) para evitar que las comillas del JSON rompan el SQL
        query = "INSERT INTO "+str(tipo)+" (fecha, "+str(columna_datos)+") VALUES (?, ?)"
        cursor.execute(query, (fecha_actual, datos_json))

        con.commit()
        print("[i] Datos insertados con éxito en la tabla '"+str(tipo)+"'")

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
    if str(conf.lower()) == "borrar":
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
def obtener_elemento(id_obj, tabla):
    # Comprobamos si la BBDD o la tabla son válidas (salimos silenciosamente si no)
    if not os.path.exists(DDBB_path):
        print("[ERROR] La BBDD no existe") 
        return None

    if tabla not in ["reportes", "baseline"]:   
        print("[ERROR] La tabla indicada no existe")
    
    # Seleccionamos el nombre de la columna
    if tabla == "reportes":
        columna_datos = "datos_reporte"
    else:
        columna_datos = "datos_baseline"
    
    con = None
    try:
        con = sqlite3.connect(DDBB_path)
        cursor = con.cursor()
        query = "SELECT fecha, "+str(columna_datos)+" FROM "+str(tabla)+" WHERE id = ?;"
        cursor.execute(query, (id_obj,))
        registro = cursor.fetchone()
        
        # Si no encontramos nada terminamos
        if not registro:
            return None

        # Obtenemos los datos del reporte para pasarlos a un diccionario
        datos_raw = registro[1]
        
        try:
            # Parseamos el JSON
            diccionario_datos = json.loads(datos_raw)
        except Exception as e:
            # No hacemos nada 
            print("[ERROR] No se han podido obtener los datos del archivo JSON: "+str(e))

        # Devolvemos una estructura limpia y estandarizada para el generador de PDFs
        return {
            "fecha": str(registro[0]),
            "datos": diccionario_datos
        }

    except sqlite3.Error as e:
        print("[ERROR] "+str(e))
        return None
        
    finally:
        if con:
            con.close()

########## BORRAR ELEMENTO #########################################################################
def borrar_elemento(id_obj, tabla):
    # Realizamos las comprobaciones previas:
    if not os.path.exists(DDBB_path):
        print("[ERROR] No se ha encontrado la BBDD en "+str(DDBB_path))
        return
   
    if not tabla in ["reportes", "baseline"]:
        print("[ERROR] La tabla indicada no existe")
        return 
    
    con = None
    try:
        con = sqlite3.connect(DDBB_path)
        cursor = con.cursor()
        
        # Usamos execute con ? para parametrizar la consulta
        query = "DELETE FROM "+str(tabla)+" WHERE id = ?;"
        cursor.execute(query, (id_obj,))
        
        # Comprobamos si se ha borrado alguna fila (si el ID existía)
        if cursor.rowcount == 0:
            print("[i] No se ha encontrado ningún elemento con el ID "+str(id_obj)+" en la tabla '"+str(tabla)+"'.")
        else:
            con.commit()
            print("[+] Elemento con ID "+str(id_obj)+" borrado con éxito de la tabla '"+str(tabla)+"'.")

    except sqlite3.Error as e:
        print("[ERROR] Fallo al intentar borrar en la tabla '"+str(tabla)+"': "+str(e))
        
    finally:
        if con:
            con.close()