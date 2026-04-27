import os
import time
import pwd
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML, CSS

def calcular_resumen_dinamico(datos):
    resumen = []
    total_seguros = 0
    total_advertencias = 0
    total_criticos = 0

    # 1. Exposición de Red
    puertos = datos.get("puertos", [])
    # Filtramos para buscar solo los puertos que NO tienen el estado 'ACEPTADO'
    puertos_peligrosos = [p for p in puertos if p.get("estado", "") != "ACEPTADO"]
    
    if len(puertos_peligrosos) == 0:
        resumen.append({"nombre": "1. Exposición de Red", "estado": "SEGURO", "clase": "bg-safe"})
        total_seguros += 1
    elif len(puertos_peligrosos) <= (len(puertos) * 0.2):
        resumen.append({"nombre": "1. Exposición de Red", "estado": "RIESGO POTENCIAL", "clase": "bg-warning"})
        total_advertencias += 1
    else:
        resumen.append({"nombre": "1. Exposición de Red", "estado": "PELIGRO", "clase": "bg-danger"})
        total_criticos += 1

    # 2. Vulnerabilidades
    vulns = datos.get("vulns", [])
    if len(vulns) == 0:
        resumen.append({"nombre": "2. Vulnerabilidades", "estado": "SEGURO", "clase": "bg-safe"})
        total_seguros += 1
    else:
        resumen.append({"nombre": "2. Vulnerabilidades", "estado": "PELIGRO", "clase": "bg-danger"})
        total_criticos += 1

    # 3. Integridad del Sistema
    integridad = datos.get("integridad", [])
    int_riesgos = [i for i in integridad if i.get("estado", "") != "INTACTO"]
    
    if len(integridad) == 0 or len(int_riesgos) == 0:
        resumen.append({"nombre": "3. Integridad del Sistema", "estado": "AUDITADO", "clase": "bg-info"})
        total_seguros += 1
    else:
        resumen.append({"nombre": "3. Integridad del Sistema", "estado": "MODIFICADO", "clase": "bg-danger"})
        total_criticos += 1

    # Función recursiva ultra-precisa para módulos complejos
    def analizar_modulo_complejo(nombre, modulo):
        # Recorremos el diccionario buscando todas las "alertas" y "detalles" que inyectamos en Python
        def contar_listas(obj):
            a, d = 0, 0
            if isinstance(obj, dict):
                if "alertas" in obj: a += len(obj["alertas"])
                if "detalles" in obj: 
                    if isinstance(obj["detalles"], list): d += len(obj["detalles"])
                    else: d += 1
                    
                # Explorar subclaves
                for k, v in obj.items():
                    if k not in ["alertas", "detalles"]:
                        sub_a, sub_d = contar_listas(v)
                        a += sub_a
                        d += sub_d
                        
            elif isinstance(obj, list):
                for item in obj:
                    sub_a, sub_d = contar_listas(item)
                    a += sub_a
                    d += sub_d
            return a, d

        alertas, detalles = contar_listas(modulo)
        total = alertas + detalles
        
        # Clasificamos según el porcentaje
        if total == 0:
            return {"nombre": nombre, "estado": "CUMPLE", "clase": "bg-safe"}
            
        porcentaje = (alertas / total) * 100
        if porcentaje == 0:
            return {"nombre": nombre, "estado": "CUMPLE", "clase": "bg-safe"}
        elif porcentaje <= 20:
            return {"nombre": nombre, "estado": "RIESGO POTENCIAL", "clase": "bg-warning"}
        else:
            return {"nombre": nombre, "estado": "PELIGRO", "clase": "bg-danger"}

    # 4. Identidad y Accesos
    mod_identidad = {"pol": datos.get("politicas_contra", {}), "usu": datos.get("usuarios", []), "mfa": datos.get("2FA", {})}
    res_identidad = analizar_modulo_complejo("4. Identidad y Accesos", mod_identidad)
    
    # 5. Hardening General
    res_hardening = analizar_modulo_complejo("5. Hardening General", datos.get("hardening", {}))
    
    # 6. Arranque Seguro
    res_boot = analizar_modulo_complejo("6. Arranque Seguro", datos.get("boot", datos.get("booting", {})))
    
    # 7. Resiliencia
    res_disp = analizar_modulo_complejo("7. Resiliencia (Disponibilidad)", datos.get("disponibilidad", {}))

    # Volcamos los resultados y sumamos las métricas
    for res in [res_identidad, res_hardening, res_boot, res_disp]:
        resumen.append(res)
        # Sumamos a seguros también el "bg-info" (Auditado)
        if res["clase"] in ["bg-safe", "bg-info"]: total_seguros += 1
        elif res["clase"] == "bg-warning": total_advertencias += 1
        elif res["clase"] == "bg-danger": total_criticos += 1

    datos["estadisticas"] = {
        "resumen_tabla": resumen,
        "seguros": total_seguros,
        "advertencias": total_advertencias,
        "criticos": total_criticos,
        "total": total_seguros + total_advertencias + total_criticos
    }


def obtener_ruta_escritorio_real():
    user_logueado = os.environ.get('SUDO_USER')
    if user_logueado:
        home_usuario = pwd.getpwnam(user_logueado).pw_dir
    else:
        home_usuario = os.path.expanduser("~")
        
    ruta_desktop = os.path.join(home_usuario, "Desktop")
    if not os.path.exists(ruta_desktop):
        variante_es = os.path.join(home_usuario, "Escritorio")
        if os.path.exists(variante_es): return variante_es
        return home_usuario
    return ruta_desktop

def generar_informe(fecha, datos):
    print("\n[+] Inicializando motor de generación de reportes (Jinja2 + WeasyPrint)...")
    
    # Invocamos el cálculo antes de renderizar
    calcular_resumen_dinamico(datos)
    
    id_reporte = "CRA-" + str(int(time.time()))
    ruta_escritorio = obtener_ruta_escritorio_real()
    ruta_pdf = os.path.join(ruta_escritorio, f'Reporte_CRA_{id_reporte}.pdf')
    
    try:
        env = Environment(loader=FileSystemLoader('templates'))
        plantilla = env.get_template('report_template.html')

        print("     [i] Inyectando datos de la auditoría en la plantilla HTML...")
        html_renderizado = plantilla.render(
            id=id_reporte,
            fecha=fecha,
            datos=datos
        )

        print("     [i] Renderizando PDF y aplicando estilos CSS...")
        ruta_css = os.path.join('templates', 'styles.css')
        
        HTML(string=html_renderizado, base_url='templates').write_pdf(
            ruta_pdf,
            stylesheets=[CSS(ruta_css)]
        )

        # [NUEVO] Traspaso de propiedad del archivo al usuario real
        user_logueado = os.environ.get('SUDO_USER')
        if user_logueado:
            # Obtenemos la información del usuario que lanzó el sudo
            user_info = pwd.getpwnam(user_logueado)
            # Cambiamos el dueño (uid) y el grupo (gid) del archivo PDF recién creado
            os.chown(ruta_pdf, user_info.pw_uid, user_info.pw_gid)

        print(f"[V] ¡Éxito! Reporte generado en: {ruta_pdf}\n")

    except Exception as e:
        print(f"[ERROR] Fallo crítico al generar el informe: {e}")