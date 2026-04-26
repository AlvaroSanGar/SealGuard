import os
import time
import pwd  # Librería para obtener detalles de usuarios en Unix
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML, CSS

def obtener_ruta_escritorio_real():
    """
    Detecta el usuario original incluso si se ejecuta con sudo
    y devuelve la ruta a su escritorio.
    """
    # Si estamos en sudo, la variable SUDO_USER nos dice quién lanzó el comando
    user_logueado = os.environ.get('SUDO_USER')
    
    if user_logueado:
        # Obtenemos el home directory del usuario original
        home_usuario = pwd.getpwnam(user_logueado).pw_dir
    else:
        # Si no hay sudo, usamos el home del usuario actual
        home_usuario = os.path.expanduser("~")
        
    ruta_desktop = os.path.join(home_usuario, "Desktop")
    
    # Verificamos si existe la carpeta Desktop (en algunos sistemas puede llamarse 'Escritorio')
    if not os.path.exists(ruta_desktop):
        # Fallback: Si no hay escritorio, devolvemos el home directamente
        # o intentamos 'Escritorio' en español
        variante_es = os.path.join(home_usuario, "Escritorio")
        if os.path.exists(variante_es):
            return variante_es
        return home_usuario
        
    return ruta_desktop

def generar_informe(fecha, datos):
    print("\n[+] Inicializando motor de generación de reportes (Jinja2 + WeasyPrint)...")
    
    id_reporte = "CRA-" + str(int(time.time()))
    
    # [CORREGIDO] Usamos la nueva función para encontrar el escritorio real
    ruta_escritorio = obtener_ruta_escritorio_real()
    
    # Definimos la ruta de salida del PDF
    ruta_pdf = os.path.join(ruta_escritorio, f'Reporte_CRA_{id_reporte}.pdf')
    
    try:
        # 1. Configurar Jinja2
        env = Environment(loader=FileSystemLoader('templates'))
        plantilla = env.get_template('report_template.html')

        # 2. Renderizar el HTML
        print("     [i] Inyectando datos de la auditoría en la plantilla HTML...")
        html_renderizado = plantilla.render(
            id=id_reporte,
            fecha=fecha,
            datos=datos
        )

        # 3. Convertir a PDF con WeasyPrint
        print("     [i] Renderizando PDF y aplicando estilos CSS...")
        
        ruta_css = os.path.join('templates', 'styles.css')
        
        # Generar el PDF
        HTML(string=html_renderizado, base_url='templates').write_pdf(
            ruta_pdf,
            stylesheets=[CSS(ruta_css)]
        )

        print(f"[V] ¡Éxito! Reporte generado en: {ruta_pdf}\n")

    except Exception as e:
        print(f"[ERROR] Fallo crítico al generar el informe: {e}")