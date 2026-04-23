import os
import time
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML, CSS

def generar_informe(fecha, datos):
    print("\n[+] Inicializando motor de generación de reportes (Jinja2 + WeasyPrint)...")
    
    # Generamos un ID de reporte único basado en el timestamp actual
    id_reporte = "CRA-" + str(int(time.time()))
    
    # IMPORTANTE: Nos aseguramos de que la carpeta 'output' exista antes de guardar nada
    os.makedirs('output', exist_ok=True)
    
    # Definimos las rutas de salida en la carpeta output
    ruta_pdf = os.path.join('output', f'Reporte_{id_reporte}.pdf')
    ruta_html_debug = os.path.join('output', 'debug_report.html')
    
    try:
        # 1. Configurar Jinja2 para cargar el HTML desde la carpeta 'templates'
        env = Environment(loader=FileSystemLoader('templates'))
        plantilla = env.get_template('report_template.html')

        # 2. Renderizar el HTML inyectando tu diccionario de Python
        print("     [i] Inyectando datos de la auditoría en la plantilla HTML...")
        html_renderizado = plantilla.render(
            id=id_reporte,
            fecha=fecha,
            datos=datos
        )

        # 3. Guardar una copia en HTML para depurar 
        with open(ruta_html_debug, 'w', encoding='utf-8') as f:
            f.write(html_renderizado)
        print(f"     [i] HTML interactivo de prueba guardado en: {ruta_html_debug}")
        print("         (Nota: Al abrir el HTML en el navegador puede verse sin diseño porque el CSS está en otra carpeta, pero el PDF saldrá bien)")

        # 4. Convertir a PDF con WeasyPrint y aplicar el CSS
        print("     [i] Renderizando PDF y aplicando estilos CSS...")
        
        # [MODIFICADO] Le indicamos a Python que el CSS está dentro de la carpeta templates
        ruta_css = os.path.join('templates', 'styles.css')
        
        # base_url='templates' hace que el logo.jpg también se busque dentro de esa carpeta
        HTML(string=html_renderizado, base_url='templates').write_pdf(
            ruta_pdf,
            stylesheets=[CSS(ruta_css)]
        )

        print(f"[V] ¡Éxito! Reporte final generado y guardado en: {ruta_pdf}\n")

    except Exception as e:
        print(f"[ERROR] Fallo crítico al generar el informe: {e}")