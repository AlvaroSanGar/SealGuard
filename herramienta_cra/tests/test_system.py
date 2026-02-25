import unittest
from unittest.mock import patch, MagicMock
import json

import modules.system as mSystem

class TestSystemModule(unittest.TestCase):
    # En todos vamos a capturar subrpocess.run pq son ejecuciones de comandos por terminal (también nos permite usar stdout)
    ########################## Pruebas OSquery ###################################################################

    @patch('modules.system.subprocess.run') 
    # IMPORTANTE empezar con test_
    def test_ejecutar_consulta_exito(self, mock_run):
        # Simulamos la respuesta de OSquery
        mock_proceso = MagicMock()
        mock_proceso.stdout = '[{"name": "prueba", "version": "1.0"}]'
        mock_run.return_value = mock_proceso

        resultado = mSystem.ejecutar_consulta("SELECT * FROM test;")
        self.assertEqual(len(resultado), 1) # Comprobamos que ha pillado solo la entrada que le hemos falseado
        self.assertEqual(resultado[0]['name'], 'prueba') # Comprobamos que es exactamente la entrada prueba
        self.assertEqual(resultado[0]['version'], '1.0')

    @patch('modules.system.subprocess.run')
    # Simulamos que osquery no existe
    def test_consulta_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        resultado = mSystem.ejecutar_consulta("SELECT * FROM test;")
        self.assertEqual(resultado, [])

    @patch('modules.system.subprocess.run')
    # Simulamos un error
    def test_consulta_error(self, mock_run):
        mock_run.side_effect = Exception("Error")
        resultado = mSystem.ejecutar_consulta("SELECT * FROM test;")
        self.assertEqual(resultado, [])

        ########################## Pruebas Interfaces ################################################################

    @patch('modules.system.subprocess.run')
    # Salida falsa simulando el comando ip de Linux
    def test_obtener_interfaces_exito(self, mock_run):
        salida_falsa = '''
1: lo inet 127.0.0.1/8 scope host lo\n
2: eth0 inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0
'''
        mock_proceso = MagicMock()
        mock_proceso.stdout = salida_falsa.strip()
        mock_run.return_value = mock_proceso

        resultado = mSystem.obtener_interfaces()
        
        self.assertIn('lo', resultado)
        self.assertIn('eth0', resultado)
        self.assertEqual(resultado['eth0'][0]['ip'], '192.168.1.50')
        self.assertEqual(resultado['eth0'][0]['tipo'], 'inet')

    @patch('modules.system.subprocess.run')
    def test_obtener_interfaces_exception(self, mock_run):
        mock_run.side_effect = Exception("Error")
        resultado = mSystem.obtener_interfaces()
        self.assertEqual(resultado, {})

    # Podemos falsear directamente el resultado de ejecutar_consulta
    ########################## Pruebas info sistema ############################################################

    @patch('modules.system.ejecutar_consulta')
    def test_info_sis_con_osquery(self, mock_ejecutar):
        # Simulamos que osquery devuelve datos buenos
        mock_ejecutar.return_value = [{"name": "Ubuntu", "version": "22.04"}]
        resultado = mSystem.info_sis()
        self.assertEqual(resultado['dist'], "Ubuntu")
        self.assertEqual(resultado['version'], "22.04")

    @patch('modules.system.ejecutar_consulta')
    def test_info_sis_sin_osquery(self, mock_ejecutar):
        # Simulamos que osquery falla o devuelve vacío
        mock_ejecutar.return_value = []
        resultado = mSystem.info_sis()
        self.assertEqual(resultado['dist'], "Linux")
        self.assertEqual(resultado['version'], "versión desconocida")

    ########################## Pruebas paquetes ###################################################################

    @patch('modules.system.ejecutar_consulta')
    def test_paquetes_instalados(self, mock_ejecutar):
        mock_ejecutar.return_value = [{"name": "nano", "version": "6.2"}]
        resultado = mSystem.paquetes_instalados()
        self.assertEqual(resultado[0]['ecosystem'], 'Debian')
        self.assertEqual(resultado[0]['type'], 'System (APT)')

    @patch('modules.system.ejecutar_consulta')
    def test_paquetes_python(self, mock_ejecutar):
        mock_ejecutar.return_value = [{"name": "requests", "version": "2.25.1"}]
        resultado = mSystem.paquetes_python()
        self.assertEqual(resultado[0]['ecosystem'], 'PyPI')
        self.assertEqual(resultado[0]['type'], 'Python (PIP)')

if __name__ == '__main__':
    unittest.main()