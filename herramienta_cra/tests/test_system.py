# SealGuard - Herramienta de Auditoria CRA
# Copyright (C) 2026 Alvaro Sanchez Garijo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
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



    @patch('modules.system.subprocess.run')
    def test_ejecutar_consulta_json_invalido(self, mock_run):
        """Prueba qué pasa si OSquery devuelve texto plano o un error en vez de un JSON"""
        mock_proceso = MagicMock()
        mock_proceso.stdout = "Error fatal del sistema OSquery" # No es formato JSON
        mock_run.return_value = mock_proceso

        resultado = mSystem.ejecutar_consulta("SELECT * FROM test;")
        self.assertEqual(resultado, []) # Debe ser capturado por except Exception y devolver vacío

    @patch('modules.system.subprocess.run')
    def test_obtener_interfaces_linea_corta_o_malformada(self, mock_run):
        """Verifica que el if len(partes) >= 4 protege contra líneas malformadas"""
        # La primera línea tiene solo 3 elementos (rompería el index si no estuviese protegido)
        salida_falsa = '''
1: lo inet
2: eth0 inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0
'''
        mock_proceso = MagicMock()
        mock_proceso.stdout = salida_falsa.strip()
        mock_run.return_value = mock_proceso

        resultado = mSystem.obtener_interfaces()
        
        # 'lo' no debe haberse procesado porque la línea era corta
        self.assertNotIn('lo', resultado)
        # 'eth0' sí debe estar
        self.assertIn('eth0', resultado)

    @patch('modules.system.info_sis')
    def test_ESCANEO_info_Simple(self, mock_info):
        """Prueba la función principal o wrapper del módulo"""
        # Falseamos lo que devuelve info_sis
        mock_info.return_value = {
            "hostname": "MVServidor",
            "sistema": "Linux",
            "dist": "Ubuntu",
            "version": "22.04",
            "kernel": "5.15.0",
            "arquitectura": "x86_64"
        }
        
        # Probamos con verbose=False
        resultado_silencioso = mSystem.ESCANEO_info_Simple(False)
        self.assertEqual(resultado_silencioso['hostname'], "MVServidor")
        
        # Probamos con verbose=True para asegurar que los print_c no rompen la ejecución
        resultado_hablador = mSystem.ESCANEO_info_Simple(True)
        self.assertEqual(resultado_hablador['arquitectura'], "x86_64")
        
if __name__ == '__main__':
    unittest.main()