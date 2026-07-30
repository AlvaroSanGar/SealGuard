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
import nmap

# Importamos tu módulo
import modules.network as mNetwork

# MOCK de la configuración para aislar los tests
CONFIG_MOCK = {
    'network': {
        'white_list': ['ssh'], 
        'black_list': {'telnet': 'Protocolo no seguro en texto plano'}
    }
}

class TestNetworkModule(unittest.TestCase):

    @patch.dict('modules.network.config', CONFIG_MOCK, clear=True)
    @patch('modules.network.nmap.PortScanner')
    def test_escaneo_puertos_exito_y_clasificacion(self, mock_port_scanner):        
        mock_nm = MagicMock()
        mock_port_scanner.return_value = mock_nm
        
        # Simulamos que Nmap encuentra la IP
        mock_nm.all_hosts.return_value = ['1.1.1.1']
        
        # Preparamos el Host falso
        mock_host = MagicMock()
        mock_host.hostname.return_value = 'servidor-prueba'
        mock_host.all_protocols.return_value = ['tcp']
        
        datos_puertos = {
            'tcp': {
                22: {'name': 'ssh', 'product': 'OpenSSH', 'version': '8.2'},      
                23: {'name': 'telnet', 'product': 'Telnetd', 'version': '1.0'},   
                80: {'name': 'http', 'product': 'Apache', 'version': '2.4'}       
            }
        }
        
        mock_host.__getitem__.side_effect = lambda proto: datos_puertos[proto]
        mock_nm.__getitem__.side_effect = lambda ip: mock_host

        resultado = mNetwork.escaneo_puertos(['1.1.1.1'], verbose=False)

        self.assertEqual(len(resultado), 3)

        estados = { r['servicio']: r['estado'] for r in resultado }
        peligros = { r['servicio']: r['peligro'] for r in resultado }
        
        self.assertEqual(estados['ssh'], 'ACEPTADO')
        self.assertEqual(peligros['ssh'], 'BAJO')
        self.assertEqual(estados['telnet'], 'PROHIBIDO')
        self.assertEqual(peligros['telnet'], 'ALTO')
        self.assertEqual(estados['http'], 'DESCONOCIDO')
        self.assertEqual(peligros['http'], 'MEDIO')


    @patch.dict('modules.network.config', {'network': {'white_list': [], 'black_list': {}}}, clear=True)
    @patch('modules.network.nmap.PortScanner')
    def test_escaneo_puertos_nmap_no_instalado(self, mock_port_scanner):
        mock_nm = MagicMock()
        mock_port_scanner.return_value = mock_nm
        mock_nm.scan.side_effect = nmap.PortScannerError("Nmap not found")
        
        resultado = mNetwork.escaneo_puertos(['1.1.1.1'], verbose=False)
        self.assertEqual(resultado, [])


    @patch.dict('modules.network.config', {'network': {'white_list': [], 'black_list': {}}}, clear=True)
    @patch('modules.network.nmap.PortScanner')
    def test_escaneo_puertos_error_generico(self, mock_port_scanner):
        mock_nm = MagicMock()
        mock_port_scanner.return_value = mock_nm
        mock_nm.scan.side_effect = Exception("Fallo de red o timeout")
        
        resultado = mNetwork.escaneo_puertos(['1.1.1.1'], verbose=False)
        self.assertEqual(resultado, [])


    # [MODIFICADO]: Ahora espera tu nuevo diccionario por defecto en lugar de []
    @patch.dict('modules.network.config', {'network': {'white_list': [], 'black_list': {}}}, clear=True)
    @patch('modules.network.nmap.PortScanner')
    def test_escaneo_puertos_sin_puertos_abiertos(self, mock_port_scanner):
        mock_nm = MagicMock()
        mock_port_scanner.return_value = mock_nm
        mock_nm.all_hosts.return_value = []
        
        resultado = mNetwork.escaneo_puertos(['1.1.1.1'], verbose=False)
        
        esperado = [{
            "ip": '1.1.1.1',  
            "puerto": "-",
            "protocolo": "-",
            "servicio": "-",
            "detalle": "-",
            "estado": "ACEPTADO",
            "mensaje": "-",
            "peligro": "BAJO"
        }]
        self.assertEqual(resultado, esperado)


    # [COBERTURA AÑADIDA]: Nmap detecta el host, pero no detecta protocolos/puertos (mensaje_p_encontrados = False)
    @patch.dict('modules.network.config', {'network': {'white_list': [], 'black_list': {}}}, clear=True)
    @patch('modules.network.nmap.PortScanner')
    def test_escaneo_puertos_host_up_sin_protocolos(self, mock_port_scanner):
        mock_nm = MagicMock()
        mock_port_scanner.return_value = mock_nm
        
        mock_nm.all_hosts.return_value = ['1.1.1.1'] # El host existe
        mock_host = MagicMock()
        mock_host.hostname.return_value = 'servidor-vacio'
        mock_host.all_protocols.return_value = [] # Pero no hay protocolos
        mock_nm.__getitem__.side_effect = lambda ip: mock_host

        resultado = mNetwork.escaneo_puertos(['1.1.1.1'], verbose=False)
        
        esperado = [{
            "ip": '1.1.1.1',  
            "puerto": "-",
            "protocolo": "-",
            "servicio": "-",
            "detalle": "-",
            "estado": "ACEPTADO",
            "mensaje": "-",
            "peligro": "BAJO"
        }]
        self.assertEqual(resultado, esperado)


    # [COBERTURA AÑADIDA]: Prueba del wrapper principal ESCANEO_Networking
    @patch('modules.network.escaneo_puertos')
    @patch('modules.system.obtener_interfaces')
    def test_ESCANEO_Networking_exito(self, mock_obtener_interfaces, mock_escaneo_puertos):
        # Simulamos las interfaces devueltas por el sistema
        mock_obtener_interfaces.return_value = {
            'eth0': [{'tipo': 'inet', 'ip': '192.168.1.10'}],
            'lo': [{'tipo': 'inet', 'ip': '127.0.0.1'}]
        }
        mock_escaneo_puertos.return_value = [{'mock': 'resultado'}]
        
        resultado = mNetwork.ESCANEO_Networking(verbose=False)
        
        # Verificamos que llamó a escaneo_puertos con las IPs extraídas correctamente
        mock_escaneo_puertos.assert_called_once_with(['192.168.1.10', '127.0.0.1'], False)
        self.assertEqual(resultado, [{'mock': 'resultado'}])


if __name__ == '__main__':
    unittest.main()