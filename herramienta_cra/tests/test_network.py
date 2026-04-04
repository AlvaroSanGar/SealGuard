import unittest
from unittest.mock import patch, MagicMock
import nmap

# Importamos tu módulo
import modules.network as mNetwork

class TestNetworkModule(unittest.TestCase):

    # Parcheamos la configuración para que el test no dependa del settings.yaml real
    @patch('modules.network.config', {
        'network': {
            'white_list': ['ssh'], 
            'black_list': {'telnet': 'Protocolo no seguro en texto plano'}
        }
    })
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
        
        # Diccionario con los datos exactos que devolvería python-nmap
        datos_puertos = {
            'tcp': {
                22: {'name': 'ssh', 'product': 'OpenSSH', 'version': '8.2'},      # Whitelist
                23: {'name': 'telnet', 'product': 'Telnetd', 'version': '1.0'},   # Blacklist
                80: {'name': 'http', 'product': 'Apache', 'version': '2.4'}       # Desconocido
            }
        }
        
        # Conectamos las respuestas del Mock
        mock_host.__getitem__.side_effect = lambda proto: datos_puertos[proto]
        mock_nm.__getitem__.side_effect = lambda ip: mock_host

        # Ejecutamos tu función
        resultado = mNetwork.escaneo_puertos(['1.1.1.1'], verbose=False)

        # Comprobamos que ha procesado los 3 puertos
        self.assertEqual(len(resultado), 3)

        # Extraemos los estados para comprobar la lógica de tus listas
        estados = { r['servicio']: r['estado'] for r in resultado }
        peligros = { r['servicio']: r['peligro'] for r in resultado }
        
        self.assertEqual(estados['ssh'], 'ACEPTADO')
        self.assertEqual(peligros['ssh'], 'BAJO')
        
        self.assertEqual(estados['telnet'], 'PROHIBIDO')
        self.assertEqual(peligros['telnet'], 'ALTO')
        
        self.assertEqual(estados['http'], 'DESCONOCIDO')
        self.assertEqual(peligros['http'], 'MEDIO')


    @patch('modules.network.config', {'network': {'white_list': [], 'black_list': []}})
    @patch('modules.network.nmap.PortScanner')
    def test_escaneo_puertos_nmap_no_instalado(self, mock_port_scanner):
        
        mock_nm = MagicMock()
        mock_port_scanner.return_value = mock_nm
        
        # Forzamos que el método scan salte con el error específico de la librería nmap
        mock_nm.scan.side_effect = nmap.PortScannerError("Nmap not found")
        
        resultado = mNetwork.escaneo_puertos(['1.1.1.1'], verbose=False)
        
        # Tu bloque 'except nmap.PortScannerError:' debe devolver una lista vacía
        self.assertEqual(resultado, [])


    @patch('modules.network.config', {'network': {'white_list': [], 'black_list': []}})
    @patch('modules.network.nmap.PortScanner')
    def test_escaneo_puertos_error_generico(self, mock_port_scanner):
        
        mock_nm = MagicMock()
        mock_port_scanner.return_value = mock_nm
        
        # Forzamos una excepción genérica
        mock_nm.scan.side_effect = Exception("Fallo de red o timeout")
        
        resultado = mNetwork.escaneo_puertos(['1.1.1.1'], verbose=False)
        
        # Tu bloque 'except Exception as e:' debe capturarlo y continuar, devolviendo lista vacía
        self.assertEqual(resultado, [])


    @patch('modules.network.config', {'network': {'white_list': [], 'black_list': []}})
    @patch('modules.network.nmap.PortScanner')
    def test_escaneo_puertos_sin_puertos_abiertos(self, mock_port_scanner):
        mock_nm = MagicMock()
        mock_port_scanner.return_value = mock_nm
        
        # Simulamos que la lista de hosts detectados está vacía
        mock_nm.all_hosts.return_value = []
        
        resultado = mNetwork.escaneo_puertos(['1.1.1.1'], verbose=False)
        
        # Tu comprobación 'if len(nm.all_hosts()) == 0:' debe procesarlo y devolver vacío
        self.assertEqual(resultado, [])

if __name__ == '__main__':
    unittest.main()