import unittest
from unittest.mock import patch, MagicMock
import requests

# Importamos tu módulo
import modules.vulns as mVuln

class TestVulnsModule(unittest.TestCase):

    def setUp(self):
        # Preparamos una lista de paquetes falsa que usaremos en todos los tests
        self.paquetes_mock = [
            {
                'name': 'curl', 
                'version': '7.81.0', 
                'ecosystem': 'Debian', 
                'type': 'System (APT)'
            }
        ]

    @patch('modules.vulns.requests.post')
    def test_escanear_vulnerabilidades_con_vulns(self, mock_post):
        """Camino Feliz: La API responde 200 OK y encuentra 2 vulnerabilidades."""
        
        # 1. Creamos la respuesta falsa (Mock) de la API
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        # 2. Recreamos el JSON exacto que devuelve OSV.dev cuando hay peligro
        mock_response.json.return_value = {
            "results": [
                {
                    "vulns": [
                        {"id": "CVE-2023-1234"},
                        {"id": "CVE-2023-5678"}
                    ]
                }
            ]
        }
        mock_post.return_value = mock_response

        # 3. Ejecutamos tu código
        resultado = mVuln.escanear_vulnerabilidades(self.paquetes_mock)

        # 4. Comprobaciones
        self.assertEqual(len(resultado), 1)  # 1 paquete vulnerable detectado
        self.assertEqual(resultado[0]['paquete'], 'curl')
        self.assertEqual(resultado[0]['cantidad'], 2)
        self.assertIn("CVE-2023-1234", resultado[0]['cves'])
        self.assertIn("CVE-2023-5678", resultado[0]['cves'])


    @patch('modules.vulns.requests.post')
    def test_escanear_vulnerabilidades_sin_vulns(self, mock_post):
        """Camino Feliz: La API responde 200 OK pero el paquete es seguro."""
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        # El JSON de OSV.dev cuando el paquete está limpio viene sin la clave 'vulns'
        mock_response.json.return_value = {
            "results": [
                {} 
            ]
        }
        mock_post.return_value = mock_response

        resultado = mVuln.escanear_vulnerabilidades(self.paquetes_mock)
        
        # Comprobamos que devuelve una lista vacía (ningún hallazgo)
        self.assertEqual(resultado, [])


    @patch('modules.vulns.requests.post')
    def test_escanear_vulnerabilidades_error_http(self, mock_post):
        """Camino Triste: La API está saturada y devuelve un Error 500."""
        
        mock_response = MagicMock()
        mock_response.status_code = 500 # Internal Server Error
        mock_post.return_value = mock_response

        resultado = mVuln.escanear_vulnerabilidades(self.paquetes_mock)
        
        # Tu bloque 'else' debe capturarlo, imprimir el error y devolver []
        self.assertEqual(resultado, [])


    @patch('modules.vulns.requests.post')
    def test_escanear_vulnerabilidades_fallo_conexion(self, mock_post):
        """Camino Triste: El servidor no tiene internet (Timeout o ConnectionError)."""
        
        # Forzamos que requests explote al intentar salir a internet
        mock_post.side_effect = requests.exceptions.ConnectionError("Network is unreachable")

        resultado = mVuln.escanear_vulnerabilidades(self.paquetes_mock)
        
        # Tu bloque 'except Exception as e' debe hacer su trabajo
        self.assertEqual(resultado, [])


if __name__ == '__main__':
    unittest.main()