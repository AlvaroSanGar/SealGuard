import unittest
from unittest.mock import patch, MagicMock
import requests
import modules.vulns as mVuln

# Creamos un mock de configuración base para evitar dependencias del entorno real
CONFIG_MOCK = {
    "vulnerabilities": {
        "min_cvss_score": 0.0,
        "nist_api_key": ""
    }
}

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

    # [!] Al pasar CONFIG_MOCK directamente, NO se añade mock_config a los parámetros
    @patch('modules.vulns.config', CONFIG_MOCK)
    @patch('modules.vulns.obtener_score_cvss', return_value=8.5) 
    @patch('modules.vulns.requests.post')
    def test_escanear_vulnerabilidades_con_vulns(self, mock_post, mock_score):
        """Camino Feliz: La API responde 200 OK y encuentra 2 vulnerabilidades."""
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        
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

        resultado = mVuln.escanear_vulnerabilidades(self.paquetes_mock)

        # Comprobaciones principales
        self.assertEqual(len(resultado), 1)  # 1 paquete vulnerable detectado
        self.assertEqual(resultado[0]['paquete'], 'curl')
        self.assertEqual(resultado[0]['cantidad'], 2)
        
        # Extraemos los IDs de los diccionarios para poder compararlos correctamente
        ids_detectados = [vuln['id'] for vuln in resultado[0]['cves']]
        self.assertIn("CVE-2023-1234", ids_detectados)
        self.assertIn("CVE-2023-5678", ids_detectados)


    @patch('modules.vulns.config', CONFIG_MOCK)
    @patch('modules.vulns.requests.post')
    def test_escanear_vulnerabilidades_sin_vulns(self, mock_post):
        """Camino Feliz: La API responde 200 OK pero el paquete es seguro."""
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"results": [{}]}
        mock_post.return_value = mock_response

        resultado = mVuln.escanear_vulnerabilidades(self.paquetes_mock)
        self.assertEqual(resultado, [])


    @patch('modules.vulns.config', CONFIG_MOCK)
    @patch('modules.vulns.requests.post')
    def test_escanear_vulnerabilidades_error_http(self, mock_post):
        """Camino Triste: La API está saturada y devuelve un Error 500."""
        
        mock_response = MagicMock()
        mock_response.status_code = 500 
        mock_post.return_value = mock_response

        resultado = mVuln.escanear_vulnerabilidades(self.paquetes_mock)
        self.assertEqual(resultado, [])


    @patch('modules.vulns.config', CONFIG_MOCK)
    @patch('modules.vulns.requests.post')
    def test_escanear_vulnerabilidades_fallo_conexion(self, mock_post):
        """Camino Triste: El servidor no tiene internet (Timeout o ConnectionError)."""
        
        mock_post.side_effect = requests.exceptions.ConnectionError("Network is unreachable")
        resultado = mVuln.escanear_vulnerabilidades(self.paquetes_mock)
        
        self.assertEqual(resultado, [])


if __name__ == '__main__':
    unittest.main()