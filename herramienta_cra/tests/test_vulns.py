import unittest
from unittest.mock import patch, MagicMock, mock_open
import requests
import gzip
import subprocess
import time
import modules.vulns as mVuln

# Configuración mock base
CONFIG_MOCK = {
    "vulnerabilities": {
        "min_cvss_score": 5.0,
        "nist_api_key": "test_key",
        "ignorar": ["CVE-1999-0001"]
    }
}

class TestVulnsModuleActualizado(unittest.TestCase):

    def setUp(self):
        # Reiniciamos las cachés globales para evitar contaminación entre tests
        mVuln.cache_cvss = {}
        mVuln.cache_detalles_osv = {}
        mVuln.INFO_SO_SISTEMA = None
        self.paquete_apt = [{
            'name': 'bash',
            'version': '5.1-6',
            'ecosystem': 'Debian',
            'type': 'System (APT)'
        }]

    # --- 1. TESTS DE FILTRADO Y LÓGICA LOCAL ---

    @patch('modules.vulns.os.path.exists', return_value=True)
    @patch('gzip.open', new_callable=mock_open, read_data="Fixed CVE-2023-1234\n")
    def test_cve_esta_en_changelog(self, mock_gzip, mock_exists):
        res = mVuln.cve_esta_en_changelog("bash", "CVE-2023-1234")
        self.assertTrue(res)

    @patch('modules.vulns.mSystem.info_sis', return_value={'version': '12.0', 'dist': 'debian'})
    @patch('subprocess.run')
    def test_es_falso_positivo_so_dpkg(self, mock_sub, mock_info):
        mock_sub.return_value = MagicMock(returncode=0)
        vuln_data = {
            "id": "CVE-2024-9999",
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "5.0"}]}]}]
        }
        res = mVuln.es_falso_positivo_so("5.1", vuln_data, "bash")
        self.assertTrue(res)

    @patch('modules.system.info_sis')
    def test_obtener_contexto_so_calculo_año(self, mock_info):
        mock_info.return_value = {'version': '22.04', 'dist': 'ubuntu'}
        res = mVuln.obtener_contexto_so()
        self.assertEqual(res["año_corte"], 2018)
        
        mVuln.INFO_SO_SISTEMA = None
        mock_info.return_value = {'version': 'unknown', 'dist': 'linux'}
        res = mVuln.obtener_contexto_so()
        self.assertEqual(res["año_corte"], 2022)

    # --- 2. TESTS DE CACHÉ Y RATE-LIMITING ---

    @patch('modules.vulns.session_http.get')
    def test_cache_cvss_evita_peticiones_duplicadas(self, mock_get):
        mVuln.cache_cvss["CVE-2026-0001"] = 9.0
        score = mVuln.obtener_score_cvss("CVE-2026-0001")
        self.assertEqual(score, 9.0)
        mock_get.assert_not_called()

    @patch('modules.vulns.config', {"vulnerabilities": {"nist_api_key": "clave_real"}})
    @patch('modules.vulns.session_http.get')
    @patch('time.sleep')
    def test_rate_limit_con_api_key(self, mock_sleep, mock_get):
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]}}}]}
        mock_get.return_value = mock_resp
        mVuln.obtener_score_cvss("CVE-2024-1111")
        mock_sleep.assert_called_with(0.6)

    @patch('modules.vulns.config', {"vulnerabilities": {"nist_api_key": None}})
    @patch('modules.vulns.session_http.get')
    @patch('time.sleep')
    def test_rate_limit_sin_api_key(self, mock_sleep, mock_get):
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]}}}]}
        mock_get.return_value = mock_resp
        mVuln.obtener_score_cvss("CVE-2024-2222")
        mock_sleep.assert_called_with(6.0)

    # --- 3. TESTS DE ERROR EN RED Y ROBUSTEZ ---

    @patch('modules.vulns.session_http.get')
    def test_obtener_score_cvss_error_nist(self, mock_get):
        mock_get.return_value = MagicMock(status_code=403)
        score = mVuln.obtener_score_cvss("CVE-2024-9999")
        self.assertEqual(score, 0.0)

    @patch('modules.vulns.session_http.get')
    def test_extraer_score_osv_profundo_404_con_fallback(self, mock_get):
        mock_get.return_value = MagicMock(status_code=404)
        score_profundo = mVuln.extraer_score_osv_profundo("CVE-000", {})
        self.assertIsNone(score_profundo)

    @patch('modules.vulns.os.path.exists', return_value=True)
    @patch('gzip.open')
    def test_changelog_corrupto_no_detiene_analisis(self, mock_gzip, mock_exists):
        mock_gzip.side_effect = Exception("Corrupto")
        res = mVuln.cve_esta_en_changelog("roto", "CVE-2024")
        self.assertFalse(res)

    # --- 4. TESTS DE LIBRERÍA LOCAL Y INTEGRACIÓN ---

    @patch('modules.vulns.LIBRERIA_CVSS', True)
    @patch('modules.vulns.CVSS3')
    def test_extraer_score_osv_desde_vector_local(self, mock_cvss3):
        mock_cvss3.return_value.scores.return_value = [9.8]
        vuln_data = {
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        }
        score = mVuln.extraer_score_osv_profundo("CVE-2024-TEST", vuln_data)
        self.assertEqual(score, 9.8)

    @patch('modules.vulns.session_http.post')
    @patch('modules.vulns.obtener_contexto_so', return_value={"año_corte": 2000})
    def test_escanear_vulnerabilidades_lotes_grandes(self, mock_ctx, mock_post):
        muchos_paquetes = [{'name': f'pkg{i}', 'version': '1.0', 'ecosystem': 'Debian', 'type': 'APT'} for i in range(201)]
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"results": []}
        mock_post.return_value = mock_resp
        mVuln.escanear_vulnerabilidades(muchos_paquetes)
        self.assertEqual(mock_post.call_count, 2)

    @patch('modules.vulns.config', CONFIG_MOCK)
    @patch('modules.vulns.mSystem.info_sis', return_value={'version': '12.0', 'dist': 'debian'})
    @patch('modules.vulns.session_http.post')
    @patch('modules.vulns.extraer_score_osv_profundo', return_value=7.5)
    @patch('modules.vulns.es_falso_positivo_so', return_value=False)
    def test_escanear_vulnerabilidades_flujo_completo(self, mock_fp, mock_osv_p, mock_post, mock_info):
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "results": [{
                "vulns": [
                    {"id": "CVE-1999-0001"}, 
                    {"id": "CVE-2005-0001"}, # Ignorado por año si Debian 12
                    {"id": "CVE-2024-0001"}
                ]
            }]
        }
        mock_post.return_value = mock_resp
        resultados = mVuln.escanear_vulnerabilidades(self.paquete_apt)
        self.assertEqual(len(resultados), 1)
        self.assertEqual(resultados[0]['cves'][0]['id'], "CVE-2024-0001")

    @patch('modules.vulns.escanear_vulnerabilidades', return_value=[])
    @patch('modules.system.paquetes_python', return_value=[{'name': 'requests', 'version': '2.0'}])
    @patch('modules.system.paquetes_instalados', return_value=[])
    def test_ESCANER_vulnerabilidades_integracion(self, mock_apt, mock_pip, mock_scan):
        res = mVuln.ESCANER_vulnerabilidades(verbose=False)
        self.assertIn("paquetes", res)
        self.assertEqual(res["paquetes"]["pip"], 1)
        mock_scan.assert_called_once()

if __name__ == '__main__':
    unittest.main()