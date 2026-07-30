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
from unittest.mock import patch, MagicMock, mock_open
import requests
import time
import modules.vulns as mVuln

# Configuración mock base
CONFIG_MOCK = {
    "vulnerabilities": {
        "min_cvss_score": 5.0,
        "ignorar": ["CVE-1999-0001"]
    }
}

class TestVulnsModuleActualizado(unittest.TestCase):

    def setUp(self):
        # Reiniciamos las cachés y variables globales para evitar contaminación entre tests
        mVuln.cache_detalles_osv = {}
        mVuln.cache_ubuntu_tracker = {}
        mVuln.cache_debian_tracker = {}
        mVuln._debian_cargado = False
        mVuln.ECOSISTEMAS_SO = ["Debian"]
        mVuln.TIPO_TRACKER = "debian"
        mVuln.CODENAME_TRACKER = "bookworm"
        
        self.paquete_apt = [{
            'name': 'bash',
            'version': '5.1-6',
            'ecosystem': 'Debian',
            'type': 'System (APT)'
        }]

    # --- 1. TESTS DE DETECCIÓN DE SISTEMA ---
    @patch('builtins.open', new_callable=mock_open, read_data='ID="ubuntu"\nID_LIKE="debian"\nVERSION_CODENAME="jammy"\nUBUNTU_CODENAME="jammy"\n')
    def test_detectar_info_distro_ubuntu(self, mock_file):
        eco, track, code, d_id = mVuln.detectar_info_distro()
        self.assertIn("Ubuntu", eco)
        self.assertIn("Debian", eco)
        self.assertEqual(track, "ubuntu")
        self.assertEqual(code, "jammy")

    @patch('builtins.open', new_callable=mock_open, read_data='ID="fedora"\nID_LIKE="rhel"\nVERSION_CODENAME="39"\n')
    def test_detectar_info_distro_no_soportada(self, mock_file):
        eco, track, code, d_id = mVuln.detectar_info_distro()
        self.assertEqual(eco, []) # No pertenece a familia Debian

    # --- 2. TESTS DE FILTRADO Y LÓGICA LOCAL ---
    @patch('subprocess.run')
    def test_comparar_versiones_nativa_dpkg(self, mock_run):
        # Simulamos que es falso (la instalada es menor)
        mock_run.return_value = MagicMock(returncode=1)
        with patch.dict('sys.modules', {'apt_pkg': None}): # Forzamos el uso de dpkg
            res = mVuln.comparar_versiones_nativa("1.0", "2.0")
            self.assertFalse(res)

    def test_normalizar_cve(self):
        self.assertEqual(mVuln.normalizar("UBUNTU-CVE-2024-1234"), "CVE-2024-1234")
        self.assertEqual(mVuln.normalizar("DEBIAN-CVE-2024-1234"), "CVE-2024-1234")
        self.assertEqual(mVuln.normalizar("CVE-2024-1234"), "CVE-2024-1234")
        self.assertIsNone(mVuln.normalizar("GHSA-1234"))

    @patch('modules.vulns.comparar_versiones_nativa', return_value=True)
    def test_es_falso_positivo_so_parcheado(self, mock_comp):
        # Falso positivo: el parche "2.0" está instalado
        vuln_data = {"affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.0"}]}]}]}
        res = mVuln.es_falso_positivo_so("2.5", vuln_data)
        self.assertTrue(res)

    def test_parse_vector_directo(self):
        data = {"severity": [{"score": 7.5}]}
        self.assertEqual(mVuln.parse_vector(data), 7.5)

    @patch('modules.vulns.LIBRERIA_CVSS', True)
    @patch('modules.vulns.CVSS3')
    def test_parse_vector_cvss3(self, mock_cvss3):
        mock_cvss3.return_value.scores.return_value = [8.2]
        data = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        self.assertEqual(mVuln.parse_vector(data), 8.2)

    # --- 3. TESTS DE TRACKERS (UBUNTU/DEBIAN) ---
    @patch('modules.vulns.requests.get')
    def test_cve_parcheado_ubuntu_vulnerable(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {
            "packages": [{"name": "bash", "statuses": [{"release_codename": "bookworm", "status": "needed"}]}]
        })
        mVuln.CODENAME_TRACKER = "bookworm"
        res = mVuln.cve_parcheado_ubuntu("CVE-123", "bash", "1.0")
        self.assertFalse(res) # "needed" significa que es vulnerable

    @patch('modules.vulns.requests.get')
    def test_cargar_debian_tracker(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {
            "bash": {"CVE-123": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "2.0"}}}}
        })
        res = mVuln.cargar_debian_tracker()
        self.assertTrue(res)
        self.assertIn("CVE-123", mVuln.cache_debian_tracker)

    # --- 4. TESTS DE RED Y API (OSV) ---
    @patch('modules.vulns.time.sleep')
    def test_post_con_reintentos_exito(self, mock_sleep):
        sesion = MagicMock()
        sesion.post.return_value = MagicMock(status_code=200, json=lambda: {"ok": True})
        res = mVuln.post_con_reintentos(sesion, "url", {})
        self.assertEqual(res, {"ok": True})

    @patch('modules.vulns.time.sleep')
    def test_post_con_reintentos_fallo_400(self, mock_sleep):
        sesion = MagicMock()
        sesion.post.return_value = MagicMock(status_code=400) # Error de cliente, no reintenta
        res = mVuln.post_con_reintentos(sesion, "url", {})
        self.assertIsNone(res)

    # --- 5. TESTS CORE: PROCESAMIENTO ---
    @patch('modules.vulns.obtener_score_con_cache')
    @patch('modules.vulns.es_falso_positivo_so', return_value=False)
    @patch('modules.vulns.cve_parcheado', return_value=False)
    def test_procesar_resultados_batch(self, mock_parch, mock_fp, mock_score):
        # Simulamos que la vuln tiene un CVSS de 9.0
        mock_score.return_value = {"score": 9.0, "data": {}}
        res_osv = [{"vulns": [{"id": "CVE-2024-123", "aliases": []}]}]
        meta = [{"name": "bash", "version": "1.0", "type": "System (APT)"}]
        cfg = {"min_cvss_score": 5.0}
        
        hallazgos = mVuln.procesar_resultados_batch(res_osv, meta, cfg, MagicMock())
        self.assertEqual(len(hallazgos), 1)
        self.assertEqual(hallazgos[0]["paquete"], "bash")
        self.assertEqual(hallazgos[0]["cves"][0]["id"], "CVE-2024-123")

    @patch('modules.vulns.obtener_score_con_cache')
    @patch('modules.vulns.es_falso_positivo_so', return_value=False)
    @patch('modules.vulns.cve_parcheado', return_value=False)
    def test_procesar_resultados_batch_ignorado(self, mock_parch, mock_fp, mock_score):
        mock_score.return_value = {"score": 9.0, "data": {}}
        res_osv = [{"vulns": [{"id": "CVE-1999-0001", "aliases": []}]}]
        meta = [{"name": "bash", "version": "1.0", "type": "System (APT)"}]
        cfg = {"min_cvss_score": 5.0, "ignorar": ["CVE-1999-0001"]} # En ignorados
        
        hallazgos = mVuln.procesar_resultados_batch(res_osv, meta, cfg, MagicMock())
        self.assertEqual(len(hallazgos), 0)

    # --- 6. TESTS DE INTEGRACIÓN FINAL ---
    @patch('modules.vulns.mSystem.paquetes_instalados', return_value=[{"name": "bash", "version": "1.0", "type": "System (APT)"}])
    @patch('modules.vulns.escanear_vulnerabilidades', return_value=[{"paquete": "bash", "cves": [{"id": "CVE-1"}]}])
    def test_ESCANER_vulnerabilidades_flujo_ok(self, mock_escanear, mock_paq):
        mVuln.ECOSISTEMAS_SO = ["Debian"]
        res = mVuln.ESCANER_vulnerabilidades(False)
        self.assertEqual(res["paquetes"]["apt"], 1)
        self.assertEqual(len(res["vulns"]), 1)

if __name__ == '__main__':
    unittest.main(verbosity=2)