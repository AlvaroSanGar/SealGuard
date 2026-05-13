import unittest
from unittest.mock import patch, mock_open, MagicMock

# Importación real apuntando a modules/availability.py
from modules.availability import (
    auditar_backups, auditar_protecciones_dos, 
    auditar_limites_recursos, ESCANER_disponibilidad
)

# Constantes estáticas para el mock de configuración
AVAILABILITY_CONFIG_MOCK = {
    "disponibilidad": ["backup", "rsync", "tar", "snapshot", "aws s3", "rclone"]
}

class TestAvailabilityCompleto(unittest.TestCase):

    # =====================================================================
    # 1. TESTS: BACKUPS Y RESILIENCIA (auditar_backups)
    # =====================================================================
    @patch('modules.availability.config', AVAILABILITY_CONFIG_MOCK)
    @patch('modules.availability.ejecutar_consulta')
    def test_backups_perfecto(self, mock_db):
        def side_effect(query):
            if 'crontab' in query: 
                return [{"command": "rsync -a /var /backup", "path": "/etc/crontab"}]
            if 'systemd_units' in query: 
                return [{"id": "backup.timer", "description": "Timer backup", "sub_state": "active"}]
            return []
        mock_db.side_effect = side_effect
        
        res = auditar_backups(False)
        self.assertTrue(res["backups_activos"])
        self.assertIn("cron: /etc/crontab", res["mecanismos_encontrados"])
        self.assertIn("backup", res["mecanismos_encontrados"])
        self.assertEqual(len(res["alertas"]), 0)

    @patch('modules.availability.config', AVAILABILITY_CONFIG_MOCK)
    @patch('modules.availability.ejecutar_consulta')
    def test_backups_fallos_y_servicios_huerfanos(self, mock_db):
        def side_effect(query):
            if 'crontab' in query: 
                return [] 
            if 'systemd_units' in query: 
                return [
                    {"id": "off.timer", "description": "Apagado", "sub_state": "dead"},
                    {"id": "orphan.service", "description": "Servicio sin timer", "sub_state": "exited"},
                    {"id": "failed_back.service", "description": "Fallo", "sub_state": "fail"}
                ]
            return []
        mock_db.side_effect = side_effect
        
        res = auditar_backups(False)
        self.assertFalse(res["backups_activos"])
        self.assertTrue(any("No se han detectado tareas" in a for a in res["alertas"]))
        self.assertTrue(any("estado dead" in a for a in res["alertas"]))
        self.assertTrue(any("no tiene ningún timer asociado" in a for a in res["alertas"]))

    @patch('modules.availability.config', {}) 
    @patch('modules.availability.ejecutar_consulta', return_value=[])
    def test_backups_keyerror_fallback(self, mock_db):
        res = auditar_backups(False)
        self.assertFalse(res["backups_activos"])
        self.assertTrue(any("No se han detectado" in a for a in res["alertas"]))


    # =====================================================================
    # 2. TESTS: PROTECCIÓN DoS DEL KERNEL (auditar_protecciones_dos)
    # =====================================================================
    @patch('modules.availability.ejecutar_consulta')
    def test_protecciones_dos_seguro(self, mock_db):
        mock_db.return_value = [
            {"name": "net.ipv4.tcp_syncookies", "current_value": "1"},
            {"name": "net.ipv4.conf.all.rp_filter", "current_value": "1"},
            {"name": "net.ipv4.tcp_max_syn_backlog", "current_value": "2048"},
            {"name": "net.ipv4.icmp_echo_ignore_broadcasts", "current_value": "1"}
        ]
        res = auditar_protecciones_dos(False)
        self.assertEqual(res["estado"], "SEGURO")
        self.assertTrue(res["tcp_syncookies"] and res["rp_filter"] and res["tcp_max_syn_backlog"] and res["icmp_echo_ignore_broadcasts"])

    @patch('modules.availability.ejecutar_consulta')
    def test_protecciones_dos_solo_advertencias(self, mock_db):
        mock_db.return_value = [
            {"name": "net.ipv4.tcp_syncookies", "current_value": "2"},
            {"name": "net.ipv4.conf.all.rp_filter", "current_value": "2"},
            {"name": "net.ipv4.tcp_max_syn_backlog", "current_value": "2048"},
            {"name": "net.ipv4.icmp_echo_ignore_broadcasts", "current_value": "1"}
        ]
        res = auditar_protecciones_dos(False)
        self.assertEqual(res["estado"], "ADVERTENCIA")
        self.assertTrue(any("modo forzado" in a for a in res["alertas"]))

    @patch('modules.availability.ejecutar_consulta')
    def test_protecciones_dos_peligros(self, mock_db):
        mock_db.return_value = [
            {"name": "net.ipv4.tcp_syncookies", "current_value": "2"},
            {"name": "net.ipv4.conf.all.rp_filter", "current_value": "0"},
            {"name": "net.ipv4.tcp_max_syn_backlog", "current_value": "1024"},
            {"name": "net.ipv4.icmp_echo_ignore_broadcasts", "current_value": "0"}
        ]
        res = auditar_protecciones_dos(False)
        self.assertEqual(res["estado"], "PELIGROSO")
        self.assertFalse(res["rp_filter"])

    @patch('modules.availability.ejecutar_consulta')
    def test_protecciones_dos_ausencia_y_value_error(self, mock_db):
        mock_db.return_value = [
            {"name": "net.ipv4.tcp_max_syn_backlog", "current_value": "no_numerico"}
        ]
        res = auditar_protecciones_dos(False)
        self.assertEqual(res["estado"], "PELIGROSO")
        self.assertTrue(any("no es numérico" in a for a in res["alertas"]))
        # CORRECCIÓN: El código por defecto lo evalúa a "0" si falta, lo que desencadena esta frase:
        self.assertTrue(any("SYN Cookies está desactivado" in a for a in res["alertas"]))


    # =====================================================================
    # 3. TESTS: LÍMITES DE RECURSOS (auditar_limites_recursos)
    # =====================================================================
    @patch('os.path.exists', return_value=False) 
    @patch('builtins.open', new_callable=mock_open, read_data="* hard nproc 1024\n* - core 0\n* hard nofile 4096\n") # CORRECCIÓN: Añadido nofile
    def test_limites_recursos_seguro(self, mock_archivo, mock_exists):
        res = auditar_limites_recursos(False)
        self.assertEqual(res["estado"], "SEGURO")
        self.assertEqual(len(res["alertas"]), 0)

    @patch('os.path.exists', return_value=False)
    @patch('builtins.open', new_callable=mock_open, read_data="* hard nproc 1024\n")
    def test_limites_recursos_solo_nproc(self, mock_archivo, mock_exists):
        res = auditar_limites_recursos(False)
        self.assertEqual(res["estado"], "ADVERTENCIA")
        # CORRECCIÓN: Busca la frase exacta que genera tu código (core y nofile faltan)
        self.assertTrue(any("Faltan límites para:" in a for a in res["alertas"]))

    @patch('os.path.exists', return_value=False)
    @patch('builtins.open', new_callable=mock_open, read_data="# Todo comentado\n")
    def test_limites_recursos_peligroso(self, mock_archivo, mock_exists):
        res = auditar_limites_recursos(False)
        self.assertEqual(res["estado"], "PELIGROSO")
        self.assertTrue(any("Riesgo crítico" in a for a in res["alertas"]))

    @patch('os.path.exists')
    @patch('os.listdir', return_value=['99-test.conf'])
    def test_limites_recursos_carpeta_limits_d_y_excepcion(self, mock_listdir, mock_exists):
        def exists_side_effect(path):
            return True if path == '/etc/security/limits.d' else False
        mock_exists.side_effect = exists_side_effect
        
        with patch('builtins.open', side_effect=IOError("Permiso denegado")):
            res = auditar_limites_recursos(False)
            self.assertEqual(res["estado"], "PELIGROSO")
            self.assertTrue(any("No se puede leer el archivo" in a for a in res["alertas"]))


    # =====================================================================
    # 4. TESTS: ESCÁNER PRINCIPAL (ESCANER_disponibilidad)
    # =====================================================================
    @patch('modules.availability.auditar_backups', return_value={"mock": "A"})
    @patch('modules.availability.auditar_protecciones_dos', return_value={"mock": "B"})
    @patch('modules.availability.auditar_limites_recursos', return_value={"mock": "C"})
    def test_escaner_principal(self, mock_limites, mock_dos, mock_backups):
        res = ESCANER_disponibilidad(False)
        self.assertEqual(res["backups"]["mock"], "A")
        self.assertEqual(res["protecciones_dos"]["mock"], "B")
        self.assertEqual(res["limites_recursos"]["mock"], "C")

if __name__ == '__main__':
    unittest.main(verbosity=2)