import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import stat
import time

# Importaciones directas
from modules.hardening import (
    auditar_suid_sgid, auditar_archivos_criticos, auditar_ssh,
    auditar_firewall, auditar_aslr, auditar_mac, 
    auditar_certificados, auditar_cifrado, ESCANER_hardening
)

# Mock de configuración global para los tests
HARDENING_CONFIG_MOCK = {
    "hardening": {
        "suid_sgid": {"critical_directories": ["/tmp/"], "forviden_permissions": ["2", "3", "6", "7"]},
        "critical_files": [{"path": "/etc/shadow", "max_permissions": "600", "owner": "root"}],
        "ssh": {"secure_params": {"PermitRootLogin": "no", "MaxAuthTries": "4"}, "allowed_users": ["admin"]},
        "firewall_services": ["ufw.service"],
        "certificados": {
            "dias_aviso_caducidad": 30, "min_rsa_key_size": 2048, 
            "algoritmos_permitidos": ["sha256WithRSAEncryption"],
            "rutas_criticas": [
                {"path": "/cert.pem", "tipo": "publico", "max_permissions": "644", "owner": "root"},
                {"path": "/key.pem", "tipo": "privado", "max_permissions": "600", "owner": "root"}
            ]
        },
        "encryption": {"algoritmo": "aes", "critical_mounts": ["/", "/home"]}
    }
}

@patch.dict('modules.hardening.config', HARDENING_CONFIG_MOCK, clear=True)
class TestHardeningCompleto(unittest.TestCase):

    # =====================================================================
    # 1. SUID / SGID
    # =====================================================================
    @patch('modules.hardening.ejecutar_consulta')
    def test_suid_seguro(self, mock_db):
        mock_db.return_value = [{"path": "/usr/bin/sudo", "mode": "4755"}]
        res = auditar_suid_sgid(False)
        self.assertEqual(len(res["peligrosos"]), 0)

    @patch('modules.hardening.ejecutar_consulta')
    def test_suid_peligro_directorio(self, mock_db):
        mock_db.return_value = [{"path": "/tmp/malware", "mode": "4755"}]
        res = auditar_suid_sgid(False)
        self.assertEqual(len(res["peligrosos"]), 1)

    @patch('modules.hardening.ejecutar_consulta')
    def test_suid_permisos_prohibidos(self, mock_db):
        mock_db.return_value = [{"path": "/usr/bin/test", "mode": "4757"}]
        res = auditar_suid_sgid(False)
        self.assertEqual(len(res["peligrosos"]), 1)

    @patch('modules.hardening.ejecutar_consulta')
    def test_suid_deteccion_sgid(self, mock_db):
        mock_db.return_value = [{"path": "/usr/bin/sgid_test", "mode": "2757"}]
        res = auditar_suid_sgid(False)
        self.assertEqual(len(res["peligrosos"]), 1)

    @patch('modules.hardening.ejecutar_consulta')
    def test_suid_motivos_varios(self, mock_db):
        mock_db.return_value = [{"path": "/tmp/malware", "mode": "4755"}]
        res = auditar_suid_sgid(False)
        self.assertIn("Ubicación en directorio crítico", res["peligrosos"][0]["motivo"])

    # =====================================================================
    # 2. ARCHIVOS CRÍTICOS
    # =====================================================================
    @patch('modules.hardening.ejecutar_consulta')
    def test_archivos_criticos_perfecto(self, mock_db):
        mock_db.return_value = [{"path": "/etc/shadow", "mode": "0600", "username": "root"}]
        res = auditar_archivos_criticos(False)
        self.assertEqual(res[0]["estado"], "SEGURO")

    @patch('modules.hardening.ejecutar_consulta', return_value=[])
    def test_archivos_criticos_no_encontrado(self, mock_db):
        res = auditar_archivos_criticos(False)
        self.assertEqual(res[0]["estado"], "NO ENCONTRADO")

    @patch('modules.hardening.ejecutar_consulta')
    def test_archivos_criticos_dueno_incorrecto(self, mock_db):
        mock_db.return_value = [{"path": "/etc/shadow", "mode": "0600", "username": "hacker"}]
        res = auditar_archivos_criticos(False)
        self.assertEqual(res[0]["estado"], "PELIGROSO")

    @patch('modules.hardening.config', {"hardening": {}})
    @patch('modules.hardening.ejecutar_consulta')
    def test_archivos_criticos_yaml_vacio(self, mock_db):
        mock_db.return_value = [{"path": "/etc/default/grub", "mode": "0644", "username": "root"}]
        res = auditar_archivos_criticos(False)
        self.assertEqual(res[0]["archivo"], "/etc/default/grub")

    @patch('modules.hardening.ejecutar_consulta')
    def test_archivos_criticos_permisos_restrictivos_ok(self, mock_db):
        mock_db.return_value = [{"path": "/etc/shadow", "mode": "0400", "username": "root"}]
        res = auditar_archivos_criticos(False)
        self.assertEqual(res[0]["estado"], "SEGURO")

    # =====================================================================
    # 3. SSH
    # =====================================================================
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data="Port 22\nPermitRootLogin no\n")
    def test_ssh_puerto_22_riesgo(self, mock_file, mock_exists):
        res = auditar_ssh(False)
        self.assertTrue(any("puerto en el que se está ejecutando SSH es por defecto (22)" in a for a in res["alertas"]))

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data="Port 2222\nPermitRootLogin no\nMaxAuthTries 4\nAllowUsers admin\n")
    def test_ssh_config_segura(self, mock_file, mock_exists):
        res = auditar_ssh(False)
        self.assertEqual(res["estado"], "SEGURO")

    @patch('os.path.exists', return_value=False)
    def test_ssh_no_instalado(self, mock_exists):
        res = auditar_ssh(False)
        self.assertEqual(res["estado"], "SEGURO")

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', side_effect=Exception("Error lectura"))
    def test_ssh_error_lectura(self, mock_file, mock_exists):
        res = auditar_ssh(False)
        self.assertEqual(res["alertas"], "No se ha logrado leer el archivo de configuración")

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data="Port 2222\nAllowUsers juan\n")
    def test_ssh_usuarios_no_coinciden(self, mock_file, mock_exists):
        res = auditar_ssh(False)
        self.assertEqual(res["estado"], "PELIGROSO")

    # =====================================================================
    # 4. FIREWALL
    # =====================================================================
    @patch('modules.hardening.ejecutar_consulta')
    @patch('modules.hardening.subprocess.run')
    def test_firewall_seguro_iptables(self, mock_run, mock_db):
        mock_db.return_value = [{"id": "ufw.service", "active_state": "active", "unit_file_state": "enabled"}]
        mock_run.return_value = MagicMock(returncode=0, stdout="-P INPUT DROP")
        res = auditar_firewall(False)
        self.assertEqual(res["estado"], "SEGURO")

    @patch('modules.hardening.ejecutar_consulta', return_value=[])
    @patch('modules.hardening.subprocess.run')
    def test_firewall_totalmente_expuesto(self, mock_run, mock_db):
        mock_run.return_value = MagicMock(returncode=0, stdout="-P INPUT ACCEPT")
        res = auditar_firewall(False)
        self.assertEqual(res["estado"], "PELIGROSO")

    @patch('modules.hardening.ejecutar_consulta')
    def test_firewall_activo_pero_no_enabled(self, mock_db):
        mock_db.return_value = [{"id": "ufw.service", "active_state": "active", "unit_file_state": "disabled"}]
        with patch('modules.hardening.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="-P INPUT DROP")
            res = auditar_firewall(False)
            self.assertTrue(any("no se ha configurado que arranque" in a for a in res["alertas"]))

    @patch('modules.hardening.ejecutar_consulta', return_value=[])
    @patch('modules.hardening.subprocess.run')
    def test_firewall_fallback_nftables(self, mock_run, mock_db):
        def side_effect(cmd, **kwargs):
            if cmd[0] == "iptables": return MagicMock(returncode=1)
            if cmd[0] == "nft": return MagicMock(returncode=0, stdout="policy drop")
            return MagicMock(returncode=0)
        mock_run.side_effect = side_effect
        res = auditar_firewall(False)
        self.assertEqual(res["kernel"]["tipo_filtro"], "Nftables")

    @patch('modules.hardening.ejecutar_consulta', return_value=[])
    @patch('modules.hardening.subprocess.run')
    def test_firewall_politicas_estrictas(self, mock_run, mock_db):
        mock_run.return_value = MagicMock(returncode=0, stdout="-P OUTPUT DROP\n-P FORWARD DROP")
        res = auditar_firewall(False)
        self.assertTrue(res["kernel"]["bloqueo_output"])

    # =====================================================================
    # 5. ASLR
    # =====================================================================
    @patch('modules.hardening.ejecutar_consulta', return_value=[{"current_value": "2"}])
    def test_aslr_seguro(self, mock_db):
        res = auditar_aslr(False)
        self.assertEqual(res["estado"], "SEGURO")

    @patch('modules.hardening.ejecutar_consulta', return_value=[{"current_value": "0"}])
    def test_aslr_desactivado(self, mock_db):
        res = auditar_aslr(False)
        self.assertEqual(res["estado"], "PELIGROSO")

    # =====================================================================
    # 6. MAC
    # =====================================================================
    @patch('modules.hardening.ejecutar_consulta')
    def test_mac_selinux_enforcing(self, mock_db):
        mock_db.side_effect = [[], [{"path": "/etc/selinux/config"}], [{"value": "1"}]]
        res = auditar_mac(False)
        self.assertEqual(res["selinux"]["modo"], "Enforcing")

    @patch('modules.hardening.ejecutar_consulta')
    def test_mac_apparmor_enforce(self, mock_db):
        mock_db.side_effect = [[{"path": "/etc/apparmor.d"}], [{"mode": "enforce", "total": "5"}], []]
        res = auditar_mac(False)
        self.assertEqual(res["apparmor"]["enforce"], 5)

    @patch('modules.hardening.ejecutar_consulta', return_value=[])
    def test_mac_ninguno_activo(self, mock_db):
        res = auditar_mac(False)
        self.assertEqual(res["estado"], "PELIGROSO")

# =====================================================================
    # 7. CERTIFICADOS (TEST CORREGIDO + NUEVOS)
    # =====================================================================
    @patch('os.path.exists', return_value=True)
    @patch('os.stat')
    @patch('pwd.getpwuid')
    @patch('modules.hardening.ejecutar_consulta')
    @patch('time.time', return_value=1000000)
    def test_certificados_perfecto(self, mock_time, mock_db, mock_pwd, mock_stat, mock_exists):
        """CORREGIDO: Diferencia permisos entre clave y certificado para evitar falso positivo"""
        def stat_side_effect(path):
            m = MagicMock()
            m.st_uid = 0
            # Asignamos permisos correctos según el archivo: 600 para clave, 644 para cert
            m.st_mode = 0o100600 if "key.pem" in path else 0o100644
            return m
            
        mock_stat.side_effect = stat_side_effect
        mock_pwd.return_value.pw_name = "root"
        mock_db.return_value = [{"not_valid_after": "20000000", "signing_algorithm": "sha256WithRSAEncryption"}]
        
        with patch('modules.hardening.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Public-Key: (2048 bit)\nTLS Web Server Authentication")
            res = auditar_certificados(False)
            self.assertEqual(res["estado"], "SEGURO")

    @patch('os.path.exists', return_value=True)
    @patch('os.stat')
    @patch('modules.hardening.ejecutar_consulta')
    def test_certificados_autofirmado(self, mock_db, mock_stat, mock_exists):
        """Detecta si un certificado es autofirmado (issuer == subject)"""
        mock_stat.return_value.st_mode = 0o100644
        # Simulamos que el emisor y el sujeto son la misma entidad[cite: 10]
        mock_db.return_value = [{
            "issuer": "Entidad_Prueba", "subject": "Entidad_Prueba",
            "not_valid_after": "99999999", "signing_algorithm": "sha256WithRSAEncryption"
        }]
        res = auditar_certificados(False)
        self.assertTrue(any("está AUTOFIRMADO" in a for a in res["alertas"]))

    @patch('os.path.exists', return_value=True)
    @patch('os.stat')
    @patch('modules.hardening.ejecutar_consulta')
    def test_certificados_rsa_debil(self, mock_db, mock_stat, mock_exists):
        """Detecta claves RSA de tamaño inferior al mínimo configurado[cite: 10]"""
        mock_stat.return_value.st_mode = 0o100644
        mock_db.return_value = [{"not_valid_after": "99999999", "signing_algorithm": "sha256WithRSAEncryption"}]
        with patch('modules.hardening.subprocess.run') as mock_run:
            # Simulamos una clave de 1024 bits (inferior a los 2048 requeridos)[cite: 10]
            mock_run.return_value = MagicMock(returncode=0, stdout="Public-Key: (1024 bit)\nTLS Web Server Authentication")
            res = auditar_certificados(False)
            self.assertTrue(any("clave insuficiente: 1024 bits" in a for a in res["alertas"]))

    @patch('os.path.exists', return_value=True)
    @patch('os.stat')
    @patch('modules.hardening.ejecutar_consulta')
    def test_certificados_eku_incorrecto(self, mock_db, mock_stat, mock_exists):
        """Detecta si falta el propósito 'Server Authentication' (EKU)[cite: 10]"""
        mock_stat.return_value.st_mode = 0o100644
        mock_db.return_value = [{"not_valid_after": "99999999", "signing_algorithm": "sha256WithRSAEncryption"}]
        with patch('modules.hardening.subprocess.run') as mock_run:
            # Simulamos salida de openssl sin la cadena necesaria[cite: 10]
            mock_run.return_value = MagicMock(returncode=0, stdout="Public-Key: (2048 bit)\nPurpose: Email Protection")
            res = auditar_certificados(False)
            self.assertTrue(any("no tiene el permiso 'Server Authentication'" in a for a in res["alertas"]))

    # =====================================================================
    # 8. CIFRADO
    # =====================================================================
    @patch('modules.hardening.ejecutar_consulta')
    def test_cifrado_seguro(self, mock_db):
        mock_db.return_value = [{"device_alias": "root", "path": "/", "encrypted": "1"}]
        res = auditar_cifrado(False)
        self.assertEqual(res["estado"], "SEGURO")

    @patch('modules.hardening.ejecutar_consulta')
    def test_cifrado_incompleto(self, mock_db):
        mock_db.return_value = [{"device_alias": "root", "path": "/", "encrypted": "1"}, {"device_alias": "home", "path": "/home", "encrypted": "0"}]
        res = auditar_cifrado(False)
        self.assertEqual(res["estado"], "PELIGROSO")

    @patch('modules.hardening.ejecutar_consulta', return_value=[])
    def test_cifrado_vacio(self, mock_db):
        res = auditar_cifrado(False)
        self.assertEqual(res["estado"], "PELIGROSO")

    # =====================================================================
    # 9. ORQUESTACIÓN
    # =====================================================================
    @patch('modules.hardening.auditar_cifrado', return_value={"estado": "OK"})
    @patch('modules.hardening.auditar_certificados', return_value={"estado": "OK"})
    @patch('modules.hardening.auditar_mac', return_value={"estado": "OK"})
    @patch('modules.hardening.auditar_aslr', return_value={"estado": "OK"})
    @patch('modules.hardening.auditar_firewall', return_value={"estado": "OK"})
    @patch('modules.hardening.auditar_ssh', return_value={"estado": "OK"})
    @patch('modules.hardening.auditar_archivos_criticos', return_value=[])
    @patch('modules.hardening.auditar_suid_sgid', return_value={"peligrosos": []})
    def test_ESCANER_hardening_flujo(self, *mocks):
        res = ESCANER_hardening(False)
        self.assertEqual(len(res.keys()), 8)

if __name__ == '__main__':
    unittest.main(verbosity=2)