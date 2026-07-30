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
import yaml
import sys 


def loadYaml(path):
    try:
        with open(path,"r", encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    except FileNotFoundError:
        print('Error al cargar el yaml, archivo no encontrado\n')
        sys.exit(1)
    
    except yaml.YAMLError:
        print("El archivo yaml contiene errores\n")
        sys.exit(1)
        
config = loadYaml("config/controls.yaml")