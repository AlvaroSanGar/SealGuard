# SealGuard — Herramienta de Auditoría CRA

SealGuard es una herramienta de auditoría de seguridad desarrollada como TFG de 
Ingeniería Informática en la UCLM. Su objetivo es verificar el cumplimiento técnico 
del Reglamento de Ciberresiliencia (CRA) de la UE en sistemas basados en Debian/Ubuntu,
mapeando los hallazgos técnicos del sistema a los requisitos esenciales del Anexo I del CRA.

> **Aviso:** La herramienta no cubre la totalidad del Anexo I del CRA. 
> Su uso no garantiza la certificación legal del producto bajo el reglamento.

## Requisitos
- Sistema operativo basado en Debian o Ubuntu
- Python 3.3 o superior
- Paquete `python3-venv` instalado en el sistema

## Instalación y uso
```bash
git clone <repositorio>
cd herramienta_cra
chmod +x sealguard
./sealguard --mode=scan
```

La herramienta gestiona automáticamente la escalada de privilegios, 
la creación del entorno virtual y la instalación de Nmap y OSquery.

## Modos disponibles

| Modo | Descripción |
|---|---|
| `--mode=scan` | Escaneo completo del sistema |
| `--mode=baseline` | Genera estado de referencia de integridad |
| `--mode=config-bl` | Selecciona el baseline activo |
| `--mode=recover` | Recupera un informe anterior |
| `--mode=history` | Muestra el historial de la BBDD |
| `--mode=delete` | Elimina la BBDD local |
| `--mode=edit-config` | Edita la configuración |

## Documentación
 
La memoria completa del proyecto (TFG) se publicará próximamente en este repositorio.
 
## Licencia
SealGuard es software libre: puedes usarlo, estudiarlo, modificarlo y redistribuirlo
bajo los términos de la Licencia Pública General de GNU (GPL) versión 3, publicada
por la Free Software Foundation, ya sea la versión 3 o (a tu elección) cualquier
versión posterior.

En la práctica esto significa que:
- Puedes usar SealGuard libremente, para cualquier fin.
- Puedes modificarlo y crear tus propias versiones.
- Si distribuyes SealGuard o una versión modificada, debes:
  - hacerlo también bajo GPLv3 (o posterior), con el código fuente disponible;
  - conservar el aviso de copyright y de licencia original;
  - indicar claramente qué archivos has modificado.

SealGuard se distribuye con la esperanza de que sea útil, pero sin ninguna garantía;
consulta el texto completo en [`LICENSE`](./LICENSE) para todos los detalles.

## Autor
Álvaro Sánchez Garijo — UCLM, ESII