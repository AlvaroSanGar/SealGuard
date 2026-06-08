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
La memoria completa del proyecto está disponible en el repositorio 
y se recomienda su lectura para comprender el diseño y las decisiones técnicas.

## Autor
Álvaro Sánchez Garijo — UCLM, ESII