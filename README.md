# 🛡️ NetAudit - DevSecOps Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-2B7CFF?style=for-the-badge&logo=nmap&logoColor=white)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Security-red?style=for-the-badge)

Una herramienta de auditoría automatizada desarrollada en Python para escanear redes locales, identificar servicios activos y cruzar la información en tiempo real con la **Base de Datos Nacional de Vulnerabilidades (NVD)** del gobierno de Estados Unidos. Diseñada para generar reportes corporativos limpios y visuales de forma autónoma.

## 🌟 Características Principales

* **Orquestación de Nmap:** Uso del módulo `subprocess` de Python para invocar escaneos de red silenciosos en segundo plano y extraer versiones exactas de software.
* **Procesamiento de Datos Complejos:** Análisis y *parsing* de grandes volúmenes de datos en formato XML (`xml.etree.ElementTree`) generados por el escáner de red.
* **Integración API RESTful:** Conexión con la API del NIST (NVD) para buscar CVEs (Common Vulnerabilities and Exposures) conocidos.
* **Tácticas DevSecOps:** Implementación de *Rate Limiting* (control de peticiones) para evitar bloqueos por parte de los servidores gubernamentales al realizar múltiples consultas.
* **Generación Dinámica de Reportes:** Creación automatizada de informes de auditoría en formato **HTML** mediante inyección de variables (f-strings) y CSS incrustado, ideal para presentar a clientes o equipos técnicos.

## 🛠️ Stack Tecnológico

* **Lenguaje Core:** Python 3
* **Motor de Escaneo:** Nmap (Network Mapper)
* **Peticiones HTTP:** Librería `requests`
* **Formatos de Datos:** XML, JSON, HTML

## 🚀 Instalación y Despliegue Local

1. **Requisitos previos:**
   Asegúrate de tener instalado Python 3 y el motor Nmap en tu sistema operativo (ej. `brew install nmap` en macOS).

2. **Clonar el repositorio:**
   ```bash
   git clone [https://github.com/josemanueldg02-star/net-audit.git](https://github.com/josemanueldg02-star/net-audit.git)
   cd net-audit
   ```

3. **Crear y activar un entorno virtual (Recomendado):**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # En Linux/macOS
   # En Windows usa: .venv\Scripts\activate
   ```

4. **Instalar dependencias:**
   ```bash
   pip install requests
   ```

5. **Ejecutar la auditoría:**
   ```bash
   python3 scanner.py
   ```
   *(Nota: Al finalizar, se generará automáticamente el archivo `reporte_auditoria.html` en el directorio).*

## ⚠️ Disclaimer Ético y Legal

Este proyecto ha sido desarrollado con fines **estrictamente educativos y de Hacking Ético**. El uso de esta herramienta para escanear redes o sistemas sin el consentimiento explícito de sus propietarios es ilegal. Por defecto, el script está configurado para auditar únicamente el entorno local (`127.0.0.1`).

---
*Desarrollado como proyecto de portfolio para demostrar habilidades de automatización de sistemas, análisis de vulnerabilidades y buenas prácticas en DevSecOps.*