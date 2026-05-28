import subprocess
import xml.etree.ElementTree as ET
import os
import requests
import urllib.parse
import time
from datetime import datetime


def ejecutar_escaneo(target_ip):
    print(f"[*] Iniciando escaneo de seguridad sobre {target_ip}...")
    archivo_salida = "scan_result.xml"
    comando = ["nmap", "-sV", "--top-ports", "100", "-oX", archivo_salida, target_ip]

    try:
        subprocess.run(
            comando, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print("[+] Escaneo Nmap completado.")
        return archivo_salida
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al ejecutar Nmap: {e}")
        return None
    except FileNotFoundError:
        print("[-] Error crítico: Nmap no está instalado.")
        return None


def buscar_vulnerabilidades(software):
    print(f"    [*] Consultando base de datos NVD para: {software}...")
    keyword = urllib.parse.quote(software)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=3"

    try:
        time.sleep(6)  # Rate limiting para evitar bloqueos del servidor
        headers = {"User-Agent": "NetAudit-DevSecOps-Project"}
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            datos = response.json()
            vulnerabilidades = []

            for item in datos.get("vulnerabilities", []):
                cve_id = item.get("cve", {}).get("id", "Desconocido")
                descripciones = item.get("cve", {}).get("descriptions", [])
                descripcion = "Sin descripción"

                for d in descripciones:
                    if d.get("lang") == "en":
                        descripcion = d.get("value")
                        break

                vulnerabilidades.append({"id": cve_id, "descripcion": descripcion})
            return vulnerabilidades
        return []
    except Exception as e:
        print(f"[-] Error de conexión con NVD: {e}")
        return []


def generar_reporte_html(resultados, ip_objetivo):
    """
    Toma los datos procesados y construye un archivo HTML corporativo
    inyectando variables de Python dentro de la estructura web.
    """
    print("\n[*] Generando reporte corporativo en formato HTML...")
    fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Iniciamos la plantilla HTML con CSS incrustado para darle estilo corporativo
    html = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Reporte de Auditoría DevSecOps</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f4f6f9; color: #333; }}
            h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
            .resumen {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 30px; border-left: 5px solid #3498db; }}
            table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }}
            th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #ecf0f1; }}
            th {{ background-color: #2c3e50; color: white; text-transform: uppercase; font-size: 0.9em; }}
            tr:hover {{ background-color: #f9f9f9; }}
            .badge-safe {{ background-color: #2ecc71; color: white; padding: 6px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }}
            .badge-danger {{ background-color: #e74c3c; color: white; padding: 6px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }}
            .badge-warning {{ background-color: #f39c12; color: white; padding: 6px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }}
            .cve-list {{ margin-top: 10px; padding-left: 20px; font-size: 0.9em; color: #c0392b; }}
        </style>
    </head>
    <body>
        <h1>🛡️ Reporte de Auditoría de Red (NetAudit)</h1>
        <div class="resumen">
            <p><strong>Fecha de escaneo:</strong> {fecha_actual}</p>
            <p><strong>Objetivo auditado:</strong> {ip_objetivo}</p>
        </div>
        <table>
            <tr>
                <th>Puerto / Protocolo</th>
                <th>Servicio Identificado</th>
                <th>Estado de Seguridad</th>
            </tr>
    """

    # Recorremos cada puerto y creamos una fila en la tabla HTML dinámicamente
    for srv in resultados:
        html += f"<tr><td><strong>{srv['puerto']}/{srv['protocolo']}</strong></td><td>{srv['software']}</td><td>"

        if "Servicio:" in srv["software"] or srv["software"] == "Desconocido":
            html += "<span class='badge-warning'>⚠️ Requiere versión exacta</span>"
        elif not srv["cves"]:
            html += "<span class='badge-safe'>✅ Seguro (0 CVEs)</span>"
        else:
            html += f"<span class='badge-danger'>❌ {len(srv['cves'])} Vulnerabilidades</span>"
            html += "<ul class='cve-list'>"
            for cve in srv["cves"]:
                desc = (
                    cve["descripcion"][:100] + "..."
                    if len(cve["descripcion"]) > 100
                    else cve["descripcion"]
                )
                html += f"<li><strong>{cve['id']}:</strong> {desc}</li>"
            html += "</ul>"

        html += "</td></tr>"

    html += """
        </table>
        <p style="text-align: center; margin-top: 40px; font-size: 0.8em; color: #95a5a6;">
            Generado automáticamente por NetAudit - Herramienta DevSecOps
        </p>
    </body>
    </html>
    """

    # Guardamos todo ese texto HTML en un archivo físico
    nombre_archivo = "reporte_auditoria.html"
    with open(nombre_archivo, "w", encoding="utf-8") as file:
        file.write(html)
    print(
        f"[+] ¡Reporte HTML generado con éxito! Puedes abrir '{nombre_archivo}' en tu navegador."
    )


def analizar_resultados_xml(archivo_xml, ip_objetivo):
    print("[*] Procesando resultados y buscando vulnerabilidades en internet...")
    if not os.path.exists(archivo_xml):
        return

    tree = ET.parse(archivo_xml)
    root = tree.getroot()
    datos_completos = []

    for host in root.findall("host"):
        for ports in host.findall("ports"):
            for port in ports.findall("port"):
                if port.find("state").get("state") == "open":
                    puerto_num = port.get("portid")
                    protocolo = port.get("protocol")
                    servicio = port.find("service")

                    if servicio is not None:
                        nombre = servicio.get("name", "Desconocido")
                        producto = servicio.get("product", "")
                        version = servicio.get("version", "")
                        software = (
                            f"{producto} {version}".strip() or f"Servicio: {nombre}"
                        )
                    else:
                        software = "Desconocido"

                    # Buscamos los CVEs antes de guardar los datos
                    cves_encontrados = []
                    if "Servicio:" not in software and software != "Desconocido":
                        cves_encontrados = buscar_vulnerabilidades(software)

                    # Guardamos toda la información de este puerto en nuestro diccionario
                    datos_completos.append(
                        {
                            "puerto": puerto_num,
                            "protocolo": protocolo,
                            "software": software,
                            "cves": cves_encontrados,
                        }
                    )

    # Imprimimos en terminal para el "modo hacker" y generamos el HTML para el "modo jefe"
    for srv in datos_completos:
        print(
            f"\n [+] Puerto {srv['puerto']} -> {srv['software']} | CVEs: {len(srv['cves'])}"
        )

    generar_reporte_html(datos_completos, ip_objetivo)


if __name__ == "__main__":
    IP_OBJETIVO = "127.0.0.1"
    xml_generado = ejecutar_escaneo(IP_OBJETIVO)
    if xml_generado:
        analizar_resultados_xml(xml_generado, IP_OBJETIVO)
