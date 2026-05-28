import subprocess
import xml.etree.ElementTree as ET
import os
import requests
import urllib.parse
import time


def ejecutar_escaneo(target_ip):
    print(f"[*] Iniciando escaneo de seguridad sobre {target_ip}...")
    archivo_salida = "scan_result.xml"
    comando = ["nmap", "-sV", "--top-ports", "100", "-oX", archivo_salida, target_ip]

    try:
        subprocess.run(
            comando, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print("[+] Escaneo completado. Archivo de datos generado con éxito.")
        return archivo_salida
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al ejecutar Nmap: {e}")
        return None
    except FileNotFoundError:
        print("[-] Error crítico: Nmap no está instalado en el sistema.")
        return None


def buscar_vulnerabilidades(software):
    """
    Se conecta a la API pública del NIST (Gobierno de EEUU) para buscar
    vulnerabilidades (CVEs) asociadas a un software específico.
    """
    print(f"    [*] Consultando bases de datos de vulnerabilidades para: {software}...")

    # Codificamos el texto para URLs (ej. "PostgreSQL 14" -> "PostgreSQL%2014")
    keyword = urllib.parse.quote(software)
    # Buscamos la palabra clave y limitamos a 3 resultados para no saturar la terminal
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=3"

    try:
        # TÁCTICA DEVSECOPS: Rate Limiting
        # La API del gobierno bloquea a quien hace muchas peticiones seguidas sin una API Key.
        # Le decimos a Python que "respire" 6 segundos antes de consultar para evitar ser baneados.
        time.sleep(6)

        headers = {"User-Agent": "NetAudit-DevSecOps-Project"}
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            datos = response.json()
            vulnerabilidades = []

            # Extraemos los datos de los CVEs encontrados
            for item in datos.get("vulnerabilities", []):
                cve_id = item.get("cve", {}).get("id", "Desconocido")
                descripciones = item.get("cve", {}).get("descriptions", [])
                descripcion = "Sin descripción"

                # Buscamos la descripción en inglés ("en")
                for d in descripciones:
                    if d.get("lang") == "en":
                        descripcion = d.get("value")
                        break

                vulnerabilidades.append({"id": cve_id, "descripcion": descripcion})
            return vulnerabilidades
        else:
            return []
    except Exception as e:
        print(f"[-] Error de conexión con NVD: {e}")
        return []


def analizar_resultados_xml(archivo_xml):
    print("[*] Procesando puertos y analizando vulnerabilidades potenciales...")
    if not os.path.exists(archivo_xml):
        print("[-] No se encontró el archivo de resultados.")
        return

    tree = ET.parse(archivo_xml)
    root = tree.getroot()
    servicios_encontrados = []

    for host in root.findall("host"):
        for ports in host.findall("ports"):
            for port in ports.findall("port"):
                estado = port.find("state").get("state")
                if estado == "open":
                    puerto_num = port.get("portid")
                    protocolo = port.get("protocol")
                    servicio = port.find("service")

                    if servicio is not None:
                        nombre_servicio = servicio.get("name", "Desconocido")
                        producto = servicio.get("product", "")
                        version = servicio.get("version", "")

                        software_completo = f"{producto} {version}".strip()
                        if not software_completo:
                            software_completo = f"Servicio: {nombre_servicio}"
                    else:
                        software_completo = "Desconocido"

                    servicios_encontrados.append(
                        {
                            "puerto": puerto_num,
                            "protocolo": protocolo,
                            "software": software_completo,
                        }
                    )

    # IMPRESIÓN DEL REPORTE FINAL CON VULNERABILIDADES
    print("\n" + "=" * 60)
    print(" REPORTE DE PUERTOS, SERVICIOS Y VULNERABILIDADES (CVEs)")
    print("=" * 60)
    if not servicios_encontrados:
        print("No se encontraron puertos abiertos. El sistema está blindado.")
    else:
        for srv in servicios_encontrados:
            print(
                f"\n [+] Puerto {srv['puerto']}/{srv['protocolo']} -> {srv['software']}"
            )

            # Solo buscamos vulnerabilidades si Nmap logró adivinar la versión exacta
            if "Servicio:" not in srv["software"] and srv["software"] != "Desconocido":
                cves = buscar_vulnerabilidades(srv["software"])
                if cves:
                    print("     ⚠️  Vulnerabilidades conocidas encontradas:")
                    for cve in cves:
                        # Recortamos la descripción a 100 caracteres para no llenar toda la pantalla
                        desc_corta = (
                            cve["descripcion"][:100] + "..."
                            if len(cve["descripcion"]) > 100
                            else cve["descripcion"]
                        )
                        print(f"        - {cve['id']}: {desc_corta}")
                else:
                    print(
                        "     ✅ No se encontraron vulnerabilidades críticas recientes."
                    )
            else:
                print(
                    "     ℹ️  Se necesita la versión exacta del software para buscar vulnerabilidades."
                )
    print("=" * 60 + "\n")


if __name__ == "__main__":
    IP_OBJETIVO = "127.0.0.1"
    xml_generado = ejecutar_escaneo(IP_OBJETIVO)

    if xml_generado:
        analizar_resultados_xml(xml_generado)
