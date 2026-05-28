import subprocess
import xml.etree.ElementTree as ET
import os

def ejecutar_escaneo(target_ip):
    """
    Ejecuta un escaneo de Nmap contra la IP objetivo.
    -sV: Intenta determinar la versión exacta de los servicios.
    -oX: Exporta el resultado en formato XML para que Python lo lea fácilmente.
    --top-ports 100: Escanea los 100 puertos más comunes para que sea rápido.
    """
    print(f"[*] Iniciando escaneo de seguridad sobre {target_ip}...")
    archivo_salida = "scan_result.xml"

    # Constucción comando terminal.
    comando = ["nmap", "-sV", "--top-ports", "100", "-oX", archivo_salida, target_ip]

    try:
        # subprocess.run -> para ejecutar comandos del sistema operativo.
        subprocess.run(comando, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[*] Escaneo completado. Archivo de datos generado con éxito.")
        return archivo_salida
    except subprocess.CalledProcessError as e:
        print(f"[*] Error al ejecutar Nmap: {e}")
        return None
    except FileNotFoundError:
        print("[-] Error crítico: Nmap no está instalado en el sistema.")
        return None
    
def analizar_resultados_xml(archivo_xml):
    """
    Abre el archivo XML generado por Nmap, extrae la paja y se queda solo con los 
    puertos abiertos y sus versiones de software.
    """
    print("[*] Analizando vulnerabilidades potenciales...")
    if not os.path.exists(archivo_xml):
        print("[-] No se encontró el archivo de resultados")
        return
    
    # Parseamos el árbol de datos XML.
    tree = ET.parse(archivo_xml)
    root = tree.getroot()

    servicios_encontrados = []

    # Buscamos en el XML buscando: host -> ports -> port
    for host in root.findall('host'):
        for ports in host.findall('ports'):
            for port in ports.findall('port'):
                estado = port.find('state').get('state')

                # Sólo interesan las puertas que están abiertas.
                if estado == 'open':
                    puerto_num = port.get('portid')
                    protocolo = port.get('protocol')

                    # Buscamos qué programa está escuchando detrás de esa puerta.
                    # Buscamos qué programa está escuchando detrás de esa puerta
                    servicio = port.find('service')
                    if servicio is not None:
                        nombre_servicio = servicio.get('name', 'Desconocido')
                        # Usamos .get('atributo', 'valor_por_defecto') para evitar los "None"
                        producto = servicio.get('product', '')
                        version = servicio.get('version', '')
                        
                        software_completo = f"{producto} {version}".strip()
                        # Si no hay producto ni versión, mostramos al menos el nombre del servicio
                        if not software_completo:
                            software_completo = f"Servicio: {nombre_servicio}"
                    else:
                        software_completo = "Servicio Desconocido"

                    servicios_encontrados.append({
                        "puerto": puerto_num,
                        "protocolo": protocolo,
                        "software": software_completo
                    })

    # Imprimimos el reporte final.
    print("\n" + "="*40)
    print(" REPORTE DE PUERTOS Y SERVICIOS ACTIVOS")
    print("="*40)
    if not servicios_encontrados:
        print("No se encontraron puertos abiertos. El sistema está blindado.")
    else:
        for srv in servicios_encontrados:
            print(f" [+] Puerto {srv['puerto']}/{srv['protocolo']} -> {srv['software']}")
    print("="*40 + "\n")

if __name__ == "__main__":
    IP_OBJETIVO = "127.0.0.1"
    
    xml_generado = ejecutar_escaneo(IP_OBJETIVO)
    
    if xml_generado:
        analizar_resultados_xml(xml_generado)