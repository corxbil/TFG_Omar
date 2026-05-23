import os
import requests
import base64
import hashlib
import logging
import time

logger = logging.getLogger(__name__)

def analizar_archivo_vt(nombre_archivo: str, contenido_base64: str) -> dict:
    """ Sube un archivo a VirusTotal calculando su Hash primero (Lógica original segura) """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": True, "mensaje": "API Key de VirusTotal no configurada."}

    try:
        # 1. Decodificamos el archivo en MEMORIA
        archivo_bytes = base64.b64decode(contenido_base64)
        
        # 2. Calculamos el Hash SHA-256 (La "huella dactilar" matemática)
        sha256_hash = hashlib.sha256(archivo_bytes).hexdigest()
        logger.info(f"🔍 Hash del archivo '{nombre_archivo}': {sha256_hash}")

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        # 3. Preguntamos a VirusTotal si YA CONOCE este Hash
        url_hash = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        logger.info("Consultando reporte del archivo en VirusTotal...")
        res_hash = requests.get(url_hash, headers=headers)

        if res_hash.status_code == 200:
            # Si lo conoce, Extraemos las estadísticas exactas
            stats = res_hash.json()["data"]["attributes"].get("last_analysis_stats", {})
            maliciosos = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total_motores = sum(stats.values())
            
            # LÓGICA ANTI 0/0 (Protección asincronía)
            if total_motores == 0:
                logger.info("El archivo está en VT pero el análisis aún no ha terminado (0 motores).")
                return {
                    "analizado": False,
                    "es_peligroso": False,
                    "mensaje": "En cola de escaneo. Analice de nuevo en unos segundos."
                }
            
            es_peligroso = maliciosos > 0
            logger.info(f"Reporte VT: {maliciosos}/{total_motores} motores lo detectan como malware.")
            
            return {
                "analizado": True,
                "es_peligroso": es_peligroso,
                "maliciosos": maliciosos,
                "total_motores": total_motores,
                "mensaje": f"{maliciosos} de {total_motores} antivirus detectan amenaza."
            }

        elif res_hash.status_code == 404:
            # 4. No lo conoce. Lo subimos a la cola de análisis
            logger.info("Archivo desconocido para VT. Procediendo a subirlo...")
            url_upload = "https://www.virustotal.com/api/v3/files"
            files = { "file": (nombre_archivo, archivo_bytes) }
            res_upload = requests.post(url_upload, headers=headers, files=files)

            if res_upload.status_code == 200:
                return {
                    "analizado": False,
                    "es_peligroso": False, 
                    "mensaje": "Archivo nuevo. Subido a VirusTotal (Pendiente de análisis)."
                }
            else:
                return {"error": True, "mensaje": f"Fallo al subir: {res_upload.status_code}"}
        else:
            return {"error": True, "mensaje": f"Error API VT: {res_hash.status_code}"}

    except Exception as e:
        logger.error(f"Error analizando archivo en VT: {e}")
        return {"error": True, "mensaje": str(e)}

def analizar_url_vt(url: str) -> dict:
    """ Envía una URL a VT. Sin esperas bloqueantes (Ideal para Streaming) """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": True, "mensaje": "API Key de VirusTotal no configurada."}

    headers_get = {"x-apikey": api_key}
    
    try:
        # 1. En lugar de hacer POST primero, Hacemos GET de la URL codificada
        # Así, si ya la conoce (el 99% de las veces en phishings reales), respondemos al instante
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers_get)
        
        if report_res.status_code == 200:
            stats = report_res.json()["data"]["attributes"]["last_analysis_stats"]
            maliciosos = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            
            if total == 0:
                return {"url": url, "analizado": False, "es_peligroso": False, "mensaje": "En cola de escaneo."}
                
            return {
                "url": url,
                "analizado": True,
                "es_peligroso": maliciosos > 0,
                "maliciosos": maliciosos,
                "total_motores": total,
                "mensaje": "OK"
            }
            
        elif report_res.status_code == 404:
            # 2. Si no la conoce (404), la subimos a VT y NO ESPERAMOS. 
            # Devolvemos el control inmediatamente a FastAPI para que siga el streaming.
            headers_post = {
                "x-apikey": api_key,
                "Content-Type": "application/x-www-form-urlencoded"
            }
            scan_res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers_post, data={"url": url})
            
            if scan_res.status_code == 200:
                logger.info(f"URL nueva '{url}' enviada a VT con éxito. Pendiente de motores.")
                return {"url": url, "analizado": False, "es_peligroso": False, "mensaje": "URL nueva enviada a escanear."}
            else:
                 return {"url": url, "error": True, "mensaje": f"Fallo al enviar URL: {scan_res.status_code}"}
                 
        elif report_res.status_code == 429:
             return {"url": url, "error": True, "mensaje": "Límite de API excedido."}
        else:
            return {"url": url, "error": True, "mensaje": f"Error HTTP {report_res.status_code}"}
            
    except Exception as e:
        logger.error(f"Error analizando URL en VT: {e}")
        return {"url": url, "error": True, "mensaje": str(e)}