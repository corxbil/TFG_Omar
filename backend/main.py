from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional
import logging
import os
import re
import json
import asyncio
from dotenv import load_dotenv

ruta_env = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
load_dotenv(ruta_env)

from modulos.blocklists import verificar_reputacion_total
from modulos.seguridad_email import analizar_spf_y_cabeceras
from modulos.virustotal import analizar_archivo_vt, analizar_url_vt
from modulos.modelo_ia import analizar_texto_ia

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="API Ciberseguridad TFG", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Adjunto(BaseModel):
    nombre: str
    contenido_base64: str

class CorreoRequest(BaseModel):
    texto: str
    remitente: str
    tiene_adjuntos: bool
    adjuntos: Optional[List[Adjunto]] = []
    cabeceras: Optional[str] = ""
    email_usuario: Optional[str] = "" 

@app.post("/api/v1/analizar")
async def analizar_correo(data: CorreoRequest):
    logger.info("==================================================")
    logger.info(f"📩 NUEVO CORREO A ANALIZAR POR STREAMING")
    
    # Creamos un GENERADOR que irá devolviendo resultados capa por capa
    async def generador_analisis():
        try:
            texto_limpio = data.texto if data.texto else ""
            remitente_real = data.remitente if data.remitente else "Desconocido"

            # CAPA 1: OSINT
            logger.info("-> Capa 1: OSINT")
            resultado_osint = verificar_reputacion_total(remitente_real)
            yield json.dumps({"capa": "osint", "datos": resultado_osint}) + "\n"
            await asyncio.sleep(0.1) # Pausa mínima para forzar el envío del paquete por red

            # CAPA 1.5: AUTENTICACIÓN
            logger.info("-> Capa 1.5: Auth")
            cabeceras_raw = data.cabeceras if data.cabeceras else ""
            resultado_spf = analizar_spf_y_cabeceras(remitente_real, cabeceras_raw)
            yield json.dumps({"capa": "auth", "datos": resultado_spf}) + "\n"
            await asyncio.sleep(0.1)

            # CAPA 2: VIRUSTOTAL
            logger.info("-> Capa 2: VirusTotal")
            resultados_vt_archivos = []
            resultados_vt_urls = []
            peligro_vt = False
            
            if data.tiene_adjuntos and data.adjuntos:
                primer_adjunto = data.adjuntos[0] 
                res_vt = analizar_archivo_vt(primer_adjunto.nombre, primer_adjunto.contenido_base64)
                resultados_vt_archivos.append(res_vt)
                if res_vt.get("es_peligroso"):
                    peligro_vt = True

            urls_encontradas = re.findall(r'(https?://[^\s]+)', texto_limpio)
            urls_a_analizar = list(set([u.rstrip('.,;>\'")') for u in urls_encontradas]))[:2] 
            
            for enlace in urls_a_analizar:
                res_url = analizar_url_vt(enlace)
                resultados_vt_urls.append(res_url)
                if res_url.get("es_peligroso"):
                    peligro_vt = True

            yield json.dumps({"capa": "vt", "datos": {"archivos": resultados_vt_archivos, "urls": resultados_vt_urls}}) + "\n"
            await asyncio.sleep(0.1)

            # CAPA 3: IA SEMÁNTICA
            logger.info("-> Capa 3: Llama-3 (Pensando...)")
            resultado_ia = analizar_texto_ia(texto_limpio)
            yield json.dumps({"capa": "ia", "datos": resultado_ia}) + "\n"
            await asyncio.sleep(0.1)

            # VEREDICTO FINAL - El Juez Final Ponderado
            logger.info("-> Calculando Veredicto Ponderado...")
            
            riesgo_total = 0
            
            # 1. Verificar Malware (Capa Técnica - Bloqueo Crítico 100%)
            if peligro_vt:
                veredicto_final = "MALWARE"
                riesgo_total = 100
                color = "ROJO"
                detalles = "BLOQUEO CRÍTICO: VirusTotal ha detectado firmas maliciosas."
            else:
                # 2. Asignación de pesos según la detección
                # 2.1 IA Semántica (50%)
                es_phishing_ia = resultado_ia.get("categoria_texto") == "phishing" or (resultado_ia.get("urgencia") and resultado_ia.get("peticion_sensible"))
                score_ia = 50 if es_phishing_ia else 0
                
                # 2.2 Identidad (20%)
                score_spf = 20 if resultado_spf.get("es_peligroso") else 0
                
                # 2.3 Reputación DNSBL (30%) - Lógica de 1 lista o 2+ listas
                listas_positivas = resultado_osint.get("listas_detectadas", 0) 
                
                if listas_positivas >= 2:
                    score_dnsbl = 30  # 100% del peso de la capa
                elif listas_positivas == 1:
                    score_dnsbl = 15  # 50% del peso de la capa
                else:
                    score_dnsbl = 0
                    
                # Suma base de riesgo
                riesgo_total = score_ia + score_spf + score_dnsbl
                
                # 3. Factor de Confianza (Detección de dominio corporativo interno)
                es_contacto_conocido = False
                
                # Extraemos los dominios (lo que va después de la '@')
                dominio_remitente = remitente_real.split('@')[-1].lower() if '@' in remitente_real else ""
                dominio_usuario = data.email_usuario.split('@')[-1].lower() if data.email_usuario else ""
                
                # Si los dominios coinciden y no están vacíos, es un correo interno
                if dominio_remitente == dominio_usuario and dominio_remitente != "":
                    es_contacto_conocido = True
                    logger.info(f"Remitente corporativo interno detectado (Dominio: {dominio_usuario}). Aplicando multiplicador de confianza.")
                    
                if es_contacto_conocido:
                    riesgo_total = riesgo_total * 0.8  # Multiplicador reductor de confianza
                    
                # 4. Clasificación del riesgo para la interfaz
                if riesgo_total >= 60:
                    veredicto_final = "PHISHING"
                    color = "ROJO"
                    detalles = f"Riesgo crítico de suplantación. Score: {riesgo_total}%. (IA: {score_ia}, Auth: {score_spf}, OSINT: {score_dnsbl})"
                elif riesgo_total >= 20:
                    veredicto_final = "PRECAUCIÓN"
                    color = "AMARILLO"
                    detalles = f"Se han detectado anomalías. Score: {riesgo_total}%. Se recomienda cautela."
                else:
                    veredicto_final = "SEGURO"
                    color = "VERDE"
                    detalles = "El correo ha pasado todos los filtros de seguridad sin levantar alertas."

            # Enviamos el JSON actualizado al frontend
            yield json.dumps({
                "capa": "veredicto", 
                "datos": {
                    "veredicto": veredicto_final, 
                    "score_riesgo": riesgo_total,
                    "color": color,
                    "detalles": detalles
                }
            }) + "\n"

        except Exception as e:
            logger.error(f"❌ Error en streaming: {e}")
            yield json.dumps({"capa": "error", "datos": str(e)}) + "\n"

    # Devolvemos el generador empaquetado como NDJSON (Newline Delimited JSON)
    return StreamingResponse(generador_analisis(), media_type="application/x-ndjson")