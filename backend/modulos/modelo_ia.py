import os
import json
import logging
from llama_cpp import Llama

logger = logging.getLogger(__name__)

# CONFIGURACIÓN DEL MODELO LOCAL
NOMBRE_MODELO = "llama-3-8b.Q4_K_M.gguf" 
RUTA_MODELO = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modelos", NOMBRE_MODELO)

# Variable global para mantener el modelo cargado en memoria RAM
llm = None

def cargar_modelo():
    """Carga el modelo GGUF en memoria solo la primera vez que se necesita (Lazy Loading)"""
    global llm
    if llm is None:
        if not os.path.exists(RUTA_MODELO):
            logger.error(f"ARCHIVO NO ENCONTRADO: No se encontró el modelo de IA en: {RUTA_MODELO}")
            logger.error("Por favor, descarga el archivo .gguf y mételo en la carpeta 'backend/modelos/'")
            return False
        
        logger.info("Cargando modelo de Inteligencia Artificial en memoria, puede tomará unos segundos")
        try:
            llm = Llama(
                model_path=RUTA_MODELO,
                n_ctx=1024,
                n_threads=4,  # Usa 4 hilos de tu procesador
                verbose=False # Silencia los logs técnicos de C++
            )
            logger.info("¡Modelo IA cargado con éxito y listo para analizar!")
            return True
        except Exception as e:
            logger.error(f"Error al cargar el modelo: {e}")
            return False
    return True

def analizar_texto_ia(texto_correo: str) -> dict:
    """
    Toma el texto del correo, se lo pasa al modelo Llama-3 local y devuelve un JSON estructurado.
    """
    if not texto_correo or len(texto_correo.strip()) < 5:
        return {"error": "Texto vacío o demasiado corto para analizar."}

    if not cargar_modelo():
        return {
            "error": "El modelo de IA no está disponible.",
            "categoria_texto": "desconocido"
        }

    # 1. El prompt exacto con el que entrenamos al modelo
    instruccion = """Eres un analista experto en ciberseguridad. Voy a darte el texto de un correo electrónico.
Tu trabajo es analizarlo y devolver ÚNICAMENTE un objeto JSON válido con esta estructura exacta, sin texto adicional:
{
  "urgencia": true/false,
  "peticion_sensible": true/false,
  "intencion_detectada": "breve descripción de lo que busca el remitente",
  "categoria_texto": "phishing" o "seguro",
  "justificacion": "explicación en menos de 15 palabras"
}"""

    prompt_entrenamiento = f"""A continuación hay una instrucción que describe una tarea, junto con una entrada que proporciona más contexto. Escribe una respuesta que complete adecuadamente la petición.

### Instrucción:
{instruccion}

### Entrada:
{texto_correo[:1500]} 

### Respuesta:
"""

    logger.info("Analizando la semántica del correo con Llama-3 (Local)...")
    try:
        # 2. Inferencia (Hacer pensar a la IA)
        respuesta = llm(
            prompt_entrenamiento,
            max_tokens=250,  # Límite de palabras para el JSON de salida
            temperature=0.1, # Creatividad casi a cero para que sea determinista
            stop=["<|end_of_text|>", "</s>", "###"] # Cuándo debe callarse
        )
        
        # 3. Limpiar y extraer la respuesta
        texto_generado = respuesta["choices"][0]["text"].strip()
        
        # Buscamos las llaves del JSON por si la IA ha escrito texto extra alrededor
        inicio_json = texto_generado.find('{')
        fin_json = texto_generado.rfind('}')
        
        if inicio_json != -1 and fin_json != -1:
            json_puro = texto_generado[inicio_json:fin_json+1]
            resultado_json = json.loads(json_puro)
            return resultado_json
        else:
            logger.warning("El modelo no devolvió un formato JSON válido.")
            return {"error": "Formato de respuesta inválido.", "raw_text": texto_generado}
            
    except Exception as e:
        logger.error(f"Error en la inferencia del modelo: {e}")
        return {"error": str(e)}