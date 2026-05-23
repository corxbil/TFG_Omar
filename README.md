# Orquestador de Ciberseguridad para Outlook (TFG)

Este proyecto es un complemento (Add-in) para Microsoft Outlook diseñado para detectar amenazas en tiempo real. Utiliza un enfoque multicapa (Ensemble) combinando Inteligencia de Amenazas (OSINT), análisis estático de malware, validación de protocolos de autenticación y Procesamiento de Lenguaje Natural (PLN) mediante un LLM ejecutado en local.

## Arquitectura de Detección (Filtro Multicapa)

La herramienta evalúa cada correo electrónico pasando por cuatro fases críticas:

1. **Capa OSINT (Reputación de Red):** - Extrae el dominio/IP del remitente y realiza consultas DNS inversas a **Spamhaus DBL**, **SpamCop** y **PSBL**. Detecta envíos desde servidores catalogados como emisores de Spam.
2. **Capa de Autenticación Híbrida (SPF y Spoofing):**
   - **Motor Matemático Custom:** Extrae la IP original del remitente (RegEx) y realiza una validación recursiva del protocolo SPF (RFC 7208) con resolución de rangos CIDR y control de saltos (`include:`).
   - **Fallback a Cabeceras:** Parsea la etiqueta `Authentication-Results` del Mail Transfer Agent (MTA) para prevenir falsos positivos en ecosistemas de correo complejos.
3. **Capa de Análisis de Malware:**
   - Extrae los archivos adjuntos (en Base64) y consulta la API de **VirusTotal** para evaluarlos contra más de 70 motores antivirus simultáneos.
4. **Capa Semántica (LLM Local Fine-Tuned):**
   - Utiliza un modelo **Llama-3 cuantizado (GGUF)**, entrenado específicamente (Fine-Tuning con método LoRA) usando un dataset balanceado de ataques.
   - Detecta tácticas de Ingeniería Social, sentido de urgencia y peticiones de datos sensibles de manera **100% offline y privada**.

---

## Guía de Instalación y Despliegue

### 1. Clonar el repositorio
```bash
git clone <https://github.com/MrOmarxD/TFG>
cd <nombre_de_la_carpeta>

2. Preparar el Modelo de Inteligencia Artificial
Descarga el archivo del modelo (formato .gguf) proporcionado en la memoria del TFG.

Crea una carpeta llamada modelos dentro del directorio backend/.

Introduce el archivo .gguf dentro de backend/modelos/.

3. Configurar Variables de Entorno
Crea tu archivo de variables de entorno copiando la plantilla proporcionada:

Bash
cp .env.example .env
Abre el archivo .env e introduce tu API Key de VirusTotal.

4. Instalar Dependencias
Se requiere Python 3.10 o superior. (Nota para Windows: La instalación de llama-cpp-python requiere C++ Build Tools o un wheel precompilado).

Bash
cd backend
pip install -r requirements.txt
5. Ejecutar el Servidor (Backend)
Bash
uvicorn main:app --reload
El servidor se iniciará en http://localhost:8000.

6. Ejecutar el Cliente (Frontend / Add-in)
Para cargar la interfaz en Microsoft Outlook:

Sube el frontend mediante un túnel seguro (Ej: ngrok http 8000).

Actualiza los manifiestos XML y URLs en los archivos app.js e index.html.

Carga el Add-in lateralmente (Sideloading) en Outlook Web o de Escritorio.