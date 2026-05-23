import dns.resolver
import ipaddress
import re
import logging

logger = logging.getLogger(__name__)

def obtener_registro_spf(dominio: str) -> str:
    try:
        respuestas = dns.resolver.resolve(dominio, 'TXT')
        for rdata in respuestas:
            texto = rdata.to_text().strip('"')
            if texto.startswith("v=spf1"):
                return texto
    except Exception:
        pass
    return None

def extraer_ip_origen(cabeceras: str) -> str:
    if not cabeceras:
        return None
    match = re.search(r'client-ip=([0-9\.]+)', cabeceras, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def validar_ip_en_spf(ip_origen: str, dominio: str, saltos_maximos=10, saltos_actuales=0) -> bool:
    if saltos_actuales >= saltos_maximos:
        return False
    registro = obtener_registro_spf(dominio)
    if not registro:
        return False
    mecanismos = registro.split()[1:]
    try:
        ip_obj = ipaddress.ip_address(ip_origen)
    except ValueError:
        return False
    for mec in mecanismos:
        if mec.startswith("ip4:"):
            rango_ip = mec.split("ip4:")[1]
            if "/" not in rango_ip:
                rango_ip += "/32"
            try:
                red = ipaddress.ip_network(rango_ip, strict=False)
                if ip_obj in red:
                    return True
            except ValueError:
                pass
        elif mec.startswith("include:"):
            nuevo_dominio = mec.split("include:")[1]
            if validar_ip_en_spf(ip_origen, nuevo_dominio, saltos_maximos, saltos_actuales + 1):
                return True
        elif mec == "a":
            try:
                ips_a = dns.resolver.resolve(dominio, 'A')
                for rdata in ips_a:
                    if rdata.to_text() == ip_origen:
                        return True
            except:
                pass
    return False

def analizar_spf_y_cabeceras(remitente: str, cabeceras: str) -> dict:
    """Orquestador híbrido: Valida SPF matemáticamente y extrae DKIM/DMARC de las cabeceras."""
    resultado = {
        "tiene_spf": False,
        "registro_spf": "No encontrado",
        "estado_spf": "desconocido",
        "estado_dkim": "desconocido",
        "estado_dmarc": "desconocido",
        "es_peligroso": False,
        "detalles": ""
    }
    
    if not remitente or "@" not in remitente:
        resultado["detalles"] = "Remitente inválido."
        return resultado

    dominio = remitente.split("@")[1].strip()
    registro_spf = obtener_registro_spf(dominio)
    
    if registro_spf:
        resultado["tiene_spf"] = True
        resultado["registro_spf"] = registro_spf

    # 1. Validación Matemática SPF
    ip_origen = extraer_ip_origen(cabeceras)
    validacion_matematica = None
    if ip_origen and registro_spf:
        validacion_matematica = validar_ip_en_spf(ip_origen, dominio)

    # 2. Extracción de Autenticaciones desde la cabecera (Authentication-Results)
    if cabeceras:
        match_spf = re.search(r'spf=(pass|fail|softfail|neutral|none)', cabeceras, re.IGNORECASE)
        match_dkim = re.search(r'dkim=(pass|fail|neutral|none|temperror|permerror)', cabeceras, re.IGNORECASE)
        match_dmarc = re.search(r'dmarc=(pass|fail|bestguesspass|none)', cabeceras, re.IGNORECASE)

        estado_header_spf = match_spf.group(1).lower() if match_spf else "none"
        resultado["estado_dkim"] = match_dkim.group(1).lower() if match_dkim else "none"
        resultado["estado_dmarc"] = match_dmarc.group(1).lower() if match_dmarc else "none"
    else:
        estado_header_spf = "none"

    # 3. Lógica de Veredicto SPF
    if validacion_matematica is True:
        resultado["estado_spf"] = "pass"
        resultado["detalles"] = f"SPF (Matemático): PASS para IP {ip_origen}. "
    elif validacion_matematica is False and estado_header_spf not in ["pass"]:
        resultado["estado_spf"] = "fail"
        resultado["es_peligroso"] = True
        resultado["detalles"] = f"SPF: FAIL (La IP {ip_origen} no está autorizada). "
    else:
        resultado["estado_spf"] = estado_header_spf
        resultado["detalles"] = f"SPF: {estado_header_spf.upper()}. "

    # 4. Lógica de Veredicto DKIM y DMARC
    if resultado["estado_dkim"] == "fail":
        resultado["es_peligroso"] = True
        resultado["detalles"] += "| DKIM: FAIL (Firma criptográfica inválida o correo alterado). "
    else:
        resultado["detalles"] += f"| DKIM: {resultado['estado_dkim'].upper()}. "

    if resultado["estado_dmarc"] == "fail":
        resultado["es_peligroso"] = True
        resultado["detalles"] += "| DMARC: FAIL (Identidad no alineada. RIESGO CRÍTICO DE SPOOFING)."
    else:
        resultado["detalles"] += f"| DMARC: {resultado['estado_dmarc'].upper()}."

    if not resultado["tiene_spf"]:
        resultado["detalles"] += " | ALERTA: Dominio sin políticas de seguridad."

    return resultado