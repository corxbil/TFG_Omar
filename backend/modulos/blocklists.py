import dns.resolver
import logging

logger = logging.getLogger(__name__)

def verificar_reputacion_total(email: str) -> dict:
    """
    Consulta el dominio y su IP asociada en Spamhaus, SpamCop y PSBL.
    """
    if not email or "@" not in email:
        return {"es_peligroso": False, "detalles": "Remitente inválido"}

    dominio = email.split("@")[1].strip()
    
    # Diccionario para guardar los resultados de cada motor
    resultados = {
        "spamhaus": False,
        "spamcop": False,
        "psbl": False,
        "es_peligroso": False,
        "mensajes": []
    }

    # 1. CONSULTA A SPAMHAUS (Por Dominio)

    try:
        dns.resolver.resolve(f"{dominio}.dbl.spamhaus.org", 'A')
        resultados["spamhaus"] = True
        resultados["mensajes"].append("Spamhaus: Dominio detectado en lista negra.")
    except Exception:
        pass # Si da error (NXDOMAIN), es que está limpio


    # 2. OBTENER LA IP DEL DOMINIO
    ips = []
    try:
        respuestas_ip = dns.resolver.resolve(dominio, 'A')
        ips = [str(ip) for ip in respuestas_ip]
    except Exception as e:
        logger.warning(f"No se pudo resolver la IP de {dominio}: {e}")

    # 3. CONSULTAS A SPAMCOP Y PSBL (Por IP)
    for ip in ips:
        # Para consultar DNSBL por IP, hay que invertir el orden de los números
        # Ej: 192.168.1.5 -> 5.1.168.192
        ip_invertida = '.'.join(reversed(ip.split('.')))

        # SpamCop
        try:
            dns.resolver.resolve(f"{ip_invertida}.bl.spamcop.net", 'A')
            resultados["spamcop"] = True
            resultados["mensajes"].append(f"SpamCop: La IP {ip} del servidor está listada.")
        except Exception:
            pass

        # PSBL
        try:
            dns.resolver.resolve(f"{ip_invertida}.psbl.surriel.com", 'A')
            resultados["psbl"] = True
            resultados["mensajes"].append(f"PSBL: La IP {ip} del servidor está listada.")
        except Exception:
            pass

    # 4. VEREDICTO FINAL
    # Contamos cuántas listas han dado positivo
    listas_detectadas = sum([resultados["spamhaus"], resultados["spamcop"], resultados["psbl"]])
    resultados["listas_detectadas"] = listas_detectadas

    # Si CUALQUIERA de las tres listas dice que es malo, levantamos la alerta general (para compatibilidad)
    resultados["es_peligroso"] = listas_detectadas > 0
    
    if not resultados["es_peligroso"]:
        resultados["mensajes"].append("El remitente está limpio en Spamhaus, SpamCop y PSBL.")
    else:
        resultados["mensajes"].append(f"Listado en {listas_detectadas} de 3 listas.")
        
    logger.info(f"Reporte OSINT para {dominio}: Spamhaus={resultados['spamhaus']}, SpamCop={resultados['spamcop']}, PSBL={resultados['psbl']}, Total_Listas={listas_detectadas}")
    
    return resultados