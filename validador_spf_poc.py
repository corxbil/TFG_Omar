import dns.resolver
import ipaddress

def obtener_registro_spf(dominio):
    """Hace una consulta DNS para buscar el registro TXT que empieza por v=spf1"""
    try:
        respuestas = dns.resolver.resolve(dominio, 'TXT')
        for rdata in respuestas:
            texto = rdata.to_text().strip('"')
            if texto.startswith("v=spf1"):
                return texto
    except Exception as e:
        return None
    return None

def validar_ip_en_spf(ip_origen, dominio, saltos_maximos=10, saltos_actuales=0):
    """
    Función recursiva que evalúa si una IP pertenece a las reglas SPF de un dominio.
    Cumple con el RFC 7208: Límite de 10 saltos DNS, validación matemática de CIDR y resolución de 'includes'.
    """
    # 1. PREVENCIÓN DE BUCLES (Límite del estándar RFC)
    if saltos_actuales >= saltos_maximos:
        print(f"{'  ' * saltos_actuales}[-] ERROR: Límite de {saltos_maximos} saltos DNS superado.")
        return False

    print(f"{'  ' * saltos_actuales}[>] Consultando SPF para el dominio: {dominio}")
    registro = obtener_registro_spf(dominio)
    
    if not registro:
        print(f"{'  ' * saltos_actuales}[!] No se encontró registro SPF en {dominio}")
        return False

    print(f"{'  ' * saltos_actuales}[i] Registro encontrado: {registro}")
    
    # Separar las reglas (ej: "v=spf1", "ip4:192.168.1.0/24", "include:microsoft.com", "-all")
    mecanismos = registro.split()[1:] 
    
    # Convertimos la IP en un objeto matemático
    try:
        ip_obj = ipaddress.ip_address(ip_origen)
    except ValueError:
        print("La IP de origen no tiene un formato válido.")
        return False

    for mec in mecanismos:
        # CASO A: REGLA DE RANGO IP (Matemáticas de Subred)
        if mec.startswith("ip4:"):
            rango_ip = mec.split("ip4:")[1]
            
            # Si el administrador del servidor no le puso máscara (ej: ip4:1.1.1.1), asumimos /32 (una sola IP)
            if "/" not in rango_ip:
                rango_ip += "/32"
            
            try:
                # Calculamos matemáticamente si la IP está dentro de la subred (CIDR)
                red = ipaddress.ip_network(rango_ip, strict=False)
                if ip_obj in red:
                    print(f"{'  ' * saltos_actuales}[+] ¡BINGO MATEMÁTICO! La IP {ip_origen} pertenece a la red {red}")
                    return True
            except ValueError:
                pass

        # CASO B: REGLA INCLUDE (La magia de la Recursividad)
        elif mec.startswith("include:"):
            nuevo_dominio = mec.split("include:")[1]
            print(f"{'  ' * saltos_actuales}[⮑] Saltando a incluir las reglas de: {nuevo_dominio} ...")
            
            # ¡La función se llama a sí misma! (Recursividad) sumando 1 al contador de saltos
            if validar_ip_en_spf(ip_origen, nuevo_dominio, saltos_maximos, saltos_actuales + 1):
                return True
                
        # CASO C: REGLA 'A' (Comprueba si la IP es la misma que aloja la web del dominio)
        elif mec == "a":
            try:
                ips_a = dns.resolver.resolve(dominio, 'A')
                for rdata in ips_a:
                    if rdata.to_text() == ip_origen:
                        print(f"{'  ' * saltos_actuales}[+] ¡COINCIDENCIA! La IP corresponde al registro 'A' de {dominio}")
                        return True
            except:
                pass
    
    # Si ha leído todo el registro, ha entrado en los includes, y no ha encontrado coincidencia
    return False

# ==========================================
# ZONA DE PRUEBAS (Simulador)
# ==========================================
if __name__ == "__main__":
    print("🛡️ INICIANDO MOTOR DE VALIDACIÓN SPF (RFC 7208) 🛡️\n")
    
    # CASO PRÁCTICO: Comprobemos si una IP oficial de los servidores de Google 
    # está autorizada para mandar correos en nombre de "google.com"
    ip_sospechosa = "209.85.220.69" 
    dominio_remitente = "google.com" 
    
    print(f"🕵️‍♂️ OBJETIVO: ¿Tiene permiso la IP {ip_sospechosa} para enviar como @{dominio_remitente}?\n")
    
    resultado = validar_ip_en_spf(ip_sospechosa, dominio_remitente)
    
    print("\n================ VEREDICTO ================")
    if resultado:
        print(f"✅ PASS: La IP {ip_sospechosa} ESTÁ AUTORIZADA.")
    else:
        print(f"❌ FAIL: La IP {ip_sospechosa} NO ESTÁ AUTORIZADA. (Alerta Spoofing)")