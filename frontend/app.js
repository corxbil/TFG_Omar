const BACKEND_URL = "https://overintense-cleo-unwaved.ngrok-free.dev/api/v1/analizar";

Office.onReady((info) => {
    if (info.host === Office.HostType.Outlook) {
        document.getElementById("btn-analizar").addEventListener("click", orquestarAnalisis);
    }
});

async function orquestarAnalisis() {
    const btn = document.getElementById("btn-analizar");
    const consola = document.getElementById("consola");
    
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner"></div> Analizando...';
    consola.style.display = "block";
    consola.style.borderLeftColor = "#ccc";

    // CREAMOS EL "ESQUELETO" VISUAL (Las cajas en estado de espera)
    consola.innerHTML = `
        <div id="veredicto-box" style="text-align: center; margin-bottom: 15px;">
            <span style="font-size: 16px; font-weight:bold; color: #555;">⏳ Analizando en tiempo real...</span><br>
            <span style="font-size: 12px; color: #888;">Por favor, no cierre el panel.</span>
        </div>
        <div id="box-osint" style="margin-bottom: 10px; padding: 10px; background: #fafafa; border: 1px dashed #ccc; border-radius: 4px; color: #888; font-size: 12px;">
            ⏳ <b>Capa 1:</b> Consultando reputación del remitente (OSINT)...
        </div>
        <div id="box-auth" style="margin-bottom: 10px; padding: 10px; background: #fafafa; border: 1px dashed #ccc; border-radius: 4px; color: #888; font-size: 12px;">
            ⏳ <b>Capa 1.5:</b> A la espera de OSINT para validar SPF/DKIM/DMARC...
        </div>
        <div id="box-vt" style="margin-bottom: 10px; padding: 10px; background: #fafafa; border: 1px dashed #ccc; border-radius: 4px; color: #888; font-size: 12px;">
            ⏳ <b>Capa 2:</b> A la espera de la Autenticación para escanear Malware...
        </div>
        <div id="box-ia" style="margin-bottom: 10px; padding: 10px; background: #fafafa; border: 1px dashed #ccc; border-radius: 4px; color: #888; font-size: 12px;">
            ⏳ <b>Capa 3:</b> A la espera para iniciar Análisis Semántico (Llama-3)...
        </div>
    `;

    try {
        const texto = await obtenerTextoAsync();
        const remitente = Office.context.mailbox.item.from.emailAddress;

        // Obtener el email del usuario actual (la posible víctima)
        const emailUsuario = Office.context.mailbox.userProfile.emailAddress;
        
        // OBTENER CABECERAS PARA EL SPF
        const cabeceras = await obtenerCabecerasAsync();

        // LÓGICA DE ADJUNTOS
        const adjuntosOutlook = Office.context.mailbox.item.attachments;
        const tieneAdjuntos = adjuntosOutlook.length > 0;
        let listaAdjuntosParaPython = [];

        if (tieneAdjuntos) {
            const primerAdjunto = adjuntosOutlook[0];
            const contenidoBase64 = await obtenerAdjuntoBase64Async(primerAdjunto.id);
            listaAdjuntosParaPython.push({ nombre: primerAdjunto.name, contenido_base64: contenidoBase64 });
        }

        const respuesta = await fetch(BACKEND_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                texto: texto, 
                remitente: remitente, 
                tiene_adjuntos: tieneAdjuntos,
                adjuntos: listaAdjuntosParaPython,
                cabeceras: cabeceras,
                email_usuario: emailUsuario 
            })
        });

        if (!respuesta.ok) {
            throw new Error(`Error HTTP: ${respuesta.status}`);
        }
        
        // LECTOR DE STREAM (SSE)
        const reader = respuesta.body.getReader();
        const decoder = new TextDecoder("utf-8");
        let buffer = "";

        while (true) {
            const { value, done } = await reader.read();
            
            // 1. Decodificamos el nuevo trozo de forma segura
            if (value) {
                buffer += decoder.decode(value, { stream: true });
            }
            
            // 2. Buscamos y extraemos todas las líneas completas
            let partes = buffer.split('\n');
            
            // 3. El último elemento del split() SIEMPRE es lo que queda sin salto de línea
            // Así que lo sacamos del array y lo guardamos de vuelta en el buffer para la siguiente ronda
            buffer = partes.pop(); 
            
            // 4. Procesamos los JSONs que sí están completos
            for (let parte of partes) {
                if (parte.trim() !== "") {
                    try {
                        const chunk = JSON.parse(parte);
                        pintarCapaEnVivo(chunk.capa, chunk.datos);
                    } catch (e) {
                        console.error("❌ Error aislando JSON:", parte, e);
                    }
                }
            }
            
            // 5. Salimos del bucle si el servidor dice que ya ha terminado
            if (done) break;
        }

    } catch (error) {
        console.error(error);
        document.getElementById("consola").style.borderLeftColor = "#D83B01";
        document.getElementById("veredicto-box").innerHTML = `<b>Error Crítico:</b> <small>${error.message}</small><br><i style="font-size:10px;">Compruebe que ngrok y el backend de Python están encendidos.</i>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = "Analizar Correo";
    }
}

// FUNCIÓN PARA PINTAR LAS CAJAS DINÁMICAMENTE
function pintarCapaEnVivo(capa, datos) {
    if (capa === "osint") {
        document.getElementById("box-auth").innerHTML = "⏳ <b>Capa 1.5:</b> Verificando criptografía y SPF...";
        
        const getIcon = (isListed) => isListed ? "🔴" : "🟢";
        const getColor = (isListed) => isListed ? "#D83B01" : "#107C10";

        document.getElementById("box-osint").outerHTML = `
            <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <b style="font-size: 11px; color: #555;">📍 CAPA 1: OSINT (REPUTACIÓN RED)</b><br>
                <span style="color: ${getColor(datos.spamhaus)};">${getIcon(datos.spamhaus)} Spamhaus DBL</span><br>
                <span style="color: ${getColor(datos.spamcop)};">${getIcon(datos.spamcop)} SpamCop</span><br>
                <span style="color: ${getColor(datos.psbl)};">${getIcon(datos.psbl)} PSBL</span>
            </div>`;
    } 
    else if (capa === "auth") {
        document.getElementById("box-vt").innerHTML = "⏳ <b>Capa 2:</b> Subiendo adjuntos y URLs a VirusTotal...";
        
        const getAuthStyle = (estado) => {
            if (estado === "pass" || estado === "bestguesspass") return { color: "#107C10", icon: "🟢" };
            if (estado === "fail" || estado === "permerror") return { color: "#D83B01", icon: "🔴" };
            return { color: "#FFB900", icon: "⚠️" };
        };

        const spfStyle = getAuthStyle(datos.estado_spf);
        const dkimStyle = getAuthStyle(datos.estado_dkim);
        const dmarcStyle = getAuthStyle(datos.estado_dmarc);
        
        document.getElementById("box-auth").outerHTML = `
            <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <b style="font-size: 11px; color: #555;">🔐 CAPA 1.5: AUTENTICACIÓN (ANTI-SPOOFING)</b><br>
                <table style="width: 100%; font-size: 12px; margin-top: 5px;">
                    <tr>
                        <td><b>SPF:</b></td>
                        <td style="color: ${spfStyle.color};">${spfStyle.icon} ${datos.estado_spf.toUpperCase()}</td>
                    </tr>
                    <tr>
                        <td><b>DKIM:</b></td>
                        <td style="color: ${dkimStyle.color};">${dkimStyle.icon} ${datos.estado_dkim.toUpperCase()}</td>
                    </tr>
                    <tr>
                        <td><b>DMARC:</b></td>
                        <td style="color: ${dmarcStyle.color};">${dmarcStyle.icon} ${datos.estado_dmarc.toUpperCase()}</td>
                    </tr>
                </table>
                <hr style="border:0; border-top:1px solid #eee; margin: 5px 0;">
                <i style="font-size: 11px; color: #666;">${datos.detalles}</i>
            </div>`;
    }
    else if (capa === "vt") {
        document.getElementById("box-ia").innerHTML = "⏳ <b>Capa 3:</b> Despertando a Llama-3. Analizando semántica... (Tomará unos segundos)";
        
        let vtDetails = "";
        let hasVtData = false;

        // Mostrar resultados de Archivos
        if (datos.archivos && datos.archivos.length > 0) {
            hasVtData = true;
            let vt = datos.archivos[0]; 
            if (vt.error) {
                vtDetails += `<b>Adjunto:</b> ⚠️ Error de conexión.<br>`;
            } else if (vt.analizado) {
                let colorVT = vt.es_peligroso ? "#D83B01" : "#107C10";
                let icono = vt.es_peligroso ? "🔴" : "🟢";
                vtDetails += `<b>Adjunto:</b> <span style="color:${colorVT}; font-weight:bold;">${icono} ${vt.maliciosos}/${vt.total_motores} motores alertan malware</span><br>`;
            } else {
                vtDetails += `<b>Adjunto:</b> ⏳ ${vt.mensaje}<br>`;
            }
        }

        // Mostrar resultados de URLs
        if (datos.urls && datos.urls.length > 0) {
            hasVtData = true;
            datos.urls.forEach(urlRes => {
                let urlCortada = urlRes.url.length > 50 ? urlRes.url.substring(0, 50) + '...' : urlRes.url;
                
                if (urlRes.error) {
                    vtDetails += `
                        <div style="word-break: break-all; margin-top: 4px;">
                            <b style="color: #666;">Enlace:</b> ⚠️ Error al escanear <br>
                            <small style="color: #888;">${urlCortada}</small>
                        </div>`;
                } else if (urlRes.analizado) {
                    let colorVT = urlRes.es_peligroso ? "#D83B01" : "#107C10";
                    let icono = urlRes.es_peligroso ? "🔴" : "🟢";
                    vtDetails += `
                        <div style="word-break: break-all; margin-top: 4px;">
                            <b style="color: #666;">Enlace:</b> <span style="color:${colorVT}; font-weight:bold;">${icono} ${urlRes.maliciosos}/${urlRes.total_motores} motores</span><br>
                            <small style="color: #888;">${urlCortada}</small>
                        </div>`;
                } else {
                    vtDetails += `
                        <div style="word-break: break-all; margin-top: 4px;">
                            <b style="color: #666;">Enlace:</b> ⏳ En cola / Desconocida <br>
                            <small style="color: #888;">${urlCortada}</small>
                        </div>`;
                }
            });
        }

        if (!hasVtData) {
            vtDetails = "Sin adjuntos ni enlaces sospechosos para analizar.";
        }

        document.getElementById("box-vt").outerHTML = `
            <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <b style="font-size: 11px; color: #555;">🦠 CAPA 2: VIRUSTOTAL (MALWARE Y ENLACES)</b><br>
                ${vtDetails}
            </div>`;
    }
    else if (capa === "ia") {
        const getIaIcon = (flag) => flag ? "🔴 Sí" : "🟢 No";
        
        let contenidoIA = "";
        if (datos.error) {
            contenidoIA = `<span style="color:#D83B01;">⚠️ ${datos.error}</span>`;
        } else {
            contenidoIA = `
                <b>Urgencia detectada:</b> ${getIaIcon(datos.urgencia)}<br>
                <b>Petición sensible:</b> ${getIaIcon(datos.peticion_sensible)}<br>
                <hr style="border:0; border-top:1px solid #eee; margin: 5px 0;">
                <b>Intención:</b> <span style="font-size: 12px;">${datos.intencion_detectada || 'N/A'}</span><br>
                <b>Justificación:</b> <i style="font-size: 12px; color: #666;">"${datos.justificacion || 'Sin justificación'}"</i>
            `;
        }

        document.getElementById("box-ia").outerHTML = `
            <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <b style="font-size: 11px; color: #555;">🧠 CAPA 3: ANÁLISIS SEMÁNTICO (LLAMA-3)</b><br>
                ${contenidoIA}
            </div>`;
    }
    else if (capa === "veredicto") {
        let colorFondo = "#107C10"; // Verde por defecto
        let colorTexto = "white";
        
        // Usamos el color enviado por el Juez Final
        if (datos.color === "ROJO") {
            colorFondo = "#D83B01"; // Rojo oscuro
            colorTexto = "white";
        } else if (datos.color === "AMARILLO") {
            colorFondo = "#FFB900"; // Amarillo
            colorTexto = "black";
        }
        
        document.getElementById("consola").style.borderLeftColor = colorFondo;
        
        document.getElementById("veredicto-box").innerHTML = `
            <div style="background-color: ${colorFondo}; color: ${colorTexto}; padding: 10px; border-radius: 4px; text-align: center; margin-bottom: 15px;">
                <span style="font-size: 18px; font-weight:bold;">${datos.veredicto}</span><br>
                <span style="font-size: 12px;">Índice de Riesgo: ${datos.score_riesgo}%</span>
            </div>
            <div style="font-size: 12px; margin-bottom: 15px; text-align: justify;">
                <b>Detalle:</b> ${datos.detalles}
            </div>`;
    }
    else if (capa === "error") {
        document.getElementById("veredicto-box").innerHTML = `<b>Error Interno:</b> <small>${datos}</small>`;
    }
}

// Helpers originales
function obtenerCabecerasAsync() {
    return new Promise((resolve) => {
        if (Office.context.mailbox.item.getAllInternetHeadersAsync) {
            Office.context.mailbox.item.getAllInternetHeadersAsync((result) => resolve(result.status === Office.AsyncResultStatus.Succeeded ? result.value : ""));
        } else resolve(""); 
    });
}
function obtenerTextoAsync() {
    return new Promise((resolve, reject) => {
        Office.context.mailbox.item.body.getAsync(Office.CoercionType.Text, (result) => result.status === Office.AsyncResultStatus.Failed ? reject(new Error(result.error.message)) : resolve(result.value));
    });
}
function obtenerAdjuntoBase64Async(attachmentId) {
    return new Promise((resolve, reject) => {
        Office.context.mailbox.item.getAttachmentContentAsync(attachmentId, (result) => result.status === Office.AsyncResultStatus.Failed ? reject(new Error(result.error.message)) : resolve(result.value.content));
    });
}