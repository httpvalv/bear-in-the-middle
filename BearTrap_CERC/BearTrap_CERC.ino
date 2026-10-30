#include <WiFi.h>
#include <AsyncUDP.h>
#include <WebServer.h>

const char *SSID_DEMO = "BEAR_TRAP_DEMO";
const char *CLAVE_DEMO = "Bear2026!";

AsyncUDP dnsUdp;
WebServer server(80);
bool dnsActivo = false;
uint8_t ipLocal[4] = {192, 168, 4, 1};

// El callback DNS se ejecuta en una tarea diferente de loop().
// Protegemos exclusivamente el acceso a los contadores.
portMUX_TYPE dnsMux = portMUX_INITIALIZER_UNLOCKED;
struct ContadoresDNS {
  uint32_t recibidos = 0;
  uint32_t tipoA = 0;
  uint32_t tipoAAAA = 0;
  uint32_t otrosTipos = 0;
  uint32_t respuestasIPv4 = 0;
  uint32_t respuestasSinIPv4 = 0;
  uint32_t invalidos = 0;
};
ContadoresDNS dnsEstadisticas;

unsigned long totalPortalHTTP = 0;
unsigned long ultimaRevision = 0;
unsigned long ultimoLogPortal = 0;
unsigned long ultimoResumenDNS = 0;
uint8_t clientesAnteriores = 0;

struct Evento { unsigned long segundos; const char *mensaje; };
const uint8_t MAX_EVENTOS = 10;
Evento eventos[MAX_EVENTOS];
uint8_t proximoEvento = 0, cantidadEventos = 0;

void registrarEvento(const char *mensaje) {
  eventos[proximoEvento] = {millis() / 1000UL, mensaje};
  proximoEvento = (proximoEvento + 1) % MAX_EVENTOS;
  if (cantidadEventos < MAX_EVENTOS) cantidadEventos++;
}

ContadoresDNS snapshotDNS() {
  ContadoresDNS salida;
  portENTER_CRITICAL(&dnsMux);
  salida = dnsEstadisticas;
  portEXIT_CRITICAL(&dnsMux);
  return salida;
}

// Se responde a A y ANY con la IP del ESP32. A AAAA y otros tipos:

void atenderDNS(AsyncUDPPacket &paquete) {
  const uint8_t *p = paquete.data();
  size_t n = paquete.length();

  // Solo contar solicitudes (QR=0); omitir respuestas ajenas.
  if (n >= 3 && (p[2] & 0x80)) return;
  portENTER_CRITICAL(&dnsMux);
  dnsEstadisticas.recibidos++;
  portEXIT_CRITICAL(&dnsMux);


  bool valido = n >= 17 && n <= 512;
  if (valido) {
    uint16_t preguntas = (uint16_t(p[4]) << 8) | p[5];
    uint16_t respuestas = (uint16_t(p[6]) << 8) | p[7];
    uint16_t autoridad = (uint16_t(p[8]) << 8) | p[9];
    // QR debe ser 0, OPCODE debe ser 0.
    valido = ((p[2] & 0xF8) == 0) && preguntas == 1 &&
             respuestas == 0 && autoridad == 0;
  }

  size_t finPregunta = 12;
  if (valido) {
    // Saltar los labels de QNAME sin leer ni almacenar su contenido.
    size_t longitudNombre = 0;
    while (true) {
      if (finPregunta >= n) { valido = false; break; }
      uint8_t longitud = p[finPregunta++];
      if (longitud == 0) break;

      if (longitud > 63 || longitudNombre + longitud + 1 > 255 ||
          finPregunta + longitud > n) { valido = false; break; }
      longitudNombre += longitud + 1;
      finPregunta += longitud;
    }
    if (valido) valido = (finPregunta + 4 <= n);
  }

  if (!valido) {
    portENTER_CRITICAL(&dnsMux);
    dnsEstadisticas.invalidos++;
    portEXIT_CRITICAL(&dnsMux);
    return;
  }

  uint16_t tipo = (uint16_t(p[finPregunta]) << 8) | p[finPregunta + 1];
  uint16_t clase = (uint16_t(p[finPregunta + 2]) << 8) | p[finPregunta + 3];
  size_t longitudPregunta = finPregunta + 4 - 12;
  bool ipv4 = (clase == 1 && (tipo == 1 || tipo == 255));

  // Construir una respuesta DNS con tamaño fijo acotado.
  uint8_t respuesta[300] = {0};
  size_t longitud = 12 + longitudPregunta;
  if (longitud + (ipv4 ? 16 : 0) > sizeof(respuesta)) {
    portENTER_CRITICAL(&dnsMux);
    dnsEstadisticas.invalidos++;
    portEXIT_CRITICAL(&dnsMux);
    return;
  }
  respuesta[0] = p[0]; respuesta[1] = p[1]; // Transaction ID
  respuesta[2] = 0x84 | (p[2] & 0x01);    // QR=1, AA=1, RD preservado
  respuesta[3] = 0x00;                   // NOERROR, RA=0
  respuesta[4] = 0; respuesta[5] = 1;     // 1 pregunta
  respuesta[6] = 0; respuesta[7] = ipv4 ? 1 : 0;
  // NSCOUNT y ARCOUNT quedan en 0 (se ignora EDNS OPT).
  memcpy(respuesta + 12, p + 12, longitudPregunta);
  if (ipv4) {
    size_t i = longitud;
    respuesta[i++] = 0xC0; respuesta[i++] = 0x0C; // puntero QNAME
    respuesta[i++] = 0; respuesta[i++] = 1;       // A
    respuesta[i++] = 0; respuesta[i++] = 1;       // IN
    respuesta[i++] = 0; respuesta[i++] = 0;
    respuesta[i++] = 0; respuesta[i++] = 15;      // TTL 15 s
    respuesta[i++] = 0; respuesta[i++] = 4;       // IPv4: 4 bytes
    for (int k = 0; k < 4; ++k) respuesta[i++] = ipLocal[k];
    longitud = i;
  }

  size_t enviados = paquete.write(respuesta, longitud);
  portENTER_CRITICAL(&dnsMux);
  if (tipo == 1) dnsEstadisticas.tipoA++;
  else if (tipo == 28) dnsEstadisticas.tipoAAAA++;
  else dnsEstadisticas.otrosTipos++;
  if (enviados == longitud) {
    if (ipv4) dnsEstadisticas.respuestasIPv4++;
    else dnsEstadisticas.respuestasSinIPv4++;
  }
  portEXIT_CRITICAL(&dnsMux);
}

// Resumen de la carga DNS: una muestra por segundo, últimos 30 segundos.
const uint8_t HIST_MUESTRAS = 30;
uint16_t dnsHistoria[HIST_MUESTRAS] = {0};
uint8_t cursorHistoria = 0;
uint32_t ultimoTotalDNS = 0;
unsigned long ultimaMuestra = 0;
uint32_t ultimoEventoDNS = 0;

void actualizarHistorialDNS() {
  if (millis() - ultimaMuestra < 1000UL) return;
  ultimaMuestra = millis();
  ContadoresDNS s = snapshotDNS();
  uint32_t diferencia = s.recibidos - ultimoTotalDNS;
  ultimoTotalDNS = s.recibidos;
  dnsHistoria[cursorHistoria] = diferencia > 65535 ? 65535 : (uint16_t)diferencia;
  cursorHistoria = (cursorHistoria + 1) % HIST_MUESTRAS;

  // Un evento DNS resumido, no uno por dominio ni uno por usuario.
  if (s.recibidos > ultimoEventoDNS && millis() - ultimoResumenDNS > 8000UL) {
    registrarEvento("Actividad DNS registrada (sin guardar dominios)");
    ultimoResumenDNS = millis();
    ultimoEventoDNS = s.recibidos;
  }
}

const char PAGINA_PORTAL[] PROGMEM = R"PORTAL_HTML(
<!DOCTYPE html>
<html lang="es"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BEAR IN THE MIDDLE · CERC</title>
<style>
:root{--o:#ED7025;--cream:#ffe5cf;--white:#faf8f4;--muted:#bac1cc;--ink:#090c12}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(circle at 50% 5%,#2b1a15,#090c12 55%);color:var(--white);font:16px/1.55 Arial,Helvetica,sans-serif}
.wrapper{max-width:520px;margin:auto;padding:18px 16px 35px}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;border-bottom:1px solid #5a3423;padding:8px 0 14px;font-size:11px;letter-spacing:.1em;color:#f4bc96;font-weight:bold}
.pill{border:1px solid var(--o);border-radius:99px;padding:5px 9px;color:var(--o)}
.card{margin-top:22px;padding:28px 19px 24px;border-radius:22px;border:1px solid #754124;background:linear-gradient(160deg,#1c202d,#11151e);box-shadow:0 15px 50px #0008;text-align:center}
.symbol{position:relative;margin:0 auto 8px;width:185px;max-width:75%}
.symbol:before{content:'';position:absolute;inset:10px;border:1px dashed #ED702577;border-radius:50%;animation:spin 20s linear infinite}
.symbol img{position:relative;display:block;width:100%;height:auto;filter:drop-shadow(0 4px 16px #ed70253a);animation:float 2.8s ease-in-out infinite;transform-origin:center}
.eyebrow{font-size:11px;letter-spacing:.24em;font-weight:bold;color:var(--o);margin:4px 0 8px}
h1{margin:0;font-size:clamp(28px,9vw,44px);line-height:1.06;color:var(--o);font-weight:900;letter-spacing:-.03em}
h2{margin:15px 0;color:var(--white);font-size:clamp(21px,6vw,28px);line-height:1.15}
.lead{font-size:16px;margin:12px auto;max-width:390px;color:#e0e3eb}
.notice{margin:20px 0;padding:13px 14px;text-align:left;background:#0c111b;border-left:4px solid var(--o);border-radius:9px;color:#e3e4e8;font-size:14px}
.notice strong{color:var(--cream)}
.btn{border:0;width:100%;display:block;padding:14px 16px;margin:12px 0 0;border-radius:12px;background:var(--o);color:#120f0d;text-align:center;text-decoration:none;font-size:16px;font-weight:900;cursor:pointer}
.btn.secondary{color:var(--o);background:transparent;border:1px solid var(--o);font-weight:bold}
.more{margin-top:18px;border:1px solid #394354;background:#111927;border-radius:14px;padding:17px;text-align:left}
.more summary{font-size:16px;cursor:pointer;color:#ffb781;font-weight:bold}
.more ol{margin:13px 0 6px;padding-left:20px}.more li{margin-bottom:8px;color:#e4e8ef}
.quiz{margin-top:15px;padding-top:15px;border-top:1px solid #384150}.quiz b{display:block;margin-bottom:12px}
.quiz button{margin:0 6px 8px 0;padding:10px 15px;border:1px solid #ed7025;border-radius:9px;color:#fff;background:#202839;cursor:pointer}
#answer{font-weight:bold;color:#ffc099;min-height:1em}
.foot{margin-top:22px;color:#aeb9c6;text-align:center;font-size:12px}
@keyframes float{0%,100%{transform:translateY(0) rotate(-2deg)}50%{transform:translateY(-11px) rotate(2deg)}}
@keyframes spin{to{transform:rotate(360deg)}}
@media(prefers-reduced-motion:reduce){.symbol img,.symbol:before{animation:none}}
</style></head><body>
<main class="wrapper">
<header class="top"><span>CERC · REDES Y CIBERSEGURIDAD</span><span class="pill">HALLOWEEN DEMO</span></header>
<section class="card">
<div class="symbol"><img alt="Oso oficial de CERC" src="data:image/png;base64,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"></div>
<div class="eyebrow">THE WI-FI HALLOWEEN TRAP</div>
<h1>BEAR IN<br>THE MIDDLE</h1><h2>¡HAS CAÍDO EN LA TRAMPA!</h2>
<p class="lead">Te conectaste a una red Wi-Fi creada por un <strong>ESP32</strong>. El oso CERC te recibió en un <strong>portal cautivo</strong> de demostración.</p>
<div class="notice"><strong>Experimento educativo autorizado.</strong><br>Este proyecto no solicita contraseñas ni lee tus mensajes. Únicamente muestra un portal local y estadísticas generales de la demo.</div>
<a class="btn" href="#aprende">DESCUBRE CÓMO FUNCIONA</a>
<a class="btn secondary" href="/monitor">VER MONITOR DE RED</a>
</section>
<details class="more" id="aprende"><summary>¿Qué ocurrió realmente? (toca aquí)</summary>
<ol><li>Tu teléfono se asoció a la red <b>BEAR_TRAP_DEMO</b>.</li><li>El ESP32 contestó una pregunta de dirección (DNS) con la IP de este portal de prueba.</li><li>Tu celular abrió la página del oso, guardada dentro del ESP32. No necesitamos Internet.</li></ol>
<p><b>Importante:</b> Este portal no intercepta páginas HTTPS.</p>
<div class="quiz"><b>Minireto: ¿Conectarte significa que te robaron tus datos?</b><button type="button" onclick="responder(false)">Sí</button><button type="button" onclick="responder(true)">No</button><p id="answer" aria-live="polite"></p></div>
</details>
<footer class="foot">CERC · Círculo de Estudios de Redes y Ciberseguridad<br>BEAR IN THE MIDDLE · Demo educativa</footer>
</main>
<script>function responder(ok){document.getElementById('answer').textContent=ok?'¡Correcto! Conectarse no demuestra que se hayan robado datos.':'No necesariamente. Este portal no intercepta contenido HTTPS ni credenciales.';}
var l=document.querySelector('a[href="#aprende"]');l.addEventListener('click',function(){document.getElementById('aprende').open=true;});</script>
</body></html>
)PORTAL_HTML";

const char PAGINA_MONITOR[] PROGMEM = R"MONITOR_HTML(
<!DOCTYPE html><html lang="es"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BEAR MONITOR · CERC</title>
<style>
:root{--o:#ED7025;--mut:#c4cad4}*{box-sizing:border-box}body{margin:0;background:#0a0e15;color:#fff;font:16px/1.4 Arial,Helvetica,sans-serif}
main{max-width:1050px;margin:0 auto;padding:20px 16px 35px}
.head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding-bottom:14px;border-bottom:1px solid #51402f}
.label{color:var(--o);font-size:12px;font-weight:bold;letter-spacing:.15em}h1{margin:10px 0 4px;font-size:clamp(25px,5vw,37px)}.desc{color:var(--mut);font-size:14px;margin:0 0 22px}
.chip{background:#232c31;border:1px solid #44624d;padding:9px 11px;border-radius:99px;color:#aff0b6;font-size:12px;white-space:nowrap}
.cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.card{padding:17px;border-radius:14px;background:#171d2a;border:1px solid #303d50}
.card span{display:block;color:var(--mut);font-size:13px}.card strong{display:block;margin-top:5px;font-size:clamp(23px,5vw,33px);overflow-wrap:anywhere}
.card strong.orange{color:var(--o)}.extra{font-size:12px;color:#9ba5b5;margin-top:6px}
.panel{background:#121926;border:1px solid #303d50;border-radius:14px;padding:16px;margin-top:18px}
h2{font-size:18px;margin:0 0 10px;color:#ffb181}.event{padding:8px 0;border-bottom:1px solid #263142;font-size:13px;color:#dae0e8}.event:last-child{border-bottom:0}
.time{display:inline-block;min-width:65px;color:#ffb181;font-family:monospace}
.chart{display:flex;gap:3px;align-items:flex-end;height:100px;border-bottom:1px solid #424c60;padding:5px 0 0}.bar{flex:1;min-width:3px;background:var(--o);border-radius:3px 3px 0 0;opacity:.92}
.legend{display:flex;justify-content:space-between;gap:6px;font-size:11px;color:#aeb8c7;margin-top:8px}
.steps{display:grid;gap:6px}.steps code{color:#ffc499;overflow-wrap:anywhere}a{color:var(--o)}.foot{margin-top:18px;color:#a5afbe;font-size:12px}.dot{display:inline-block;width:7px;height:7px;margin-right:5px;border-radius:50%;background:#65d987}
@media(min-width:720px){.cards{grid-template-columns:repeat(4,minmax(0,1fr))}}
</style></head><body><main>
<div class="head"><span class="label">CERC / DNS LIVE LAB</span><span class="chip"><span class="dot"></span>ESP32 EN LÍNEA</span></div>
<h1> BEAR NETWORK MONITOR</h1><p class="desc">Actividad de nuestra red de prueba · BEAR_TRAP_DEMO · Se actualiza cada 3 segundos</p>
<section class="panel" style="margin-top:0"><h2>¿Qué estamos viendo?</h2><p style="color:#c4cad4;font-size:14px;margin:0">El ESP32 crea una red Wi-Fi, recibe preguntas DNS (para encontrar direcciones) y muestra la página del oso. Estos son <b>contadores de actividad</b>, no intentos de ataque ni personas identificadas.</p></section>
<section class="cards">
<div class="card"><span>Equipos conectados</span><strong id="clients">—</strong><div class="extra">Celulares y computadoras en la red</div></div>
<div class="card"><span>Preguntas DNS recibidas</span><strong id="dtotal" class="orange">—</strong><div class="extra">Consultas que llegaron al ESP32</div></div>
<div class="card"><span>Respuestas HTTP del portal</span><strong id="hits">—</strong><div class="extra">Incluye solicitudes automáticas, no visitantes únicos</div></div>
<div class="card"><span>Servidor DNS</span><strong style="font-size:20px" id="dns">—</strong><div class="extra" id="uptime">—</div></div>
</section>
<details class="panel"><summary style="cursor:pointer;color:#ffb181;font-weight:bold">Detalles técnicos (A, AAAA y otros)</summary>
<p style="color:#c4cad4;font-size:14px">A pide una dirección IPv4 (como 192.168.4.1). AAAA pregunta por una dirección IPv6. ¡Son consultas normales de red, no ataques!</p>
<section class="cards">
<div class="card"><span>Consultas A (IPv4)</span><strong id="da">—</strong></div>
<div class="card"><span>Consultas AAAA (IPv6)</span><strong id="daaaa">—</strong></div>
<div class="card"><span>Otros tipos DNS</span><strong id="dother">—</strong></div>
<div class="card"><span>Respuestas con IPv4</span><strong id="dipv4">—</strong></div>
<div class="card"><span>Respuestas sin IPv4</span><strong id="dno">—</strong></div>
<div class="card"><span>Paquetes DNS inválidos</span><strong id="dbad">—</strong></div>
</section></details>
<section class="panel"><h2>Actividad DNS reciente · Últimos 30 segundos</h2><div class="chart" id="chart" aria-label="Consultas por segundo"></div><div class="legend"><span>Hace 30 s</span><span id="d30">0 consultas recibidas</span><span>Ahora</span></div></section>
<section class="panel"><h2>Eventos recientes</h2><div id="events"><div class="event">Consultando al ESP32...</div></div></section>
<section class="panel"><h2>Haz la prueba en vivo</h2><div class="steps"><p>En una computadora conectada a BEAR_TRAP_DEMO, abre la terminal y escribe:</p><code>nslookup demo.test 192.168.4.1</code><p>Comprueba que se devuelve <b>192.168.4.1</b> y que aumenta el contador DNS.</p></div></section>
<p><a href="/">← Volver al portal del oso</a></p><p class="foot">CERC · Círculo de Estudios de Redes y Ciberseguridad · Demostración autorizada</p>
</main><script>
async function actualizar(){try{var r=await fetch('/api/status?x='+Date.now(),{cache:'no-store'});if(!r.ok)throw Error('HTTP');var s=await r.json();
[['clients',s.clientes],['hits',s.portal_http],['dtotal',s.dns_recibidos],['da',s.dns_a],['daaaa',s.dns_aaaa],['dother',s.dns_otros],['dipv4',s.dns_ipv4],['dno',s.dns_sin_ipv4],['dbad',s.dns_invalidos]].forEach(function(p){document.getElementById(p[0]).textContent=p[1]});
document.getElementById('dns').textContent=s.dns?'ACTIVO':'ERROR';document.getElementById('uptime').textContent='Encendido: '+s.segundos+' s';
var barras=document.getElementById('chart');barras.textContent='';var h=s.dns_historia||[];var max=Math.max(1,...h);h.forEach(function(v){var b=document.createElement('div');b.className='bar';b.style.height=(v?Math.max(4,(v/max)*100):1)+'%';b.title=v+' consultas/s';barras.appendChild(b);});
document.getElementById('d30').textContent=(s.dns_30s||0)+' paquetes recibidos';
var root=document.getElementById('events');root.textContent='';(s.eventos||[]).forEach(function(e){var d=document.createElement('div');d.className='event';var t=document.createElement('span');t.className='time';t.textContent='+'+e.t+' s';d.appendChild(t);d.appendChild(document.createTextNode(e.msg));root.appendChild(d);});if(!s.eventos.length)root.textContent='Sin eventos registrados';
}catch(e){document.getElementById('dns').textContent='SIN RESPUESTA';}}
actualizar();setInterval(actualizar,3000);
</script></body></html>
)MONITOR_HTML";


void mostrarPortal() {
  totalPortalHTTP++;
  if (ultimoLogPortal == 0 || millis() - ultimoLogPortal > 4000UL) {
    registrarEvento("Portal HTTP solicitado");
    ultimoLogPortal = millis();
  }
  server.sendHeader("Cache-Control", "no-store");
  server.send_P(200, "text/html; charset=utf-8", PAGINA_PORTAL);
}

void mostrarMonitor() {
  server.sendHeader("Cache-Control", "no-store");
  server.send_P(200, "text/html; charset=utf-8", PAGINA_MONITOR);
}

void estadoJSON() {
  ContadoresDNS d = snapshotDNS();
  String json;
  json.reserve(1600);
  json += "{\"clientes\":";
  json += String(WiFi.softAPgetStationNum());
  json += ",\"portal_http\":";
  json += String(totalPortalHTTP);
  json += ",\"dns\":";
  json += (dnsActivo ? "true" : "false");
  json += ",\"segundos\":";
  json += String(millis() / 1000UL);
  json += ",\"dns_recibidos\":";
  json += String(d.recibidos);
  json += ",\"dns_a\":";
  json += String(d.tipoA);
  json += ",\"dns_aaaa\":";
  json += String(d.tipoAAAA);
  json += ",\"dns_otros\":";
  json += String(d.otrosTipos);
  json += ",\"dns_ipv4\":";
  json += String(d.respuestasIPv4);
  json += ",\"dns_sin_ipv4\":";
  json += String(d.respuestasSinIPv4);
  json += ",\"dns_invalidos\":";
  json += String(d.invalidos);
  json += ",\"dns_historia\":[";
  uint32_t total30 = 0;
  for (uint8_t i = 0; i < HIST_MUESTRAS; ++i) {
    uint8_t indice = (cursorHistoria + i) % HIST_MUESTRAS;
    if (i) json += ',';
    json += String(dnsHistoria[indice]);
    total30 += dnsHistoria[indice];
  }
  json += "],\"dns_30s\":";
  json += String(total30);
  json += ",\"eventos\":[";
  for (uint8_t i = 0; i < cantidadEventos; ++i) {
    uint8_t pos = (proximoEvento + MAX_EVENTOS - 1 - i) % MAX_EVENTOS;
    if (i) json += ',';
    json += "{\"t\":";
    json += String(eventos[pos].segundos);
    json += ",\"msg\":\"";
    json += eventos[pos].mensaje;
    json += "\"}";
  }
  json += "]}";
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "application/json; charset=utf-8", json);
}

void vigilarClientes() {
  if (millis() - ultimaRevision < 400UL) return;
  ultimaRevision = millis();
  uint8_t actuales = WiFi.softAPgetStationNum();
  if (actuales > clientesAnteriores) registrarEvento("Aumento de clientes conectados");
  if (actuales < clientesAnteriores) registrarEvento("Disminucion de clientes conectados");
  clientesAnteriores = actuales;
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_AP);

  if (!WiFi.softAP(SSID_DEMO, CLAVE_DEMO)) {
    Serial.println("ERROR: no se pudo crear la red Wi-Fi");
    return;
  }
  IPAddress ip = WiFi.softAPIP();
  for (int i = 0; i < 4; ++i) ipLocal[i] = ip[i];

  // Un único servidor UDP, enlazado al puerto DNS 53.
  // No utilizar DNSServer simultáneamente (mismo puerto).
  dnsActivo = dnsUdp.listen(53);
  if (dnsActivo) dnsUdp.onPacket(atenderDNS);
  registrarEvento(dnsActivo ? "DNS UDP listo" : "ERROR: DNS no disponible");

  server.on("/", HTTP_GET, mostrarPortal);
  server.on("/monitor", HTTP_GET, mostrarMonitor);
  server.on("/api/status", HTTP_GET, estadoJSON);
  server.on("/favicon.ico", HTTP_GET, []() { server.send(204); });
  server.onNotFound(mostrarPortal);
  server.begin();
  registrarEvento("Portal HTTP listo");
  ultimaMuestra = millis();

  Serial.println("=== BEAR IN THE MIDDLE v3.0 DNS PRO ===");
  Serial.print("Red: "); Serial.println(SSID_DEMO);
  Serial.print("IP: "); Serial.println(ip);
  Serial.print("DNS: "); Serial.println(dnsActivo ? "ACTIVO" : "ERROR");
  Serial.println("Portal: http://192.168.4.1/");
  Serial.println("Monitor: http://192.168.4.1/monitor");
  Serial.println("DNS test: nslookup demo.test 192.168.4.1");
}

void loop() {
  // AsyncUDP recibe DNS sin requerir processNextRequest().
  server.handleClient();
  vigilarClientes();
  actualizarHistorialDNS();
  delay(2);
}
