# 🐻 BEAR IN THE MIDDLE — Halloween CERC

**Un ESP32, una red Wi-Fi y un oso.** Es una demostración educativa hecha para CERC y para repetirla en casa.

> **Qué es:** un portal cautivo educativo con un monitor de consultas DNS reales. Aunque el nombre dice "in the middle", **no es un MITM real**: no intercepta HTTPS ni roba contraseñas.

## ¿Qué hace?

1. El ESP32 crea una red Wi-Fi local.
2. Al conectarte, tu celular puede mostrar el portal cautivo de CERC.
3. Desde una computadora u otro celular puedes ver cuántos dispositivos hay conectados y cuántas consultas DNS llegan al ESP32.
4. La demostración funciona **sin Internet!!**.

## Materiales

- Un **ESP32** con Wi-Fi, por ejemplo una placa genérica **ESP32 Dev Module**.
- Cable USB de datos para programarlo.
- Una computadora con Arduino IDE 1.8.19 y el paquete **esp32 by Espressif Systems 3.x**.
- Un celular para la prueba; otra computadora es opcional para abrir el monitor.

## Instalar y probar

1. Descarga el repositorio desde GitHub usando **Code → Download ZIP** y extráelo.
2. Abre `BearTrap_CERC/BearTrap_CERC.ino` en Arduino IDE.
3. Selecciona **Herramientas → Placa → ESP32 Dev Module** y el puerto COM/USB correspondiente.
4. Pulsa **Verificar (✓)** y después **Subir (→)**.
5. Conecta tu celular a la red **`BEAR_TRAP_DEMO`**, contraseña **`Bear2026!`**.
6. Si la página del oso no se abre sola, visita **http://192.168.4.1** (HTTP, no HTTPS).
7. Para ver el monitor, abre **http://192.168.4.1/monitor** desde otro dispositivo de esa misma red.

**Nota:** el sistema puede indicar «sin Internet». Es esperado: el portal funciona totalmente de forma local. La aparición automática depende del teléfono.

## Explicación DNS

DNS es como una **agenda de direcciones**. El teléfono pregunta dónde encontrar una página. En esta red de demostración el ESP32 responde con la IP de su portal, `192.168.4.1`.

En el monitor verás preguntas DNS recibidas. **Una consulta no es una persona ni un ataque**. Los teléfonos hacen consultas automáticas.

En «Detalles técnicos»:
- **A:** pide una dirección IPv4, como `192.168.4.1`.
- **AAAA:** pide una dirección IPv6, otro formato de dirección.
- **Otros:** otras clases de preguntas DNS.

### Prueba opcional desde una computadora conectada a la red

```bash
nslookup demo.test 192.168.4.1
```

La respuesta esperada es `192.168.4.1` y el contador DNS debe aumentar.

## Uso responsable y privacidad

Utiliza únicamente la red propia de prueba con participantes informados. **No imites redes ajenas ni solicites contraseñas personales**. El código no guarda nombres de dominios consultados, IP, MAC, mensajes ni credenciales. La actividad general permanece temporalmente en la memoria del ESP32 y se borra al reiniciarlo. El ESP32 no ofrece salida a Internet ni intercepta HTTPS.
