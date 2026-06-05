# Informe Técnico — DHCP Starvation Attack
**Nombre:** Reymond Marte  
**Matrícula:** 2025-0684  
**Asignatura:** Seguridad en Redes  
**Práctica:** P4 — DHCP Starvation  

---
Link de demostracion: https://youtu.be/h0Z90WX5XIw?si=FfDcIAug4pnnNNd4
## 1. Objetivo del Laboratorio

Demostrar cómo un atacante puede agotar el pool de direcciones IP de un servidor DHCP mediante el envío masivo de solicitudes DHCP Discover con MACs de origen falsas, impidiendo que clientes legítimos obtengan una dirección IP, y documentar la contramedida correspondiente para mitigar el ataque.

---

## 2. Objetivo del Script

El script `dhcp_starvation.py` genera solicitudes DHCP Discover con MACs de origen aleatorias, haciendo creer al servidor DHCP que existen múltiples clientes nuevos. El servidor asigna una IP por cada solicitud hasta agotar su pool disponible. Una vez agotado, ningún cliente legítimo puede obtener una dirección IP.

### 2.1 Parámetros del Script

| Flag | Parámetro | Descripción | Default |
|---|---|---|---|
| `-i` | Interfaz | Interfaz de red del atacante | Requerido |
| `-c` | Cantidad | Paquetes a enviar (0 = infinito) | 100 |
| `-d` | Delay | Segundos entre paquetes | 0.05 |
| `-v` | Verbose | Muestra detalle de cada paquete | False |

### 2.2 Requisitos

| Requisito | Detalle |
|---|---|
| Sistema operativo | Linux |
| Python | 3.x |
| Librería | Scapy: `pip install scapy` |
| Permisos | Root: `sudo` |
| Conectividad | Mismo dominio L2 que el servidor DHCP |
| Entorno | Laboratorio controlado |

---

## 3. Funcionamiento del Script

### 3.1 Descripción por Función

**`random_mac()`**  
Genera una MAC aleatoria unicast (`02:xx:xx:xx:xx:xx`) para simular un cliente DHCP diferente por cada solicitud enviada.

**`mac_to_bytes(mac)`**  
Convierte la MAC en formato string a bytes para incluirla correctamente en el campo `chaddr` del paquete BOOTP, que identifica al cliente ante el servidor DHCP.

**`build_discover(mac)`**  
Construye un paquete DHCP Discover completo con la estructura correcta:
- `Ether` → broadcast (`ff:ff:ff:ff:ff:ff`)
- `IP` → origen `0.0.0.0`, destino `255.255.255.255`
- `UDP` → puerto origen 68, destino 67
- `BOOTP` → `op=1` (Request), `chaddr` con la MAC falsa, `xid` aleatorio
- `DHCP` → opciones: message-type discover, hostname aleatorio, param_req_list

**`dhcp_starvation(iface, count, delay, verbose)`**  
Función principal del ataque. Genera y envía DHCP Discovers en loop hasta alcanzar el límite configurado o ser interrumpido. Muestra estadísticas de tasa de envío cada 50 paquetes.

**`signal_handler(sig, frame)`**  
Captura `SIGINT` (Ctrl+C) y muestra estadísticas finales del ataque antes de terminar.

### 3.2 Ejecución

```bash
# Ataque infinito
sudo python3 dhcp_starvation.py -i ens3 -c 0 -d 0.05

# Ataque con 200 paquetes
sudo python3 dhcp_starvation.py -i ens3 -c 200 -d 0.1
```

---

## 4. Documentación de la Red

### 4.1 Topología

> Ver screenshot adjunto de la topología en PNetLab.
![[Pasted image 20260604215802.png]]
### 4.2 Direccionamiento IP

| Dispositivo | Interfaz | IP | Rol |
|---|---|---|---|
| Router | e0/0 | 192.6.84.1 | Gateway / Servidor DHCP |
| Atacante | ens3 | 192.6.84.10 | Atacante |
| Víctima | eth0 | DHCP | Víctima |
| VPCs | eth0 | DHCP | Hosts adicionales |
| SW1 | — | Solo L2 | Switch central |
| SW2 | — | Solo L2 | Switch STP |
| SW3 | — | Solo L2 | Switch STP |

### 4.3 Detalles de Red

| Parámetro | Valor |
|---|---|
| Red | 192.6.84.0/24 |
| Máscara | 255.255.255.0 |
| Gateway | 192.6.84.1 |
| Pool DHCP | 192.6.84.1 — 192.6.84.254 |
| Total IPs pool | 254 |
| VLAN | VLAN 1 (default) |
| Plataforma | PNetLab |

### 4.4 Requisitos de Red

- Servidor DHCP activo en el Router con pool configurado
- Sin DHCP Snooping configurado en el switch
- Atacante en el mismo dominio L2 que el servidor DHCP
- Red de laboratorio aislada

---

## 5. Demostración del Ataque

### 5.1 Verificación Inicial

Estado del pool DHCP antes del ataque:
```cisco
Router# show ip dhcp pool
Router# show ip dhcp binding
```
```
Pool LAN-2025-0684:
Total addresses  : 254
Leased addresses : 2
```

### 5.2 Ejecución del Ataque

```bash
sudo python3 dhcp_starvation.py -i ens3 -c 0 -d 0.05
```

### 5.3 Verificación del Efecto

Pool DHCP durante el ataque:
```cisco
Router# show ip dhcp binding
Router# show ip dhcp pool
```

> Las IPs asignadas suben rápidamente hasta agotar el pool disponible. Cada entrada en `show ip dhcp binding` corresponde a una MAC falsa generada por el atacante.

### 5.4 Prueba de Denegación de Servicio

Desde la víctima intentar obtener IP:
```
Victima> ip dhcp
```

> La víctima no puede obtener una dirección IP — el pool está agotado. El servidor DHCP no tiene IPs disponibles para asignar a clientes legítimos.

### 5.5 Indicadores de Ataque

| Indicador | Descripción |
|---|---|
| Pool DHCP agotado | `Leased addresses` igual a `Total addresses` |
| Bindings con MACs `02:xx` | MACs falsas con prefijo unicast aleatorio |
| Clientes legítimos sin IP | DHCP timeout en hosts que intentan conectarse |
| Alto volumen de Discovers | Tráfico UDP puerto 67/68 masivo en el switch |

---

## 6. Contramedida — DHCP Snooping Rate Limiting

### 6.1 Descripción

DHCP Snooping es una función de seguridad del switch que actúa como firewall entre clientes DHCP no confiables y servidores DHCP confiables. El rate limiting de DHCP Snooping limita la cantidad de paquetes DHCP que puede enviar cada puerto por segundo, bloqueando el ataque de starvation al descartar los paquetes que excedan el límite configurado.

### 6.2 Configuración en SW1

**Activar DHCP Snooping:**
```cisco
SW1(config)# ip dhcp snooping
SW1(config)# ip dhcp snooping vlan 1
SW1(config)# no ip dhcp snooping information option
```

**Marcar puerto del Router como confiable:**
```cisco
SW1(config)# interface e0/0
SW1(config-if)# ip dhcp snooping trust
SW1(config-if)# exit
```

**Limitar rate en el puerto del atacante:**
```cisco
SW1(config)# interface e0/3
SW1(config-if)# ip dhcp snooping limit rate 10
SW1(config-if)# exit
```

> El límite de 10 paquetes por segundo permite el tráfico DHCP legítimo pero bloquea el flood masivo del atacante.

### 6.3 Verificación

```cisco
SW1# show ip dhcp snooping
SW1# show ip dhcp snooping statistics
SW1# show ip dhcp snooping binding
```

### 6.4 Resultado

Con DHCP Snooping rate limiting activo, el switch descarta todos los paquetes DHCP que excedan el límite de 10 pps en el puerto del atacante. El pool DHCP se mantiene disponible para clientes legítimos y la víctima puede obtener su IP sin problemas.

### 6.5 Contramedidas Adicionales

| Medida | Descripción |
|---|---|
| `ip dhcp snooping limit rate` | Limita paquetes DHCP por puerto por segundo |
| Pool DHCP reducido | Asignar IPs solo al rango necesario |
| Reservas DHCP estáticas | Asignar IPs fijas a hosts críticos por MAC |
| Port Security | Limitar MACs por puerto, reduciendo el impacto |

---

## 7. Conclusión

El ataque DHCP Starvation explota la ausencia de autenticación en el protocolo DHCP para agotar el pool de direcciones disponibles, dejando a los clientes legítimos sin conectividad. La contramedida más efectiva es DHCP Snooping con rate limiting, que restringe el flujo de paquetes DHCP por puerto y bloquea el ataque masivo antes de que pueda agotar el pool del servidor.

---


