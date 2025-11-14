# BGP Looking Glass

Looking Glass moderno con **FRR (recomendado)** y soporte legacy para MikroTik, integración con PeeringDB/RIPEstat, detección automática de información del cliente y **hardening de seguridad implementado**.

## 🌟 Características

- **Auto-detección de cliente**: IP, ASN, red y nombre del AS automáticos via BGP + PeeringDB
- **Integración PeeringDB**: Obtiene nombres de organizaciones y ASN en tiempo real
- **Integración RIPEstat**: Datos de enrutamiento y geolocalización
- **Soporte dual IPv4/IPv6**: Protocolo dual completo con validación
- **Múltiples backends**:
  - **FRR (Free Range Routing)** ⭐ **RECOMENDADO**: Soporte nativo via vtysh con wrapper seguro, sin impacto en rendimiento
  - **MikroTik RouterOS** (Legacy): Mantenido solo para compatibilidad histórica, **no recomendado** para nuevas instalaciones
- **Comandos BGP**: Consulta rutas BGP con AS Path en formato estándar y origen del prefijo
- **Ping y Traceroute**: Diagnóstico de conectividad completo (traceroute optimizado para FRR)
- **Interfaz moderna**: Terminal-style responsive con React-like interactivity
- **🔐 Seguridad hardened**: Múltiples capas de protección implementadas
  - Validación estricta de inputs
  - Sanitización de comandos
  - Rate limiting
  - reCAPTCHA v3/v2 dual
  - Sesiones seguras
  - CORS restrictivo
  - Logging de auditoría
- **RPKI**: Validación de Route Origin Authorization

## 🔒 Seguridad

Este proyecto implementa **múltiples capas de seguridad** siguiendo mejores prácticas de OWASP.

### Protecciones Implementadas

✅ **Command Injection Prevention**
- Validación estricta de caracteres permitidos en targets
- Sanitización de comandos vtysh con blacklist de caracteres peligrosos
- Wrapper de vtysh con whitelist de comandos permitidos

✅ **Information Disclosure Prevention**
- Display errors deshabilitado en producción
- Mensajes de error genéricos para usuarios
- Logging detallado solo en servidor

✅ **Session Security**
- Cookies con flags `httponly`, `secure`, `samesite=Strict`
- Regeneración de session ID
- Validación de IP anti-hijacking
- Expiración automática de sesiones

✅ **CORS Protection**
- Whitelist de orígenes confiables
- No permite `*` en producción
- Validación de Origin header

✅ **Audit Logging**
- Todos los comandos vtysh registrados en syslog
- Tracking de IP origen
- Logs separados para seguridad y comandos

✅ **Proxy IP Validation**
- Solo confía en X-Forwarded-For de proxies conocidos
- Previene IP spoofing
- Rangos de Cloudflare incluidos

### Testing de Seguridad

```bash
# Ejecutar tests automáticos
./test-security.sh

# Ver logs de seguridad
sudo tail -f /var/log/looking-glass/vtysh.log
sudo tail -f /var/log/apache2/error.log | grep SECURITY
```

## 📋 Requisitos

### Backend
- **Servidor web**: Apache/Nginx con PHP 7.4+
- **PHP Extensions**: curl, json, mbstring, session
- **Sistema**: Linux con systemd (para logging)

### Routing Backend
- **FRR (Free Range Routing)** ⭐ **RECOMENDADO**: v7.5+
  - vtysh instalado
  - Usuario `www-data` en grupo `frrvty`
  - Traceroute disponible en el sistema
- **MikroTik RouterOS** (Legacy, no recomendado): v6.47+
  - API habilitada en puerto 8728
  - Usuario con permisos read-only
  - ⚠️ Impacto en performance del router

### Servicios Externos
- **reCAPTCHA**: Claves v3 y v2 de Google reCAPTCHA
- **Conexión Internet**: Para APIs de PeeringDB y RIPEstat

## 🚀 Instalación

### 1. Clonar el repositorio

```bash
cd /var/www/html
git clone https://github.com/dpecile/looking-glass.git lg2
cd lg2
```

### 2. Configurar archivos de entorno

```bash
# Copiar y editar .env
cp .env.example .env
nano .env
```

Edita `.env` con tus claves de reCAPTCHA:
```bash
# reCAPTCHA v3 (invisible)
RECAPTCHA_V3_SITE_KEY=tu_clave_v3_site
RECAPTCHA_V3_SECRET_KEY=tu_clave_v3_secret

# reCAPTCHA v2 (fallback)
RECAPTCHA_V2_SITE_KEY=tu_clave_v2_site
RECAPTCHA_V2_SECRET_KEY=tu_clave_v2_secret
```

Obtén tus claves en: https://www.google.com/recaptcha/admin

**Configurar permisos del archivo .env:**
```bash
# Permitir que www-data lea el archivo (necesario para Apache/PHP)
sudo chown root:www-data .env
sudo chmod 640 .env
```

### 3. Configurar routers

```bash
# Copiar y editar configuración
cp config/config.example.json config/config.json
nano config/config.json
```

**Configuración de ejemplo:**
```json
{
  "environment": "production",
  "company": {
    "name": "Tu Red",
    "asn": "XXXXX",
    "logo": "/assets/Logo-XL.png",
    "fallback_logo": "TR"
  },
  "routers": [
    {
      "id": "frr_router_01",
      "name": "Router Principal",
      "location": "Tu Ciudad",
      "backend": "frr",
      "frr_host": "localhost",
      "frr_ssh_user": "www-data",
      "enabled": true,
      "supports_ipv6": true
    }
  ],
  "security": {
    "rate_limit": {
      "commands_per_minute": 5,
      "commands_per_hour": 50
    },
    "allowed_commands": ["bgp", "ping", "trace"]
  }
}
```

**⚠️ IMPORTANTE - CORS Restrictivo:**

Los dominios permitidos se configuran en el archivo `.env`:
```bash
# Dominios permitidos (separados por comas)
CORS_ALLOWED_ORIGINS=https://lg.tudominio.com,https://lg2.tudominio.com
CORS_DEFAULT_ORIGIN=https://lg.tudominio.com
```

### 4. Configurar permisos FRR (SEGURO)

**Opción recomendada: Grupo frrvty**

```bash
# Agregar www-data al grupo frrvty (NO root)
sudo usermod -a -G frrvty www-data

# Verificar
groups www-data
# Debe mostrar: www-data frrvty
```

**🔐 Instalar wrapper seguro de vtysh:**

```bash
# Instalar wrapper que solo permite comandos show
sudo cp scripts/lg-vtysh.example /usr/local/bin/lg-vtysh
sudo chmod +x /usr/local/bin/lg-vtysh
sudo chown root:frrvty /usr/local/bin/lg-vtysh
sudo chmod 750 /usr/local/bin/lg-vtysh

# Probar
sudo -u www-data /usr/local/bin/lg-vtysh "show bgp summary"
# Debe funcionar ✅

sudo -u www-data /usr/local/bin/lg-vtysh "configure terminal"
# Debe bloquearse ❌
```

**Modificar FRR API para usar wrapper:**

Edita `includes/FRRAPI.php` línea 10:
```php
private $vtysh_path = '/usr/local/bin/lg-vtysh';  // Usar wrapper seguro
```

### 5. Configurar logging de auditoría

```bash
# Instalar configuración rsyslog
sudo cp scripts/rsyslog-looking-glass.conf.example /etc/rsyslog.d/50-looking-glass.conf

# Crear directorio de logs
sudo mkdir -p /var/log/looking-glass
sudo chown www-data:www-data /var/log/looking-glass
sudo chmod 755 /var/log/looking-glass

# Reiniciar rsyslog
sudo systemctl restart rsyslog

# Verificar
sudo tail -f /var/log/looking-glass/vtysh.log
```

### 6. Configurar Apache/Nginx

**Apache** (ya viene configurado con `.htaccess`):
```bash
# Habilitar mod_rewrite
sudo a2enmod rewrite
sudo systemctl reload apache2
```

**Nginx**:
```nginx
server {
    listen 443 ssl http2;
    server_name lg.example.com;
    root /var/www/html/lg2/public;
    index index.html;

    # SSL (obligatorio para cookies secure)
    ssl_certificate /etc/ssl/certs/lg.example.com.crt;
    ssl_certificate_key /etc/ssl/private/lg.example.com.key;

    location /api.php {
        try_files $uri =404;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

### 7. Crear directorio de logs para PHP

```bash
# Crear directorio para logs PHP
sudo mkdir -p /var/log/looking-glass
sudo chown www-data:www-data /var/log/looking-glass
sudo chmod 755 /var/log/looking-glass
```

## 🔧 Configuración de Backends

### ⚠️ Importante: Elección de Backend

**Se recomienda usar FRR** como backend para Looking Glass por las siguientes razones:

- ✅ **Performance superior**: Las consultas son rápidas y no impactan en el router de producción
- ✅ **Funcionalidad completa**: Soporte completo para BGP, ping, traceroute
- ✅ **Desarrollo activo**: FRR está en desarrollo activo y recibe actualizaciones
- ✅ **Nativo en Linux**: Diseñado específicamente para entornos Linux
- ✅ **Sin impacto**: Las consultas no afectan el rendimiento del routing

**MikroTik RouterOS**: Este backend se mantiene únicamente por razones históricas (proyectos legacy que lo usaban). **No se recomienda para nuevas instalaciones** porque:

- ⚠️ **Impacto en performance**: Las consultas via API impactan significativamente en el rendimiento del router, especialmente en operaciones de traceroute
- ⚠️ **Sin desarrollo activo**: El backend de MikroTik no recibe nuevas funcionalidades
- ⚠️ **Limitaciones**: Funcionalidad reducida comparado con FRR
- ⚠️ **Complejidad**: Requiere configuración adicional de API y credenciales

**Recomendación**: Si estás empezando un nuevo proyecto, usa FRR. Si ya usas MikroTik, considera migrar a FRR para mejor rendimiento.

---

### FRR (Free Range Routing) - ⭐ RECOMENDADO

FRR es el backend recomendado para redes que usan BGP en Linux.

**Instalación de FRR:**
```bash
# Ubuntu/Debian
curl -s https://deb.frrouting.org/frr/keys.asc | sudo apt-key add -
echo deb https://deb.frrouting.org/frr $(lsb_release -s -c) frr-stable | sudo tee /etc/apt/sources.list.d/frr.list
sudo apt update
sudo apt install frr frr-pythontools

# Habilitar BGP
sudo sed -i 's/bgpd=no/bgpd=yes/' /etc/frr/daemons
sudo systemctl restart frr
```

**Verificar acceso:**
```bash
# Como www-data
sudo -u www-data /usr/local/bin/lg-vtysh "show bgp ipv4 unicast summary"

# Debe mostrar la tabla BGP
```

**Configuración en config.json (FRR Local):**
```json
{
  "routers": [
    {
      "id": "frr_router_01",
      "name": "FRR Router Local",
      "location": "Datacenter 1",
      "backend": "frr",
      "frr_host": "localhost",
      "frr_ssh_user": "www-data",
      "enabled": true,
      "supports_ipv6": true
    }
  ]
}
```

---

#### 🌐 Consultar FRR Remoto via SSH

El Looking Glass soporta consultar routers FRR remotos via SSH. Esto es útil cuando:
- FRR está en un servidor diferente al del Looking Glass
- Tienes múltiples routers FRR en diferentes ubicaciones
- Quieres centralizar el Looking Glass en un solo servidor web

**¿Cómo funciona?**

Cuando `frr_host` no es `localhost`, el sistema ejecuta comandos via SSH:
```bash
ssh -o ConnectTimeout=5 usuario@host vtysh -c "show bgp ipv4 unicast summary"
```

---

**PASO 1: Configurar autenticación SSH sin contraseña**

En el servidor del Looking Glass (donde corre Apache/PHP):

```bash
# 1. Cambiar al usuario www-data
sudo su - www-data -s /bin/bash

# 2. Generar clave SSH (si no existe)
ssh-keygen -t ed25519 -C "looking-glass-www-data" -f ~/.ssh/id_ed25519 -N ""

# Salida esperada:
# Your identification has been saved in /var/www/.ssh/id_ed25519
# Your public key has been saved in /var/www/.ssh/id_ed25519.pub

# 3. Copiar la clave pública
cat ~/.ssh/id_ed25519.pub
# Copia este contenido (ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AA...)
```

**PASO 2: Agregar la clave al servidor FRR remoto**

En el servidor FRR remoto:

```bash
# 1. Crear usuario para el Looking Glass (si no existe)
# Opción A: Usuario dedicado (más seguro)
sudo useradd -m -s /bin/bash -G frrvty lg-remote
sudo passwd lg-remote  # Opcional, solo para login manual

# Opción B: Usar usuario existente con acceso a frrvty
sudo usermod -a -G frrvty nombre-usuario-existente

# 2. Agregar la clave pública de www-data
sudo mkdir -p /home/lg-remote/.ssh
sudo nano /home/lg-remote/.ssh/authorized_keys
# Pega aquí la clave pública que copiaste antes
# Guardar y salir (Ctrl+X, Y, Enter)

# 3. Configurar permisos correctos
sudo chown -R lg-remote:lg-remote /home/lg-remote/.ssh
sudo chmod 700 /home/lg-remote/.ssh
sudo chmod 600 /home/lg-remote/.ssh/authorized_keys

# 4. Verificar que el usuario tiene acceso a vtysh
sudo -u lg-remote /usr/local/bin/lg-vtysh "show version"
# Debe mostrar la versión de FRR
```

**PASO 3: Probar conexión SSH desde el servidor del Looking Glass**

Volver al servidor del Looking Glass:

```bash
# Como www-data
sudo -u www-data ssh lg-remote@IP_SERVIDOR_FRR "hostname"
# Primera vez pedirá aceptar la huella digital (yes)

# Probar comando vtysh remoto
sudo -u www-data ssh lg-remote@IP_SERVIDOR_FRR "/usr/local/bin/lg-vtysh 'show bgp ipv4 unicast summary'"

# Debe mostrar la tabla BGP del router remoto
```

**PASO 4: Configurar en config.json**

Edita `config/config.json`:

```json
{
  "routers": [
    {
      "id": "frr_router_local",
      "name": "FRR Local",
      "location": "Datacenter 1",
      "backend": "frr",
      "frr_host": "localhost",
      "frr_ssh_user": "www-data",
      "enabled": true,
      "supports_ipv6": true
    },
    {
      "id": "frr_router_remote",
      "name": "FRR Remoto",
      "location": "Datacenter 2",
      "backend": "frr",
      "frr_host": "192.168.10.50",
      "frr_ssh_user": "lg-remote",
      "enabled": true,
      "supports_ipv6": true
    }
  ]
}
```

**Parámetros para FRR remoto:**

| Parámetro | Descripción | Ejemplo |
|-----------|-------------|---------|
| `frr_host` | IP o hostname del servidor FRR remoto | `"192.168.10.50"` o `"router.example.com"` |
| `frr_ssh_user` | Usuario SSH en el servidor remoto (debe estar en grupo frrvty) | `"lg-remote"` |
| `enabled` | Habilitar/deshabilitar este router | `true` |
| `supports_ipv6` | Si el router soporta IPv6 | `true` / `false` |

---

**🔒 Seguridad para FRR Remoto**

**1. Restringir acceso SSH en el servidor remoto**

Edita `/etc/ssh/sshd_config` en el servidor FRR remoto:

```bash
# Solo permitir autenticación por clave (no contraseña)
PasswordAuthentication no
PubkeyAuthentication yes

# Restringir usuario lg-remote a solo ejecutar comandos específicos
# (opcional pero muy recomendado)
```

**Opción más segura: Usar `authorized_keys` con restricciones**

En el servidor FRR remoto, edita `/home/lg-remote/.ssh/authorized_keys`:

```bash
# Antes de la clave pública, agregar restricciones:
command="/usr/local/bin/lg-vtysh",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AA...
```

Esto fuerza que SOLO se pueda ejecutar el wrapper lg-vtysh, nada más.

**2. Firewall en el servidor FRR remoto**

```bash
# Solo permitir SSH desde la IP del servidor del Looking Glass
sudo ufw allow from IP_LOOKING_GLASS to any port 22
sudo ufw enable

# Verificar
sudo ufw status
```

**3. Auditoría de conexiones**

En el servidor FRR remoto, monitorear conexiones SSH:

```bash
# Ver conexiones SSH activas
sudo tail -f /var/log/auth.log | grep "Accepted publickey"

# Ver comandos vtysh ejecutados
sudo tail -f /var/log/looking-glass/vtysh.log
```

---

**🔧 Troubleshooting FRR Remoto**

**Problema: "Connection refused" o "Connection timed out"**

```bash
# Verificar que SSH está escuchando en el servidor remoto
nc -zv IP_SERVIDOR_FRR 22

# Verificar firewall
sudo ufw status

# Probar conexión SSH manual
ssh -v lg-remote@IP_SERVIDOR_FRR
```

**Problema: "Permission denied (publickey)"**

```bash
# Verificar que la clave pública está en authorized_keys
sudo cat /home/lg-remote/.ssh/authorized_keys

# Verificar permisos
ls -la /home/lg-remote/.ssh/

# Esperado:
# drwx------ (700) .ssh/
# -rw------- (600) authorized_keys

# Ver logs SSH en servidor remoto para más detalles
sudo tail -f /var/log/auth.log
```

**Problema: "Host key verification failed"**

```bash
# Primera vez, aceptar la huella digital manualmente
sudo -u www-data ssh lg-remote@IP_SERVIDOR_FRR

# O deshabilitar verificación (menos seguro)
# El código ya incluye: -o StrictHostKeyChecking=no
```

**Problema: Timeout o muy lento**

```bash
# Verificar latencia de red
ping -c 5 IP_SERVIDOR_FRR

# Verificar tiempo de conexión SSH
time ssh lg-remote@IP_SERVIDOR_FRR "echo test"

# Si tarda más de 2-3 segundos, revisar:
# - DNS inverso del servidor
# - UseDNS en sshd_config (cambiarlo a "no")
sudo nano /etc/ssh/sshd_config
# Agregar: UseDNS no
sudo systemctl restart sshd
```

**Problema: "vtysh: command not found" en servidor remoto**

```bash
# Verificar que el wrapper existe en el servidor remoto
ssh lg-remote@IP_SERVIDOR_FRR "which /usr/local/bin/lg-vtysh"

# Si no existe, instalarlo (ver sección anterior de instalación)
```

---

**💡 Consejos para múltiples routers remotos**

**Ejemplo: 3 routers FRR en diferentes ubicaciones**

```json
{
  "routers": [
    {
      "id": "frr_bsas",
      "name": "Buenos Aires",
      "location": "Argentina - BSAS",
      "backend": "frr",
      "frr_host": "10.0.1.1",
      "frr_ssh_user": "lg-remote",
      "enabled": true,
      "supports_ipv6": true
    },
    {
      "id": "frr_cordoba",
      "name": "Córdoba",
      "location": "Argentina - CBA",
      "backend": "frr",
      "frr_host": "10.0.2.1",
      "frr_ssh_user": "lg-remote",
      "enabled": true,
      "supports_ipv6": true
    },
    {
      "id": "frr_nqn",
      "name": "Neuquén",
      "location": "Argentina - NQN",
      "backend": "frr",
      "frr_host": "10.0.3.1",
      "frr_ssh_user": "lg-remote",
      "enabled": true,
      "supports_ipv6": false
    }
  ]
}
```

**Usuarios podrán seleccionar desde qué router ejecutar los comandos!**

---

**📊 Comparación: FRR Local vs FRR Remoto**

| Aspecto | FRR Local | FRR Remoto |
|---------|-----------|------------|
| **Performance** | ⚡ Instantáneo | 🟡 +50-200ms (latencia SSH) |
| **Complejidad** | ✅ Simple | 🟡 Media (SSH keys) |
| **Seguridad** | ✅ Sin red | ⚠️ Requiere SSH seguro |
| **Escalabilidad** | ❌ Solo 1 router | ✅ Múltiples routers |
| **Uso típico** | Looking Glass co-ubicado con router | Looking Glass centralizado |

**Recomendación:**
- **FRR Local**: Si tienes un solo router y el Looking Glass está en el mismo servidor
- **FRR Remoto**: Si tienes múltiples routers en diferentes ubicaciones

---

#### 🔍 Habilitar Traceroute

**¿Qué es Traceroute?**

Traceroute muestra la ruta completa que toman los paquetes desde tu servidor hasta el destino, mostrando cada salto (hop) intermedio. Es útil para:
- Diagnosticar problemas de latencia en rutas específicas
- Identificar dónde se produce pérdida de paquetes
- Ver la topología de la red hasta un destino
- Detectar rutas asimétricas o sub-óptimas

**Estado por defecto:** El traceroute está **habilitado por defecto** en Looking Glass si está incluido en `allowed_commands`.

---

**PASO 1: Instalar traceroute en el sistema**

```bash
# Ubuntu/Debian - Instalar traceroute
sudo apt update
sudo apt install traceroute iputils-tracepath -y

# Verificar instalación
which traceroute
# Esperado: /usr/bin/traceroute

traceroute --version
# Esperado: traceroute versión 2.x.x
```

**Para IPv6:**
```bash
# Verificar que traceroute soporta IPv6
traceroute -6 2001:4860:4860::8888
# O usar traceroute6
sudo apt install traceroute6 -y
```

---

**PASO 2: Verificar permisos de www-data**

```bash
# Probar que www-data puede ejecutar traceroute
sudo -u www-data traceroute -m 5 -w 2 8.8.8.8

# Salida esperada:
# traceroute to 8.8.8.8 (8.8.8.8), 5 hops max, 60 byte packets
#  1  gateway (192.168.1.1)  1.234 ms  1.123 ms  1.456 ms
#  2  10.0.0.1 (10.0.0.1)  5.678 ms  5.432 ms  5.789 ms
#  ...

# Si hay error de permisos:
ls -la /usr/bin/traceroute
# Esperado: -rwxr-xr-x (ejecutable por todos)
```

**Solución si no funciona:**
```bash
# Verificar capabilities (no debería necesitar sudo)
getcap /usr/bin/traceroute
# Esperado: /usr/bin/traceroute = cap_net_raw+ep

# Si no tiene capabilities, agregarlas:
sudo setcap cap_net_raw+ep /usr/bin/traceroute
```

---

**PASO 3: Habilitar en la configuración del Looking Glass**

Edita `config/config.json` y asegúrate de incluir `"trace"` en los comandos permitidos:

```json
{
  "security": {
    "allowed_commands": ["bgp", "ping", "trace"],
    "command_timeout_seconds": 20
  },
  "interface": {
    "ping_count": 5,
    "max_hops_traceroute": 15
  }
}
```

**Parámetros configurables:**

| Parámetro | Valor por defecto | Descripción |
|-----------|-------------------|-------------|
| `allowed_commands` | `["bgp", "ping"]` | Agregar `"trace"` para habilitar traceroute |
| `max_hops_traceroute` | `15` | Máximo de saltos (hops) a rastrear |
| `command_timeout_seconds` | `20` | Timeout total del comando (segundos) |

**Ejemplo con valores personalizados:**
```json
{
  "security": {
    "allowed_commands": ["bgp", "ping", "trace"],
    "command_timeout_seconds": 30
  },
  "interface": {
    "ping_count": 5,
    "max_hops_traceroute": 20
  }
}
```

---

**PASO 4: Reiniciar servicios (si es necesario)**

```bash
# Reiniciar Apache para cargar nueva configuración
sudo systemctl reload apache2

# O si usas Nginx con PHP-FPM
sudo systemctl reload nginx
sudo systemctl reload php7.4-fpm
```

---

**PASO 5: Verificar desde la interfaz web**

1. Abre tu Looking Glass en el navegador
2. Selecciona el comando **"Traceroute"**
3. Ingresa una IP o hostname de prueba (ejemplo: `8.8.8.8`)
4. Haz clic en **"Ejecutar"**
5. Deberías ver la salida con los hops:

```
Traceroute hacia 8.8.8.8 (8.8.8.8), máximo 15 saltos
 1  192.168.1.1 (Gateway)  1.234 ms  1.123 ms  1.456 ms
 2  10.0.0.1 (ISP Router)  5.678 ms  5.432 ms  5.789 ms
 3  172.16.0.1 (Core)  10.123 ms  10.234 ms  10.345 ms
 ...
15  8.8.8.8 (Google DNS)  25.678 ms  25.789 ms  25.890 ms
```

---

**🔧 Troubleshooting**

**Problema: "Comando no permitido"**
```bash
# Verificar que "trace" está en allowed_commands
grep -A5 "allowed_commands" config/config.json
# Debe aparecer: "trace"

# Verificar logs
sudo tail -f /var/log/looking-glass/php-errors.log
```

**Problema: "traceroute: command not found"**
```bash
# Instalar traceroute
sudo apt install traceroute -y
```

**Problema: Timeout o "No route to host"**
```bash
# Verificar conectividad básica primero
ping -c 3 8.8.8.8

# Verificar que el servidor tiene ruta al destino
ip route get 8.8.8.8

# Probar traceroute manual
sudo -u www-data traceroute -m 10 -w 2 8.8.8.8
```

**Problema: Solo muestra asteriscos (* * *)**
```bash
# Esto es NORMAL en algunos saltos
# Significa que el router intermedio no responde a traceroute
# Puede deberse a:
# - Firewall bloqueando ICMP
# - Router configurado para no responder
# - Rate limiting en el router

# No es un error, la ruta continúa
```

**Problema: Muy lento o tarda mucho**
```bash
# Reducir timeout por hop (por defecto 2 segundos)
# Editar FRRAPI.php línea ~590:
$trace_cmd = "traceroute -m {$max_hops} -w 1 {$target}";
#                                        ^^ cambiar a 1 segundo

# O reducir max_hops en config.json:
"max_hops_traceroute": 10
```

---

**📊 Parámetros avanzados de traceroute**

Si necesitas modificar el comportamiento de traceroute, edita `includes/FRRAPI.php`:

```php
// Línea ~585-595
$trace_cmd = sprintf(
    'traceroute -m %d -w 2 %s',  // Parámetros aquí
    $max_hops,
    escapeshellarg($target)
);
```

**Opciones útiles:**
- `-m N`: Máximo de saltos (default: 15)
- `-w N`: Timeout por hop en segundos (default: 2)
- `-q N`: Número de paquetes por hop (default: 3)
- `-I`: Usar ICMP ECHO en lugar de UDP
- `-T`: Usar TCP SYN (requiere root)

**Ejemplo optimizado para velocidad:**
```php
$trace_cmd = sprintf(
    'traceroute -m %d -w 1 -q 1 %s',  // 1 segundo, 1 paquete
    $max_hops,
    escapeshellarg($target)
);
```

---

**💡 Consejos de uso**

**¿Cuándo usar Traceroute vs Ping?**

| Situación | Usar |
|-----------|------|
| Verificar si un destino es alcanzable | **Ping** |
| Medir latencia promedio | **Ping** |
| Ver pérdida de paquetes | **Ping** |
| Identificar dónde falla la ruta | **Traceroute** |
| Ver todos los saltos intermedios | **Traceroute** |
| Diagnosticar latencia en ruta específica | **Traceroute** |
| Ver AS Path de capa 3 | **Traceroute** |

**Limitaciones:**
- No todos los routers responden a traceroute (aparecen como `* * *`)
- Algunos ISPs limitan o bloquean ICMP
- La ruta puede cambiar entre ejecuciones (balanceo de carga)
- No muestra la ruta de retorno (solo ida)

**Seguridad:**
- El traceroute se ejecuta **localmente en el servidor FRR**
- No impacta el rendimiento del router de producción
- Timeout de 20 segundos total para evitar abusos
- Rate limiting aplicado (5 comandos/minuto)

---

### MikroTik RouterOS (Legacy - No Recomendado)

> ⚠️ **ADVERTENCIA**: Este backend se mantiene únicamente para compatibilidad con instalaciones existentes.
>
> **NO SE RECOMIENDA PARA NUEVAS INSTALACIONES** debido a:
> - Impacto significativo en la CPU del router durante consultas
> - **Traceroute puede saturar el router**: Las operaciones de traceroute pueden consumir 30-50% de CPU
> - Sin desarrollo activo: No se agregan nuevas funcionalidades
> - Complejidad adicional de configuración
>
> **Si estás usando MikroTik, considera migrar a FRR** para evitar problemas de rendimiento.

**Habilitar API:**
```bash
# En MikroTik RouterOS
/ip service enable api
/ip service set api port=8728

# Crear usuario de solo lectura
/user add name=lg_user password=SECURE_PASSWORD group=read

# Crear grupo con permisos limitados (recomendado)
/user group add name=looking-glass policy=read,test,api
/user set lg_user group=looking-glass
```

**Configuración en config.json:**
```json
{
  "routers": [
    {
      "id": "mikrotik_router_01",
      "name": "MikroTik Router",
      "location": "Datacenter 2",
      "backend": "mikrotik",
      "api_endpoint_ip": "192.168.1.1",
      "api_port": 8728,
      "api_user": "lg_user",
      "api_password": "SECURE_PASSWORD",
      "enabled": true,
      "supports_ipv6": true
    }
  ]
}
```

## 🎯 Uso

1. **Acceder**: Navega a tu dominio/IP del servidor
2. **Auto-detección**: El sistema detecta automáticamente:
   - Tu IP (IPv4/IPv6)
   - Tu ASN y nombre de la organización (via BGP + PeeringDB)
   - Tu red/prefijo BGP
3. **Seleccionar comando**:
   - **BGP**: Consulta rutas BGP con AS Path y origen
   - **Ping**: Prueba de conectividad (5 paquetes)
   - **Trace**: Traceroute completo (15 saltos max)
4. **Elegir router**: Selecciona desde qué router ejecutar
5. **Ejecutar**: reCAPTCHA verifica automáticamente y ejecuta

## 🛡️ Validaciones de Seguridad

**Input Validation:**
- ✅ Whitelist de caracteres permitidos: `[0-9a-fA-F:./]`
- ✅ Longitud máxima de 45 caracteres
- ✅ Validación de formato IP/prefijo CIDR
- ✅ Blacklist de redes privadas (RFC1918, loopback)

**Command Sanitization:**
- ✅ Blacklist de caracteres peligrosos: `;`, `&`, `|`, `$`, etc.
- ✅ Solo permite comandos `show (bgp|ip|ipv6)`
- ✅ Wrapper vtysh con whitelist estricta
- ✅ Logging de todos los comandos ejecutados

**Session Security:**
- ✅ Cookies: `httponly=1`, `secure=1`, `samesite=Strict`
- ✅ Regeneración de session ID
- ✅ Validación de IP anti-hijacking
- ✅ Expiración automática (30 minutos)

**Rate Limiting:**
- ✅ 5 comandos/minuto por IP
- ✅ 50 comandos/hora por IP
- ✅ Tracking por IP con caché

**reCAPTCHA:**
- ✅ v3 (invisible, score > 0.8)
- ✅ v2 (fallback con checkbox)
- ✅ Doble validación server-side

## 📊 APIs Utilizadas

### PeeringDB API
- **URL**: https://www.peeringdb.com/api
- **Uso**: Obtener nombres de ASN y organizaciones
- **Rate Limit**: 30 req/min
- **Documentación**: https://docs.peeringdb.com/

### RIPEstat API
- **URL**: https://stat.ripe.net/data
- **Uso**: Geolocalización y datos de rutas
- **Rate Limit**: 60 req/min
- **Documentación**: https://stat.ripe.net/docs/

## 🐛 Troubleshooting

### Error: "Archivo de configuración no encontrado"
```bash
# Verificar que config.json existe
ls -la config/config.json

# Verificar permisos
chmod 644 config/config.json
```

### Error: "vtysh: Permission denied"
```bash
# Verificar grupo frrvty
groups www-data
# Debe incluir: frrvty

# Probar wrapper
sudo -u www-data /usr/local/bin/lg-vtysh "show version"

# Ver logs
sudo tail -f /var/log/syslog | grep lg-vtysh
```

### Error: "Router no responde" (MikroTik)
```bash
# Verificar API habilitada
ssh admin@router.ip "/ip service print"

# Test de conexión
telnet router.ip 8728
```

### IPv6 no funciona
```bash
# Verificar BGP IPv6 en FRR
sudo -u www-data /usr/local/bin/lg-vtysh "show bgp ipv6 unicast summary"

# Verificar conectividad IPv6 del servidor
ping6 google.com
```

### Comandos vtysh bloqueados
```bash
# El wrapper solo permite comandos show
# Esto es CORRECTO y es una medida de seguridad

# Ver logs de comandos bloqueados
sudo tail -f /var/log/syslog | grep "Comando bloqueado"
```

## 📝 Estructura del Proyecto

```
lg2/
├── .env                      # Credenciales (NO SUBIR)
├── .env.example             # Plantilla de variables
├── .gitignore               # Archivos a ignorar
├── README.md                # Esta documentación
│
├── config/
│   ├── config.json          # Configuración (NO SUBIR)
│   ├── config.example.json  # Plantilla de configuración
│   └── config-frr-example.json
│
├── public/
│   ├── index.html           # Frontend
│   ├── api.php              # Backend API con hardening
│   └── assets/
│       └── Logo-XL.png      # Tu logo
│
├── includes/
│   ├── FRRAPI.php           # API de FRR con sanitización
│   ├── MikroTikAPI.php      # API de MikroTik
│   └── rpki-validator.php   # Validador RPKI
│
├── scripts/
│   ├── lg-vtysh.example                    # Wrapper seguro de vtysh
│   └── rsyslog-looking-glass.conf.example  # Config logging
│
├── logs/
│   └── looking-glass.log    # Logs de aplicación
│
└── test-security.sh         # Tests de seguridad
```

## 🔄 Actualización

```bash
# 1. Backup de configuración
cp config/config.json config/config.json.backup
cp .env .env.backup

# 2. Actualizar código
git pull origin main

# 3. Verificar cambios en configuración
diff config/config.example.json config/config.json

# 4. Ejecutar tests de seguridad
./test-security.sh

# 5. Reiniciar servicios
sudo systemctl reload apache2
sudo systemctl restart rsyslog
```

## 🧪 Testing

### Tests de Seguridad

```bash
# Configurar la URL de tu API
export LG_API_URL=https://tu-dominio.com/api.php

# Ejecutar suite completa de tests
./test-security.sh

# Test manual de inyección
curl -X POST 'https://lg.example.com/api.php?endpoint=execute' \
  -H "Content-Type: application/json" \
  -d '{"command":"bgp","target":"8.8.8.8; whoami","router_id":"r1"}'
# Esperado: "caracteres no permitidos"

# Test de rate limiting
for i in {1..10}; do
  curl -X POST 'https://lg.example.com/api.php?endpoint=execute' \
    -H "Content-Type: application/json" \
    -d '{"command":"bgp","target":"8.8.8.8","router_id":"r1"}'
done
# Esperado: Bloqueado después de 5 requests
```

### Monitoreo de Logs

```bash
# Logs de comandos vtysh
sudo tail -f /var/log/looking-glass/vtysh.log

# Logs de seguridad
sudo tail -f /var/log/apache2/error.log | grep SECURITY

# Comandos bloqueados
sudo grep "Comando bloqueado" /var/log/syslog
```

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Asegúrate de no incluir información sensible
4. Ejecuta tests de seguridad (`./test-security.sh`)
5. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
6. Push a la rama (`git push origin feature/AmazingFeature`)
7. Abre un Pull Request

### Reportar Vulnerabilidades de Seguridad

**NO** uses issues públicos para vulnerabilidades de seguridad.

Para reportar problemas de seguridad:
- Crea un Security Advisory en GitHub
- O contacta al mantenedor vía email privado
- Tiempo de respuesta: 48-72 horas
- Divulgación responsable: 90 días

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver `LICENSE` para más detalles.

## 💡 Características Futuras

- [ ] Soporte para BIRD routing daemon
- [ ] Gráficos de AS Path visuales
- [ ] Historial de consultas por sesión
- [ ] Exportar resultados (JSON, texto plano)
- [ ] Temas dark/light mode
- [ ] API REST pública documentada
- [ ] Dashboard de estadísticas
- [ ] Migrar rate limiting a Redis
- [ ] Fail2ban integration
- [ ] IPv6 full support en wrapper vtysh

## 📞 Soporte

- **Issues**: https://github.com/dpecile/looking-glass/issues
- **Pull Requests**: Bienvenidos
- **Documentación**: Lee este README y los docs de seguridad
- **Security**: Ver sección de reportar vulnerabilidades arriba

## 🙏 Agradecimientos

- **FRRouting** por el excelente software de routing
- **PeeringDB** por la API pública de datos de redes
- **RIPE NCC** por RIPEstat
- Comunidad de networking y seguridad

---

**Desarrollado con ❤️ para la comunidad de redes**
