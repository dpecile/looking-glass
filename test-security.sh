#!/bin/bash
# Script de verificación de seguridad para Looking Glass
# Prueba todas las mejoras implementadas

echo "================================"
echo "LOOKING GLASS - SECURITY TESTING"
echo "================================"
echo ""

# CONFIGURACIÓN: Cambiar esta URL a tu dominio
BASE_URL="${LG_API_URL:-https://lg.example.com/api.php}"

if [[ "$BASE_URL" == *"example.com"* ]]; then
    echo "⚠️  ADVERTENCIA: Usando URL de ejemplo."
    echo "   Configura la variable LG_API_URL o edita BASE_URL en este script."
    echo "   Ejemplo: export LG_API_URL=https://tu-dominio.com/api.php"
    echo ""
fi

echo "[1] Test: Inyección de comandos en target"
echo "   Probando: target con caracteres peligrosos..."
RESULT=$(curl -s -X POST "$BASE_URL?endpoint=execute" \
  -H "Content-Type: application/json" \
  -d '{"command":"bgp","target":"8.8.8.8; ls -la","router_id":"frr_router_01"}' | jq -r '.error // .message // "OK"')
echo "   Resultado: $RESULT"
if [[ "$RESULT" == *"no permitidos"* ]] || [[ "$RESULT" == *"inválida"* ]]; then
    echo "   ✅ PASS: Bloqueado correctamente"
else
    echo "   ❌ FAIL: No bloqueado"
fi
echo ""

echo "[2] Test: Caracteres especiales en target"
echo "   Probando: target con \$(whoami)..."
RESULT=$(curl -s -X POST "$BASE_URL?endpoint=execute" \
  -H "Content-Type: application/json" \
  -d '{"command":"bgp","target":"8.8.8.8\$(whoami)","router_id":"frr_router_01"}' | jq -r '.error // .message // "OK"')
echo "   Resultado: $RESULT"
if [[ "$RESULT" == *"no permitidos"* ]] || [[ "$RESULT" == *"inválida"* ]]; then
    echo "   ✅ PASS: Bloqueado correctamente"
else
    echo "   ❌ FAIL: No bloqueado"
fi
echo ""

echo "[3] Test: Rate Limiting"
echo "   Enviando 10 requests rápidas..."
COUNT=0
for i in {1..10}; do
    RESULT=$(curl -s -X POST "$BASE_URL?endpoint=execute" \
      -H "Content-Type: application/json" \
      -d '{"command":"bgp","target":"8.8.8.8","router_id":"frr_router_01"}' | jq -r '.error // "OK"')
    if [[ "$RESULT" == *"Rate limit"* ]]; then
        COUNT=$((COUNT + 1))
    fi
    sleep 0.1
done
echo "   Requests bloqueados: $COUNT de 10"
if [ $COUNT -gt 0 ]; then
    echo "   ✅ PASS: Rate limiting funcionando"
else
    echo "   ⚠️  WARNING: Puede que necesite más requests para activar"
fi
echo ""

echo "[4] Test: CORS restrictivo"
echo "   Probando origen no permitido..."
CORS=$(curl -s -H "Origin: https://evil.com" "$BASE_URL?endpoint=config" -I | grep -i "access-control-allow-origin" | awk '{print $2}')
echo "   CORS header: $CORS"
if [[ "$CORS" != *"evil.com"* ]]; then
    echo "   ✅ PASS: No permite origen malicioso"
else
    echo "   ❌ FAIL: Permite cualquier origen"
fi
echo ""

echo "[5] Test: Display errors deshabilitado"
echo "   Probando endpoint inválido..."
RESULT=$(curl -s "$BASE_URL?endpoint=invalid_endpoint_test")
if [[ "$RESULT" == *"/var/www"* ]] || [[ "$RESULT" == *"Fatal error"* ]] || [[ "$RESULT" == *"Warning:"* ]]; then
    echo "   ❌ FAIL: Expone información del sistema"
else
    echo "   ✅ PASS: No expone paths del servidor"
fi
echo ""

echo "[6] Test: Wrapper vtysh creado"
if [ -f "/usr/local/bin/lg-vtysh" ]; then
    echo "   ✅ PASS: Wrapper existe"
    ls -la /usr/local/bin/lg-vtysh
else
    echo "   ❌ FAIL: Wrapper no encontrado"
fi
echo ""

echo "[7] Test: Logs configurados"
if [ -f "/etc/rsyslog.d/50-looking-glass.conf" ]; then
    echo "   ✅ PASS: Configuración rsyslog existe"
else
    echo "   ❌ FAIL: Configuración rsyslog no encontrada"
fi

if [ -d "/var/log/looking-glass" ]; then
    echo "   ✅ PASS: Directorio de logs existe"
    ls -la /var/log/looking-glass/
else
    echo "   ❌ FAIL: Directorio de logs no existe"
fi
echo ""

echo "[8] Test: Validación de comandos vtysh"
echo "   Probando comando no permitido..."
sudo -u www-data /usr/local/bin/lg-vtysh "configure terminal" 2>&1 | head -1
echo ""

echo "================================"
echo "TESTING COMPLETADO"
echo "================================"
echo ""
echo "Revisa los logs de seguridad:"
echo "  sudo tail -f /var/log/looking-glass/vtysh.log"
echo "  sudo tail -f /var/log/apache2/error.log | grep SECURITY"
echo ""
