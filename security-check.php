#!/usr/bin/env php
<?php
/**
 * Script de verificación de seguridad para Looking Glass
 * Ejecutar: php security-check.php
 */

echo "=== LOOKING GLASS SECURITY CHECK ===\n\n";

$errors = [];
$warnings = [];
$success = [];

// 1. Verificar que .env existe y tiene las claves
echo "1. Verificando variables de entorno...\n";
$envFile = __DIR__ . '/.env';
if (file_exists($envFile)) {
    $success[] = "✓ Archivo .env existe";
    
    $env = parse_ini_file($envFile);
    if (isset($env['RECAPTCHA_SECRET_KEY']) && $env['RECAPTCHA_SECRET_KEY'] !== '') {
        $success[] = "✓ RECAPTCHA_SECRET_KEY configurada";
    } else {
        $errors[] = "✗ RECAPTCHA_SECRET_KEY no configurada en .env";
    }
    
    if (isset($env['RECAPTCHA_SITE_KEY']) && $env['RECAPTCHA_SITE_KEY'] !== '') {
        $success[] = "✓ RECAPTCHA_SITE_KEY configurada";
    } else {
        $errors[] = "✗ RECAPTCHA_SITE_KEY no configurada en .env";
    }
} else {
    $errors[] = "✗ Archivo .env no existe";
}

// 2. Verificar que config.json no tiene claves sensibles
echo "\n2. Verificando config.json...\n";
$configFile = __DIR__ . '/config/config.json';
if (file_exists($configFile)) {
    $config = json_decode(file_get_contents($configFile), true);
    
    if (isset($config['recaptcha']['secret_key']) && 
        $config['recaptcha']['secret_key'] !== 'USE_ENV_VARIABLE') {
        $errors[] = "✗ SECRET_KEY expuesta en config.json!";
    } else {
        $success[] = "✓ SECRET_KEY no está en config.json";
    }
}

// 3. Verificar permisos de archivos
echo "\n3. Verificando permisos de archivos...\n";
$files = [
    '.env' => '0600',
    'config/config.json' => '0644',
    '.htaccess' => '0644'
];

foreach ($files as $file => $expectedPerm) {
    $fullPath = __DIR__ . '/' . $file;
    if (file_exists($fullPath)) {
        $actualPerm = substr(sprintf('%o', fileperms($fullPath)), -4);
        if ($actualPerm === $expectedPerm) {
            $success[] = "✓ $file tiene permisos correctos ($actualPerm)";
        } else {
            $warnings[] = "⚠ $file tiene permisos $actualPerm (esperado: $expectedPerm)";
        }
    }
}

// 4. Verificar que archivos sensibles no son accesibles
echo "\n4. Verificando acceso web a archivos sensibles...\n";
$sensitiveFiles = [
    '/.env',
    '/config/config.json',
    '/.git/config',
    '/security-check.php'
];

$baseUrl = 'http://localhost/lg2';
foreach ($sensitiveFiles as $file) {
    $url = $baseUrl . $file;
    $headers = @get_headers($url);
    if ($headers && strpos($headers[0], '404') !== false) {
        $success[] = "✓ $file no es accesible vía web";
    } else if ($headers && strpos($headers[0], '403') !== false) {
        $success[] = "✓ $file está protegido (403 Forbidden)";
    } else {
        $errors[] = "✗ $file PUEDE SER ACCESIBLE vía web!";
    }
}

// 5. Verificar rate limiting
echo "\n5. Verificando rate limiting...\n";
$rateLimitDir = sys_get_temp_dir() . '/lg_rate_limit/';
if (is_dir($rateLimitDir) && is_writable($rateLimitDir)) {
    $success[] = "✓ Directorio de rate limiting existe y es escribible";
} else {
    $warnings[] = "⚠ Directorio de rate limiting no existe o no es escribible";
}

// Resumen
echo "\n=== RESUMEN ===\n";
echo "Éxitos: " . count($success) . "\n";
echo "Advertencias: " . count($warnings) . "\n";
echo "Errores: " . count($errors) . "\n\n";

if (count($errors) > 0) {
    echo "ERRORES ENCONTRADOS:\n";
    foreach ($errors as $error) {
        echo $error . "\n";
    }
}

if (count($warnings) > 0) {
    echo "\nADVERTENCIAS:\n";
    foreach ($warnings as $warning) {
        echo $warning . "\n";
    }
}

echo "\nVERIFICACIONES EXITOSAS:\n";
foreach ($success as $s) {
    echo $s . "\n";
}

exit(count($errors) > 0 ? 1 : 0);