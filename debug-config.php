<?php
/**
 * Script de debug para verificar la configuración del Looking Glass
 * Ejecutar desde la línea de comandos: php debug-config.php
 */

echo "=== LOOKING GLASS DEBUG SCRIPT ===\n\n";

// Información básica de PHP
echo "1. INFORMACIÓN DE PHP:\n";
echo "   PHP Version: " . PHP_VERSION . "\n";
echo "   Script actual: " . __FILE__ . "\n";
echo "   Directorio actual: " . __DIR__ . "\n";
echo "   Working directory: " . getcwd() . "\n\n";

// Verificar estructura de directorios
echo "2. ESTRUCTURA DE DIRECTORIOS:\n";

$baseDir = __DIR__;
$expectedDirs = [
    'public' => $baseDir . '/public',
    'config' => $baseDir . '/config', 
    'includes' => $baseDir . '/includes',
    'logs' => $baseDir . '/logs'
];

foreach ($expectedDirs as $name => $path) {
    $exists = is_dir($path);
    $readable = $exists ? is_readable($path) : false;
    echo "   $name: $path ";
    echo $exists ? "✅ EXISTS" : "❌ MISSING";
    if ($exists) echo $readable ? " (readable)" : " (not readable)";
    echo "\n";
}
echo "\n";

// Verificar archivos importantes
echo "3. ARCHIVOS IMPORTANTES:\n";

$expectedFiles = [
    'config.json' => $baseDir . '/config/config.json',
    'api.php' => $baseDir . '/public/api.php',
    'index.html' => $baseDir . '/public/index.html',
    'MikroTikAPI.php' => $baseDir . '/includes/MikroTikAPI.php'
];

foreach ($expectedFiles as $name => $path) {
    $exists = file_exists($path);
    $readable = $exists ? is_readable($path) : false;
    $size = $exists ? filesize($path) : 0;
    
    echo "   $name: ";
    echo $exists ? "✅ EXISTS" : "❌ MISSING";
    if ($exists) {
        echo " ({$size} bytes)";
        echo $readable ? " (readable)" : " (not readable)";
        echo " [" . substr(sprintf('%o', fileperms($path)), -4) . "]";
    }
    echo "\n";
}
echo "\n";

// Verificar contenido del config.json
echo "4. ANÁLISIS DE config.json:\n";

$configPath = $baseDir . '/config/config.json';

if (file_exists($configPath)) {
    echo "   Archivo encontrado: $configPath\n";
    
    $content = file_get_contents($configPath);
    if ($content === false) {
        echo "   ❌ ERROR: No se pudo leer el archivo\n";
    } else {
        echo "   ✅ Archivo leído correctamente\n";
        echo "   Tamaño: " . strlen($content) . " bytes\n";
        
        // Mostrar preview del contenido
        echo "   Preview (primeros 200 chars):\n";
        echo "   " . str_replace("\n", "\n   ", substr($content, 0, 200)) . "\n";
        
        // Intentar parsear JSON
        $parsed = json_decode($content, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            echo "   ✅ JSON válido\n";
            echo "   Claves principales: " . implode(', ', array_keys($parsed)) . "\n";
            
            // Verificar campos requeridos
            $required = ['environment', 'company', 'routers'];
            echo "   Campos requeridos:\n";
            foreach ($required as $field) {
                $exists = isset($parsed[$field]);
                echo "     $field: " . ($exists ? "✅ OK" : "❌ MISSING") . "\n";
            }
            
            // Información específica
            if (isset($parsed['environment'])) {
                echo "   Environment: " . $parsed['environment'] . "\n";
            }
            if (isset($parsed['company']['name'])) {
                echo "   Company: " . $parsed['company']['name'] . "\n";
            }
            if (isset($parsed['routers'])) {
                echo "   Routers configurados: " . count($parsed['routers']) . "\n";
            }
            
        } else {
            echo "   ❌ ERROR JSON: " . json_last_error_msg() . "\n";
            echo "   Contenido completo:\n";
            echo "   " . str_replace("\n", "\n   ", $content) . "\n";
        }
    }
} else {
    echo "   ❌ Archivo NO encontrado: $configPath\n";
    
    // Sugerir ubicaciones alternativas
    $alternatives = [
        __DIR__ . '/config.json',
        __DIR__ . '/../config/config.json',
        getcwd() . '/config/config.json',
        getcwd() . '/config.json'
    ];
    
    echo "   Verificando ubicaciones alternativas:\n";
    foreach ($alternatives as $alt) {
        if (file_exists($alt)) {
            echo "   ✅ ENCONTRADO EN: $alt\n";
        } else {
            echo "   ❌ No encontrado en: $alt\n";
        }
    }
}
echo "\n";

// Verificar permisos y usuario
echo "5. INFORMACIÓN DE PERMISOS:\n";
echo "   Usuario actual: " . get_current_user() . "\n";
if (function_exists('posix_getuid')) {
    echo "   UID: " . posix_getuid() . "\n";
    echo "   GID: " . posix_getgid() . "\n";
}
echo "\n";

// Verificar extensiones PHP
echo "6. EXTENSIONES PHP REQUERIDAS:\n";
$requiredExtensions = ['json', 'sockets', 'curl'];
foreach ($requiredExtensions as $ext) {
    $loaded = extension_loaded($ext);
    echo "   $ext: " . ($loaded ? "✅ LOADED" : "❌ MISSING") . "\n";
}
echo "\n";

// Sugerencias
echo "7. SUGERENCIAS:\n";

if (!file_exists($configPath)) {
    echo "   • Crear el archivo config.json en: $configPath\n";
    echo "   • Usar el archivo config-dev.json como template\n";
}

if (!is_dir($baseDir . '/logs')) {
    echo "   • Crear directorio logs: mkdir " . $baseDir . "/logs\n";
    echo "   • Dar permisos de escritura: chmod 755 " . $baseDir . "/logs\n";
}

if (!extension_loaded('sockets')) {
    echo "   • Instalar extensión sockets: apt-get install php-sockets (Ubuntu/Debian)\n";
}

echo "\n=== FIN DEBUG SCRIPT ===\n";
?>
