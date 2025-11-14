<?php
/**
 * API Router completo que funciona sin .htaccess
 * Maneja URLs como: api.php?endpoint=config o api.php/config
 */

// Cargar variables de entorno desde .env
$envPath = __DIR__ . '/../.env';
if (file_exists($envPath)) {
    $envLines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($envLines as $line) {
        // Ignorar comentarios y líneas vacías
        if (strpos(trim($line), '#') === 0) {
            continue;
        }
        // Parsear línea KEY=VALUE
        if (strpos($line, '=') !== false) {
            list($key, $value) = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value);
            // Solo setear si no existe ya en el entorno
            if (!array_key_exists($key, $_ENV)) {
                $_ENV[$key] = $value;
                putenv("$key=$value");
            }
        }
    }
}

// SEGURIDAD: Configuración de errores según ambiente
// Cargar config para determinar environment
$configPath = __DIR__ . '/../config/config.json';
$environment = 'production'; // Por defecto production
if (file_exists($configPath)) {
    $configContent = file_get_contents($configPath);
    $config = json_decode($configContent, true);
    $environment = $config['environment'] ?? 'production';
}

if ($environment === 'development' && isset($_GET['debug']) && $_GET['debug'] === 'true') {
    // Solo permitir debug en desarrollo
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    // En producción: registrar pero NO mostrar
    error_reporting(E_ALL);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', '/var/log/looking-glass/php-errors.log');
}

header('Content-Type: application/json');

// SEGURIDAD: CORS restrictivo - solo permitir orígenes confiables
// Leer dominios permitidos desde .env
$corsOriginsEnv = $_ENV['CORS_ALLOWED_ORIGINS'] ?? '';
$allowed_origins = [];
if (!empty($corsOriginsEnv)) {
    $allowed_origins = array_map('trim', explode(',', $corsOriginsEnv));
}

// En desarrollo permitir localhost
if ($environment === 'development') {
    $allowed_origins[] = 'http://localhost';
    $allowed_origins[] = 'http://localhost:3000';
    $allowed_origins[] = 'http://127.0.0.1';
}

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$defaultOrigin = $_ENV['CORS_DEFAULT_ORIGIN'] ?? 'https://localhost';

if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    // Origen por defecto si no coincide
    header("Access-Control-Allow-Origin: $defaultOrigin");
}

header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Max-Age: 3600'); // Cache preflight 1 hora

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Incluir las clases de API
require_once __DIR__ . '/../includes/MikroTikAPI.php';
require_once __DIR__ . '/../includes/FRRAPI.php';

class LookingGlassAPI {
    private $config;
    private $clientIP;
    private $rateLimiter;
    private $logger;

    public function __construct() {
        $this->clientIP = $this->getClientIP();
        $this->loadEnvironmentVariables();
        $this->loadConfiguration();
        $this->initializeRateLimiter();
        $this->initializeLogger();
    }
    
    private function log($message, $level = 'info') {
        $logLevel = getenv('LOG_LEVEL') ?: 'error';
        $isDevelopment = ($this->config['environment'] ?? 'production') === 'development';
        
        $levels = ['debug' => 0, 'info' => 1, 'warning' => 2, 'error' => 3];
        $currentLevel = $levels[$logLevel] ?? 3;
        $messageLevel = $levels[$level] ?? 1;
        
        if ($messageLevel >= $currentLevel) {
            error_log("[" . strtoupper($level) . "] " . $message);
        }
    }
    
    private function setSecurityHeaders() {
        // Content Security Policy - ajustado para reCAPTCHA v3
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/ https://www.google.com/ https://www.gstatic.com/; frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/; style-src 'self' 'unsafe-inline' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; img-src 'self' data: https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; connect-src 'self' https://www.google.com/recaptcha/");
        
        // Otros headers de seguridad
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: SAMEORIGIN");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        
        // CORS restrictivo
        header("Access-Control-Allow-Origin: " . ($_SERVER['HTTP_ORIGIN'] ?? '*'));
        header("Access-Control-Allow-Methods: GET, POST");
        header("Access-Control-Allow-Headers: Content-Type");
    }
    
    private function loadEnvironmentVariables() {
        $envFile = __DIR__ . '/../.env';
        if (file_exists($envFile)) {
            $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                if (strpos(trim($line), '#') === 0) continue;
                if (strpos($line, '=') === false) continue;
                
                list($key, $value) = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                
                if (!isset($_ENV[$key])) {
                    putenv("$key=$value");
                    $_ENV[$key] = $value;
                }
            }
        }
    }

    public function handleRequest() {
        try {
            // Establecer headers de seguridad
            $this->setSecurityHeaders();
            
            $method = $_SERVER['REQUEST_METHOD'];
            
            // Obtener endpoint de diferentes fuentes
            $endpoint = $this->getEndpoint();
            
            // Debug logs removidos para producción

            switch ($endpoint) {
                case 'config':
                    if ($method === 'GET') {
                        return $this->getPublicConfig();
                    }
                    break;

                case 'client-info':
                    if ($method === 'GET') {
                        return $this->getClientInfo();
                    }
                    break;

                case 'debug':
                    if ($method === 'GET') {
                        return $this->getDebugInfo();
                    }
                    break;

                case 'execute':
                    if ($method === 'POST') {
                        return $this->executeCommand();
                    }
                    break;

                case 'status':
                    if ($method === 'GET') {
                        return $this->getSystemStatus();
                    }
                    break;

                case '':
                case 'index':
                    // Request sin endpoint específico, mostrar info básica
                    return [
                        'status' => 'online',
                        'message' => 'Looking Glass API',
                        'version' => '1.0.0',
                        'endpoints' => [
                            'config' => '?endpoint=config o /config',
                            'client-info' => '?endpoint=client-info o /client-info',
                            'execute' => '?endpoint=execute o /execute (POST)',
                            'status' => '?endpoint=status o /status',
                            'debug' => '?endpoint=debug o /debug'
                        ],
                        'timestamp' => date('c')
                    ];

                default:
                    error_log("Endpoint no reconocido: '$endpoint'");
                    throw new Exception('Endpoint no encontrado: ' . $endpoint, 404);
            }

            throw new Exception('Método no permitido para endpoint: ' . $endpoint, 405);

        } catch (Exception $e) {
            error_log("Error en handleRequest: " . $e->getMessage());
            http_response_code($e->getCode() ?: 500);
            return [
                'error' => true,
                'message' => $e->getMessage(),
                'timestamp' => date('c'),
                'debug' => [
                    'endpoint_detected' => $this->getEndpoint(),
                    'method' => $_SERVER['REQUEST_METHOD'],
                    'query_string' => $_SERVER['QUERY_STRING'] ?? '',
                    'path_info' => $_SERVER['PATH_INFO'] ?? ''
                ]
            ];
        }
    }

    private function getEndpoint() {
        // Método 1: Query parameter ?endpoint=config
        if (isset($_GET['endpoint'])) {
            return trim($_GET['endpoint'], '/');
        }
        
        // Método 2: PATH_INFO /config
        if (isset($_SERVER['PATH_INFO'])) {
            return trim($_SERVER['PATH_INFO'], '/');
        }
        
        // Método 3: Parsing manual de la URL
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        $scriptName = $_SERVER['SCRIPT_NAME'] ?? '';
        
        // Remover script name de la URI
        if (strpos($requestUri, $scriptName) === 0) {
            $pathInfo = substr($requestUri, strlen($scriptName));
            $pathInfo = trim($pathInfo, '/');
            
            // Remover query string
            if (strpos($pathInfo, '?') !== false) {
                $pathInfo = substr($pathInfo, 0, strpos($pathInfo, '?'));
            }
            
            if (!empty($pathInfo)) {
                return $pathInfo;
            }
        }
        
        // Método 4: Default
        return '';
    }
    
    private function loadConfiguration() {
        // Debug: Log de la ruta esperada
        $configPath = __DIR__ . '/../config/config.json';
        
        // Debug solo en desarrollo
        $logLevel = getenv('LOG_LEVEL') ?: 'error';
        $isDevelopment = ($this->config['environment'] ?? 'production') === 'development';
        
        if ($isDevelopment || $logLevel === 'debug') {
            // Debug config loading removido para producción
        }
        
        if (file_exists($configPath)) {
        }
        
        // Listar archivos en el directorio config
        $configDir = dirname($configPath);
        if (is_dir($configDir)) {
        } else {
        }
        
        if (!file_exists($configPath)) {
            throw new Exception('Archivo de configuración no encontrado en: ' . $configPath, 500);
        }

        $configContent = file_get_contents($configPath);
        
        if ($configContent === false) {
            error_log("Error leyendo archivo de configuración");
            throw new Exception('No se pudo leer el archivo de configuración', 500);
        }
        
        
        $this->config = json_decode($configContent, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("Error JSON: " . json_last_error_msg());
            error_log("Contenido completo del archivo: " . $configContent);
            throw new Exception('Error al parsear configuración: ' . json_last_error_msg(), 500);
        }


        // Validar configuración requerida
        $required = ['environment', 'company', 'routers'];
        foreach ($required as $field) {
            if (!isset($this->config[$field])) {
                error_log("Campo requerido faltante: $field");
                throw new Exception("Configuración incompleta: falta campo '$field'", 500);
            }
        }
        
    }

    private function initializeRateLimiter() {
        // Rate limiting básico usando archivos temporales
        $this->rateLimiter = [
            'commands_per_minute' => $this->config['security']['rate_limit']['commands_per_minute'] ?? 5,
            'commands_per_hour' => $this->config['security']['rate_limit']['commands_per_hour'] ?? 50
        ];
    }

    private function initializeLogger() {
        // Logger básico
        $this->logger = [
            'enabled' => $this->config['logging']['enabled'] ?? true,
            'file' => $this->config['logging']['log_file'] ?? '/tmp/looking-glass.log'
        ];
    }

    private function getPublicConfig() {
        // Función getPublicConfig iniciada
        
        // Verificar que la configuración tenga el campo de entorno
        $environment = $this->config['environment'] ?? 'production';
        
        // En producción, validar que todos los campos requeridos estén presentes
        if ($environment === 'production') {
            $requiredFields = ['company', 'routers', 'security'];
            foreach ($requiredFields as $field) {
                if (!isset($this->config[$field])) {
                    error_log("Campo requerido faltante en producción: $field");
                    throw new Exception("Configuración incompleta: falta el campo '$field'", 500);
                }
            }
        }
        
        // Retornar solo información pública (sin credenciales)
        $publicConfig = [
            'environment' => $environment,
            'company' => $this->config['company']
        ];
        
        
        // Agregar routers sin credenciales
        if (isset($this->config['routers'])) {
            $enabledRouters = array_filter($this->config['routers'], function($r) { return $r['enabled']; });
            
            $publicConfig['routers'] = array_map(function($router) {
                return [
                    'id' => $router['id'],
                    'name' => $router['name'],
                    'location' => $router['location'],
                    'enabled' => $router['enabled'],
                    'supports_ipv6' => $router['supports_ipv6'] ?? true
                    // No incluir credenciales ni endpoints internos
                ];
            }, $enabledRouters);
            
        }
        
        // Agregar configuración de interfaz si existe
        if (isset($this->config['interface'])) {
            $publicConfig['interface'] = $this->config['interface'];
        }
        
        // Agregar configuración de reCAPTCHA (solo site_keys, no secret_keys)
        if (isset($this->config['recaptcha']) && $this->config['recaptcha']['enabled']) {
            $recaptchaConfig = ['enabled' => true];
            
            // Configurar v3
            if (isset($this->config['recaptcha']['v3'])) {
                $siteKeyV3 = $this->config['recaptcha']['v3']['site_key'] ?? '';
                if ($siteKeyV3 === 'USE_ENV_VARIABLE') {
                    $siteKeyV3 = getenv('RECAPTCHA_SITE_KEY') ?: '';
                }
                if (!empty($siteKeyV3) && $siteKeyV3 !== 'USE_ENV_VARIABLE') {
                    $recaptchaConfig['v3'] = ['site_key' => $siteKeyV3];
                }
            }
            
            // Configurar v2
            if (isset($this->config['recaptcha']['v2'])) {
                $siteKeyV2 = $this->config['recaptcha']['v2']['site_key'] ?? '';
                if ($siteKeyV2 === 'USE_ENV_VARIABLE') {
                    $siteKeyV2 = getenv('RECAPTCHA_V2_SITE_KEY') ?: '';
                }
                if (!empty($siteKeyV2) && $siteKeyV2 !== 'USE_ENV_VARIABLE' && $siteKeyV2 !== 'TU_SITE_KEY_V2_AQUI') {
                    $recaptchaConfig['v2'] = ['site_key' => $siteKeyV2];
                }
            }
            
            // Solo agregar si hay al menos una versión configurada
            if (isset($recaptchaConfig['v3']) || isset($recaptchaConfig['v2'])) {
                $publicConfig['recaptcha'] = $recaptchaConfig;
            } else {
            }
        }
        
        // En desarrollo, agregar información adicional de debug
        if ($environment === 'development' || $environment === 'dev') {
            $publicConfig['debug'] = [
                'timestamp' => date('c'),
                'server_ip' => $_SERVER['SERVER_ADDR'] ?? 'unknown',
                'client_ip' => $this->clientIP
            ];
        }
        

        return $publicConfig;
    }

    /**
     * SEGURIDAD: Inicializar sesión con configuración segura
     */
    private function initSecureSession() {
        // Solo iniciar si no está ya iniciada
        if (session_status() === PHP_SESSION_NONE) {
            // Configuración de seguridad de sesión
            ini_set('session.cookie_httponly', '1');
            ini_set('session.cookie_secure', '1'); // Solo HTTPS
            ini_set('session.cookie_samesite', 'Strict');
            ini_set('session.use_strict_mode', '1');
            ini_set('session.use_only_cookies', '1');
            ini_set('session.cookie_lifetime', '0'); // Solo durante navegador abierto

            session_start();

            // Regenerar ID en primera visita
            if (!isset($_SESSION['initiated'])) {
                session_regenerate_id(true);
                $_SESSION['initiated'] = true;
                $_SESSION['created'] = time();
                $_SESSION['user_ip'] = $this->clientIP;
            }

            // Validar IP (prevenir session hijacking)
            if (isset($_SESSION['user_ip']) && $_SESSION['user_ip'] !== $this->clientIP) {
                error_log("SECURITY: Session hijacking detectado. IP original: {$_SESSION['user_ip']}, IP actual: {$this->clientIP}");
                session_destroy();
                $this->initSecureSession();
            }

            // Expirar sesiones antiguas (30 minutos)
            if (isset($_SESSION['created']) && (time() - $_SESSION['created'] > 1800)) {
                session_destroy();
                $this->initSecureSession();
            }
        }
    }

    private function getClientInfo() {
        try {
            // Función getClientInfo iniciada

            // Cache simple en sesión (v2 incluye asn_name)
            $this->initSecureSession();
            $cacheKey = 'client_info_v2_' . $this->clientIP;

            // Si hay datos en caché de menos de 5 minutos, usarlos
            if (isset($_SESSION[$cacheKey]) &&
                isset($_SESSION[$cacheKey . '_time']) &&
                (time() - $_SESSION[$cacheKey . '_time']) < 300) {
                return $_SESSION[$cacheKey];
            }
            
            $clientInfo = [
                'ipv4' => null,
                'ipv6' => null,
                'asn' => null,
                'asn_name' => null,
                'network' => null,
                'country' => null,
                'timestamp' => date('c')
            ];

            // Detectar IP del cliente
            $clientInfo['ipv4'] = $this->clientIP;
            
            // Si es una IP válida, consultar FRR para obtener información
            if (filter_var($this->clientIP, FILTER_VALIDATE_IP)) {
                try {
                    // Usar FRRAPI para consultar información de la IP
                    require_once __DIR__ . '/../includes/FRRAPI.php';
                    $frrApi = new FRRAPI([
                        'host' => 'localhost',
                        'port' => 2601,
                        'password' => null,
                        'ssh_user' => null,
                        'method' => 'vtysh'
                    ]);
                    
                    
                    // Obtener información BGP de la IP del cliente
                    $bgpInfo = $frrApi->getBGPRoute($this->clientIP);
                    
                    // Log para debug
                    error_log("BGP Info para IP {$this->clientIP} (headers: CF=" . ($_SERVER['HTTP_CF_CONNECTING_IP'] ?? 'none') . ", XFF=" . ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? 'none') . "):");
                    error_log(substr($bgpInfo, 0, 500)); // Primeros 500 caracteres
                    
                    // Parsear la respuesta para extraer ASN y red
                    if ($bgpInfo && strpos($bgpInfo, 'Network not in table') === false) {
                        
                        // Buscar prefijo/red primero (está en la primera línea)
                        if (preg_match('/BGP routing table entry for ([^\s,]+)/', $bgpInfo, $matches)) {
                            $clientInfo['network'] = $matches[1];
                            error_log("Red detectada: " . $clientInfo['network']);
                        }
                        
                        // Buscar AS Path - probar múltiples patrones
                        // Patrón 1: Línea que contiene solo números de AS
                        if (preg_match('/^\s*(\d+(?:\s+\d+)*)\s*$/m', $bgpInfo, $matches)) {
                            $asPath = explode(' ', trim($matches[1]));
                            // FRR muestra el AS Path en formato estándar: [local] ... [origen]
                            // El último AS (más a la derecha) es el origen
                            if (!empty($asPath)) {
                                $clientInfo['asn'] = end($asPath);
                                error_log("ASN detectado (patrón 1): " . $clientInfo['asn'] . " de path: " . implode(' ', $asPath));
                            }
                        }
                        // Patrón 2: Buscar "Path #1: (best)" seguido del AS path
                        else if (preg_match('/Path #\d+:\s*\(best\)\s*\n\s*(\d+(?:\s+\d+)*)/m', $bgpInfo, $matches)) {
                            $asPath = explode(' ', trim($matches[1]));
                            // El último AS (más a la derecha) es el origen
                            if (!empty($asPath)) {
                                $clientInfo['asn'] = end($asPath);
                                error_log("ASN detectado (patrón 2): " . $clientInfo['asn'] . " de path: " . implode(' ', $asPath));
                            }
                        }
                        // Patrón 3: Buscar AS path después de "AS path:"
                        else if (preg_match('/AS path:\s*(\d+(?:\s+\d+)*)/i', $bgpInfo, $matches)) {
                            $asPath = explode(' ', trim($matches[1]));
                            // El último AS (más a la derecha) es el origen
                            if (!empty($asPath)) {
                                $clientInfo['asn'] = end($asPath);
                                error_log("ASN detectado (patrón 3): " . $clientInfo['asn'] . " de path: " . implode(' ', $asPath));
                            }
                        }
                    } else {
                        error_log("Red no encontrada en tabla BGP para IP: {$this->clientIP}");
                    }
                    
                } catch (Exception $e) {
                    // Si falla la consulta FRR, continuar sin error
                    error_log("Error consultando FRR para info del cliente: " . $e->getMessage());
                }
            } else {
            }

            // Si se detectó ASN, obtener el nombre de la organización
            if (!empty($clientInfo['asn'])) {
                try {
                    // Intentar primero con PeeringDB (más confiable para ASNs)
                    $peeringDbInfo = $this->getPeeringDbInfo($clientInfo['asn']);
                    if ($peeringDbInfo && isset($peeringDbInfo['name'])) {
                        $clientInfo['asn_name'] = $peeringDbInfo['name'];
                        error_log("Nombre de ASN obtenido de PeeringDB: " . $clientInfo['asn_name']);
                    } else {
                        // Fallback a RIPEstat si PeeringDB falla
                        $ripeInfo = $this->getRipestatInfo($this->clientIP);
                        if ($ripeInfo && isset($ripeInfo['network_name'])) {
                            $clientInfo['asn_name'] = $ripeInfo['network_name'];
                            error_log("Nombre de ASN obtenido de RIPEstat: " . $clientInfo['asn_name']);
                        }
                    }
                } catch (Exception $e) {
                    error_log("Error obteniendo nombre de ASN: " . $e->getMessage());
                }
            }

            // Intentar detectar IPv6 (más complejo desde servidor)
            if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
                foreach ($ips as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        $clientInfo['ipv6'] = $ip;
                        break;
                    }
                }
            }

            // Guardar en caché
            $_SESSION[$cacheKey] = $clientInfo;
            $_SESSION[$cacheKey . '_time'] = time();
            
            
            return $clientInfo;

        } catch (Exception $e) {
            error_log("Error obteniendo información del cliente: " . $e->getMessage());
            return [
                'error' => true,
                'message' => 'No se pudo obtener información del cliente',
                'ipv4' => $this->clientIP,
                'ipv6' => null,
                'timestamp' => date('c')
            ];
        }
    }

    private function getRipestatInfo($ip) {
        try {
            $results = [
                'asn' => null,
                'country' => null,
                'network_name' => null
            ];

            // Obtener ASN
            $asnUrl = "https://stat.ripe.net/data/network-info/data.json?resource=" . urlencode($ip);
            $asnData = $this->makeHttpRequest($asnUrl);
            
            if ($asnData && isset($asnData['data']['asns']) && !empty($asnData['data']['asns'])) {
                $results['asn'] = $asnData['data']['asns'][0];
            }

            // Obtener geolocalización
            $geoUrl = "https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=" . urlencode($ip);
            $geoData = $this->makeHttpRequest($geoUrl);
            
            if ($geoData && isset($geoData['data']['located_resources'])) {
                $results['country'] = $geoData['data']['located_resources'][0]['location'] ?? null;
            }

            return $results;

        } catch (Exception $e) {
            error_log("Error consultando RIPEstat: " . $e->getMessage());
            return null;
        }
    }

    private function getPeeringDbInfo($asn) {
        try {
            $url = "https://www.peeringdb.com/api/net?asn=" . urlencode($asn);
            $data = $this->makeHttpRequest($url);
            
            if ($data && isset($data['data']) && !empty($data['data'])) {
                return $data['data'][0];
            }

            return null;

        } catch (Exception $e) {
            error_log("Error consultando PeeringDB: " . $e->getMessage());
            return null;
        }
    }

    private function makeHttpRequest($url, $timeout = 3) {
        $context = stream_context_create([
            'http' => [
                'timeout' => $timeout, // Reducido a 3 segundos por defecto
                'user_agent' => 'Looking Glass API/1.0',
                'method' => 'GET',
                'ignore_errors' => true
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false
            ]
        ]);

        $response = @file_get_contents($url, false, $context);
        
        if ($response === false) {
            throw new Exception("HTTP request failed for: $url");
        }

        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Invalid JSON response from: $url");
        }

        return $data;
    }

    private function getSystemStatus() {
        return [
            'status' => 'operational',
            'version' => '1.0.0',
            'environment' => $this->config['environment'],
            'timestamp' => date('c'),
            'routers_available' => count(array_filter($this->config['routers'], function($r) { 
                return $r['enabled']; 
            })),
            'client_ip' => $this->clientIP
        ];
    }

    private function getDebugInfo() {
        $configPath = __DIR__ . '/../config/config.json';
        $configDir = dirname($configPath);
        
        $debugInfo = [
            'php_version' => PHP_VERSION,
            'script_location' => __FILE__,
            'working_directory' => getcwd(),
            'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? 'N/A',
            'script_name' => $_SERVER['SCRIPT_NAME'] ?? 'N/A',
            'config' => [
                'expected_path' => $configPath,
                'absolute_path' => realpath($configPath),
                'file_exists' => file_exists($configPath),
                'is_readable' => is_readable($configPath),
                'file_size' => file_exists($configPath) ? filesize($configPath) : 0,
                'permissions' => file_exists($configPath) ? substr(sprintf('%o', fileperms($configPath)), -4) : 'N/A'
            ],
            'directories' => [
                'config_dir_exists' => is_dir($configDir),
                'config_dir_readable' => is_readable($configDir),
                'config_dir_contents' => []
            ],
            'server_info' => [
                'user' => get_current_user(),
                'temp_dir' => sys_get_temp_dir(),
                'include_path' => get_include_path()
            ]
        ];
        
        // Listar archivos en directorio config
        if (is_dir($configDir)) {
            $files = scandir($configDir);
            foreach ($files as $file) {
                if ($file !== '.' && $file !== '..') {
                    $fullPath = $configDir . '/' . $file;
                    $debugInfo['directories']['config_dir_contents'][] = [
                        'name' => $file,
                        'size' => filesize($fullPath),
                        'readable' => is_readable($fullPath),
                        'permissions' => substr(sprintf('%o', fileperms($fullPath)), -4)
                    ];
                }
            }
        }
        
        // Intentar leer el contenido del config si existe
        if (file_exists($configPath)) {
            $content = file_get_contents($configPath);
            if ($content !== false) {
                $debugInfo['config']['content_preview'] = substr($content, 0, 500);
                $debugInfo['config']['content_length'] = strlen($content);
                
                // Intentar parsear JSON
                $parsed = json_decode($content, true);
                $debugInfo['config']['json_valid'] = (json_last_error() === JSON_ERROR_NONE);
                $debugInfo['config']['json_error'] = json_last_error_msg();
                
                if ($parsed) {
                    $debugInfo['config']['parsed_keys'] = array_keys($parsed);
                }
            } else {
                $debugInfo['config']['read_error'] = 'No se pudo leer el archivo';
            }
        }
        
        return $debugInfo;
    }

    private function executeCommand() {
        // Verificar rate limiting
        $this->checkRateLimit();

        // Obtener datos del POST
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input) {
            throw new Exception('Datos de entrada inválidos', 400);
        }

        // Validar parámetros requeridos
        $required = ['command', 'target', 'router_id'];
        foreach ($required as $param) {
            if (empty($input[$param])) {
                throw new Exception("Parámetro requerido: $param", 400);
            }
        }

        $command = $input['command'];
        $target = $input['target'];
        $routerId = $input['router_id'];
        $protocol = $input['protocol'] ?? 'ipv4';
        
        // Verificar reCAPTCHA si está habilitado
        if (isset($this->config['recaptcha']) && $this->config['recaptcha']['enabled']) {
            $recaptchaResponse = $input['recaptcha_response'] ?? '';
            $recaptchaVersion = $input['recaptcha_version'] ?? 'v3';
            
            $verificationResult = $this->verifyRecaptcha($recaptchaResponse, $recaptchaVersion);
            
            if ($verificationResult === false) {
                throw new Exception('Verificación reCAPTCHA fallida', 403);
            } else if ($verificationResult === 'low_score') {
                // Score bajo en v3, el frontend debería mostrar v2
                throw new Exception('Verificación fallida: score bajo', 403);
            }
        }

        // Validar comando
        $allowedCommands = $this->config['security']['allowed_commands'] ?? ['bgp', 'ping', 'trace'];
        if (!in_array($command, $allowedCommands)) {
            throw new Exception('Comando no permitido', 400);
        }

        // Validar target IP
        $this->validateTarget($target, $protocol);

        // Buscar configuración del router
        $router = $this->findRouter($routerId);
        if (!$router) {
            throw new Exception('Router no encontrado', 400);
        }

        // Log del comando
        $this->logCommand($command, $target, $router['name']);

        // Verificar si estamos en modo desarrollo o si el router no tiene credenciales
        if ($this->config['environment'] === 'development' || 
            empty($router['api_endpoint_ip']) || 
            empty($router['api_user']) || 
            empty($router['api_password'])) {
            // Usar simulación
            return $this->executeSimulatedCommand($command, $target, $router, $protocol);
        }

        // Determinar el backend a usar
        $backend = $router['backend'] ?? 'mikrotik';
        
        try {
            switch ($backend) {
                case 'frr':
                    // Ejecutar comando usando FRR
                    return $this->executeFRRCommand($command, $target, $router, $protocol);
                    
                case 'mikrotik':
                default:
                    // Ejecutar comando real en MikroTik
                    return $this->executeMikroTikCommand($command, $target, $router, $protocol);
            }
        } catch (Exception $e) {
            // Si falla la conexión real, intentar con simulación
            error_log("Error conectando a " . $backend . ": " . $e->getMessage());
            $result = $this->executeSimulatedCommand($command, $target, $router, $protocol);
            $result['warning'] = 'No se pudo conectar al backend ' . $backend . '. Mostrando datos de simulación. Error: ' . $e->getMessage();
            return $result;
        }
    }

    private function executeMikroTikCommand($command, $target, $router, $protocol) {
        $startTime = microtime(true);
        
        
        // Crear instancia de la API con timeout reducido
        $api = new MikroTikAPI($this->config['security']['command_timeout_seconds'] ?? 10, false); // Debug desactivado para mayor velocidad
        
        try {
            // Conectar al router
            
            if (!$api->connect($router['api_endpoint_ip'], $router['api_port'], $router['api_user'], $router['api_password'])) {
                throw new Exception('No se pudo conectar al router MikroTik');
            }
            
            
            // Ejecutar comando según el tipo
            switch ($command) {
                case 'bgp':
                    $result = $this->executeBGPCommand($api, $target, $protocol);
                    break;
                    
                case 'ping':
                    $result = $this->executePingCommand($api, $target, $protocol);
                    break;
                    
                case 'trace':
                    $result = $this->executeTraceCommand2($api, $target, $protocol);
                    break;
                    
                default:
                    throw new Exception('Comando no soportado: ' . $command);
            }
            
            // Desconectar
            $api->disconnect();
            
            $executionTime = round((microtime(true) - $startTime) * 1000, 2);
            
            return [
                'success' => true,
                'command' => $command,
                'target' => $target,
                'router' => $router['name'],
                'protocol' => $protocol,
                'result' => $result,
                'execution_time_ms' => $executionTime,
                'timestamp' => date('c'),
                'source' => 'mikrotik'
            ];
            
        } catch (Exception $e) {
            $api->disconnect();
            throw $e;
        }
    }
    
    private function executeBGPCommand($api, $target, $protocol) {
        
        // Primero intentar buscar la ruta exacta
        if ($protocol === 'ipv6') {
            $command = ['/ipv6/route/print', '?dst-address=' . $target];
        } else {
            $command = ['/ip/route/print', '?dst-address=' . $target];
        }
        
        $response = $api->execute($command);
        
        // Si no encuentra la ruta exacta, buscar con menos especificidad
        if (empty($response)) {
            
            // Extraer la IP base del target
            $targetParts = explode('/', $target);
            $targetIp = $targetParts[0];
            
            // Buscar rutas que contengan esta IP
            if ($protocol === 'ipv6') {
                // Para IPv6, buscar por prefijo
                $command = ['/ipv6/route/print', 
                    '?bgp=yes',
                    '=.proplist=dst-address,gateway,bgp-as-path,distance,active'
                ];
            } else {
                // Para IPv4, intentar buscar con comodín
                $ipParts = explode('.', $targetIp);
                if (count($ipParts) >= 3) {
                    // Buscar por los primeros 3 octetos
                    $searchPrefix = $ipParts[0] . '.' . $ipParts[1] . '.' . $ipParts[2];
                    $command = ['/ip/route/print',
                        '~dst-address=' . $searchPrefix,
                        '=.proplist=dst-address,gateway,bgp-as-path,distance,active,bgp'
                    ];
                } else {
                    // Fallback: obtener solo ruta por defecto
                    $command = ['/ip/route/print', 
                        '?dst-address=0.0.0.0/0',
                        '?bgp=yes'
                    ];
                }
            }
            
            $response = $api->execute($command);
            
            // Si aún no hay respuesta, usar ruta por defecto
            if (empty($response)) {
                $command = ['/ip/route/print', '?dst-address=0.0.0.0/0', '?active=yes'];
                $response = $api->execute($command);
            }
        }
        
        if (empty($response)) {
            return "No se encontraron rutas BGP para $target\n\n" .
                   "Nota: La red solicitada puede ser una red local o no anunciada por BGP.";
        }
        
        // Formatear respuesta
        $output = "BGP routing table entry for $target (" . strtolower($protocol) . ")\n";
        $output .= "================================================\n\n";
        
        foreach ($response as $route) {
            $output .= "Destino: " . ($route['dst-address'] ?? $target) . "\n";
            $output .= "Gateway: " . ($route['gateway'] ?? 'N/A') . "\n";
            $output .= "Distancia: " . ($route['distance'] ?? 'N/A') . "\n";
            $output .= "Tipo: " . (isset($route['bgp']) && $route['bgp'] === 'true' ? 'BGP' : 'Local/Static') . "\n";
            $output .= "Activa: " . (isset($route['active']) && $route['active'] === 'true' ? 'Sí' : 'No') . "\n";
            
            if (isset($route['bgp-as-path']) && !empty($route['bgp-as-path'])) {
                $output .= "AS Path: " . $route['bgp-as-path'] . "\n";
            }
            if (isset($route['bgp-local-pref'])) {
                $output .= "Local Preference: " . $route['bgp-local-pref'] . "\n";
            }
            if (isset($route['bgp-origin'])) {
                $output .= "Origin: " . $route['bgp-origin'] . "\n";
            }
            if (isset($route['bgp-communities']) && !empty($route['bgp-communities'])) {
                $output .= "Communities: " . $route['bgp-communities'] . "\n";
            }
            if (isset($route['comment']) && !empty($route['comment'])) {
                $output .= "Comentario: " . $route['comment'] . "\n";
            }
            
            $output .= "\n";
        }
        
        return $output;
    }
    
    /**
     * Verificar si una ruta contiene el prefijo solicitado
     */
    private function isRouteMatch($target, $route) {
        // Simplificación: verificar si el inicio coincide
        // En un caso real deberías hacer comparación de CIDR
        $targetBase = explode('/', $target)[0];
        $routeBase = explode('/', $route)[0];
        
        // Si es la misma red exacta
        if ($target === $route) {
            return true;
        }
        
        // Si el target está contenido en una ruta más general (ej: 0.0.0.0/0)
        if ($route === '0.0.0.0/0' || $route === '::/0') {
            return true;
        }
        
        // Comparación básica de prefijos
        return strpos($targetBase, $routeBase) === 0;
    }
    
    private function executePingCommand($api, $target, $protocol) {
        $count = $this->config['interface']['ping_count'] ?? 5;
        
        // Construir comando ping para MikroTik
        $command = ['/ping', 
            '=address=' . $target, 
            '=count=' . $count,
            '=interval=1'
        ];
        
        if ($protocol === 'ipv6') {
            $command[] = '=src-address=[::/0]';
        }
        
        $response = $api->execute($command);
        
        // Formatear respuesta
        $output = "PING $target (" . strtoupper($protocol) . ")\n";
        $output .= "================================================\n\n";
        
        $sent = 0;
        $received = 0;
        $avgTime = 0;
        $times = [];
        
        foreach ($response as $ping) {
            if (isset($ping['time'])) {
                $sent++;
                if ($ping['time'] !== 'timeout') {
                    $received++;
                    $time = str_replace('ms', '', $ping['time']);
                    $times[] = floatval($time);
                    $output .= sprintf("%d bytes from %s: time=%sms ttl=%s\n", 
                        $ping['size'] ?? 64,
                        $ping['host'] ?? $target,
                        $ping['time'],
                        $ping['ttl'] ?? 'N/A'
                    );
                } else {
                    $output .= "Request timeout\n";
                }
            }
        }
        
        if (count($times) > 0) {
            $avgTime = array_sum($times) / count($times);
        }
        
        $loss = $sent > 0 ? round((($sent - $received) / $sent) * 100, 2) : 100;
        
        $output .= "\n--- $target ping statistics ---\n";
        $output .= "$sent packets transmitted, $received received, $loss% packet loss\n";
        
        if (count($times) > 0) {
            $output .= sprintf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n", 
                min($times), $avgTime, max($times));
        }
        
        return $output;
    }
    
    private function executeTraceCommand($api, $target, $protocol) {
        $maxHops = $this->config['interface']['max_hops_traceroute'] ?? 15;
        
        // Construir comando traceroute para MikroTik
        $command = ['/tool/traceroute',
            '=address=' . $target,
            '=max-hops=' . $maxHops,
            '=use-dns=yes'
        ];
        
        if ($protocol === 'ipv6') {
            $command[] = '=src-address=[::/0]';
        }
        
        $response = $api->execute($command);
        
        // Formatear respuesta
        $output = "Traceroute to $target (" . strtoupper($protocol) . ")\n";
        $output .= "================================================\n\n";
        
        $lastHop = 0;
        foreach ($response as $hop) {
            if (isset($hop['hop'])) {
                $hopNum = intval($hop['hop']);
                
                // Rellenar saltos perdidos
                while ($lastHop < $hopNum - 1) {
                    $lastHop++;
                    $output .= sprintf("%2d  * * *\n", $lastHop);
                }
                
                $output .= sprintf("%2d  %s (%s)  %sms\n",
                    $hopNum,
                    $hop['host'] ?? '*',
                    $hop['address'] ?? '*',
                    $hop['time'] ?? '*'
                );
                
                $lastHop = $hopNum;
            }
        }
        
        return $output;
    }

    private function executeFRRCommand($command, $target, $router, $protocol) {
        $startTime = microtime(true);
        
        
        // Crear instancia de la API FRR
        $api = new FRRAPI(
            $router['frr_host'] ?? 'localhost',
            $router['frr_ssh_user'] ?? 'www-data',
            $this->config['security']['command_timeout_seconds'] ?? 10,
            false // Debug desactivado para mayor velocidad
        );
        
        try {
            // Ejecutar comando según el tipo
            switch ($command) {
                case 'bgp':
                    $result = $api->getBGPRoute($target, $protocol);
                    break;
                    
                case 'ping':
                    $count = $this->config['interface']['ping_count'] ?? 5;
                    $result = $api->executePing($target, $count, $protocol);
                    break;
                    
                case 'trace':
                    $maxHops = $this->config['interface']['max_hops_traceroute'] ?? 15;
                    $rawResult = $api->executeTraceroute($target, $maxHops, $protocol);
                    $result = $this->formatTracerouteResult($rawResult, $target, $protocol);
                    break;
                    
                default:
                    throw new Exception('Comando no soportado: ' . $command);
            }
            
            $executionTime = round((microtime(true) - $startTime) * 1000, 2);

            // Agregar información del router al resultado para comandos BGP
            $header = "";
            if ($command === 'bgp') {
                $header = "Network: AS{$this->config['company']['asn']} - {$this->config['company']['name']}\n";
                $header .= "Router: {$router['location']} ({$router['name']})\n";
                $header .= "Command: show bgp " . strtolower($protocol) . " unicast $target\n";

                // Extraer ASN origen del resultado BGP
                $originAsn = null;
                $originAsnName = null;

                // Buscar AS Path en el resultado
                if (preg_match('/^\s*(\d+(?:\s+\d+)*)\s*$/m', $result, $matches)) {
                    $asPath = explode(' ', trim($matches[1]));
                    // FRR muestra el path en formato estándar [local] ... [origen]
                    if (!empty($asPath)) {
                        // El último AS del path (más a la derecha) es el origen
                        $originAsn = end($asPath);

                        // Obtener nombre del ASN origen
                        try {
                            $peeringDbInfo = $this->getPeeringDbInfo($originAsn);
                            if ($peeringDbInfo && isset($peeringDbInfo['name'])) {
                                $originAsnName = $peeringDbInfo['name'];
                            }
                        } catch (Exception $e) {
                            error_log("Error obteniendo nombre de ASN origen: " . $e->getMessage());
                        }
                    }
                }

                // Agregar información del ASN origen si se encontró
                if ($originAsn) {
                    $header .= "Origin ASN: AS{$originAsn}";
                    if ($originAsnName) {
                        $header .= " ({$originAsnName})";
                    }
                    $header .= "\n";
                }

                $header .= "\n";
            }
            
            return [
                'success' => true,
                'command' => $command,
                'target' => $target,
                'router' => $router['name'],
                'protocol' => $protocol,
                'result' => $header . $result,
                'execution_time_ms' => $executionTime,
                'timestamp' => date('c'),
                'source' => 'frr'
            ];
            
        } catch (Exception $e) {
            throw $e;
        }
    }

    private function executeSimulatedCommand($command, $target, $router, $protocol) {
        $startTime = microtime(true);
        
        // Simular latencia realista
        usleep(rand(1000000, 3000000)); // 1-3 segundos
        
        $timestamp = date('c');
        $executionTime = round((microtime(true) - $startTime) * 1000, 2);

        switch ($command) {
            case 'bgp':
                $result = "BGP routing table entry for $target ($protocol)
Consultado desde: {$router['name']} ({$router['location']})
Timestamp: $timestamp
Protocol: " . strtoupper($protocol) . "

Ruta encontrada:
Path: 266687 " . implode(' ', array_rand(array_flip([174, 3356, 1299, 6762]), 2)) . "
  Next-hop: " . $this->generateRandomIP($protocol) . "
  Origin: IGP, localpref 100, valid, external, best
  Communities: 266687:1000 266687:2000

⚠️ SIMULACIÓN - Para pruebas únicamente";
                break;

            case 'ping':
                $count = $this->config['interface']['ping_count'] ?? 5;
                $result = "PING $target ($target) desde {$router['name']}:
Protocol: " . strtoupper($protocol) . "
Timestamp: $timestamp

";
                for ($i = 1; $i <= $count; $i++) {
                    $time = rand(10, 50) . '.' . rand(100, 999);
                    $result .= "64 bytes from $target: icmp_seq=$i time={$time}ms ttl=57\n";
                }
                
                $result .= "\n--- $target ping statistics ---
$count packets transmitted, $count received, 0% packet loss

⚠️ SIMULACIÓN - Para pruebas únicamente";
                break;

            case 'trace':
                $result = "Traceroute to $target desde {$router['name']} ({$router['location']})
Protocol: " . strtoupper($protocol) . "
Timestamp: $timestamp

 1  gateway.local (" . $this->generateRandomIP($protocol) . ")  1." . rand(100, 999) . "ms
 2  core-router (" . $this->generateRandomIP($protocol) . ")  " . rand(5, 15) . "." . rand(100, 999) . "ms
 3  provider-gw (" . $this->generateRandomIP($protocol) . ")  " . rand(15, 25) . "." . rand(100, 999) . "ms
 4  $target  " . rand(25, 35) . "." . rand(100, 999) . "ms

⚠️ SIMULACIÓN - Para pruebas únicamente";
                break;

            default:
                $result = "Comando simulado: $command hacia $target";
        }

        return [
            'success' => true,
            'command' => $command,
            'target' => $target,
            'router' => $router['name'],
            'protocol' => $protocol,
            'result' => $result,
            'execution_time_ms' => $executionTime,
            'timestamp' => $timestamp,
            'source' => 'simulation'
        ];
    }

    private function formatTracerouteResult($rawResult, $target, $protocol) {
        if (!is_array($rawResult) || !isset($rawResult['hops'])) {
            return "Error: No se pudo ejecutar traceroute correctamente.";
        }
        
        $output = "Traceroute to $target (" . strtoupper($protocol) . ")\n";
        $output .= "================================================\n\n";
        
        if (empty($rawResult['hops'])) {
            $output .= "No se encontraron saltos en la ruta.\n";
            return $output;
        }
        
        foreach ($rawResult['hops'] as $hop) {
            $hopNum = $hop['hop'];
            $output .= sprintf("%2d  ", $hopNum);
            
            if (!empty($hop['hosts'])) {
                $host = $hop['hosts'][0];
                if (is_array($host)) {
                    $hostName = $host['name'];
                    if (!empty($host['ip']) && $host['ip'] !== $host['name']) {
                        $hostName .= " (" . $host['ip'] . ")";
                    }
                } else {
                    $hostName = $host;
                }
                $output .= $hostName;
                
                if (!empty($hop['times'])) {
                    $avgTime = array_sum($hop['times']) / count($hop['times']);
                    $output .= sprintf("  %.3fms", $avgTime);
                } else {
                    $output .= "  *";
                }
            } else {
                $output .= "* * *";
            }
            
            $output .= "\n";
        }
        
        return $output;
    }

    private function generateRandomIP($protocol) {
        if ($protocol === 'ipv6') {
            return '2001:db8:' . dechex(rand(0, 65535)) . '::' . dechex(rand(0, 65535));
        } else {
            return rand(1, 254) . '.' . rand(1, 254) . '.' . rand(1, 254) . '.' . rand(1, 254);
        }
    }

    private function findRouter($routerId) {
        foreach ($this->config['routers'] as $router) {
            if ($router['id'] === $routerId && $router['enabled']) {
                return $router;
            }
        }
        return null;
    }

    private function validateTarget($target, $protocol) {
        // SEGURIDAD: Validar caracteres permitidos antes de cualquier otra validación
        // Solo permitir: números, letras a-f (hex), puntos, dos puntos, slash
        if (!preg_match('/^[0-9a-fA-F:.\\/]+$/', $target)) {
            error_log("SECURITY: Target bloqueado por caracteres inválidos: $target desde IP: {$this->clientIP}");
            throw new Exception('Target contiene caracteres no permitidos', 400);
        }

        // Validar longitud razonable
        if (strlen($target) > 45) {
            error_log("SECURITY: Target bloqueado por longitud excesiva: $target desde IP: {$this->clientIP}");
            throw new Exception('Target excede longitud máxima', 400);
        }

        // Validar formato de IP/prefijo
        if ($protocol === 'ipv6') {
            if (!filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && !$this->isValidIPv6Prefix($target)) {
                throw new Exception('IPv6 inválida', 400);
            }
        } else {
            if (!filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && !$this->isValidIPv4Prefix($target)) {
                throw new Exception('IPv4 inválida', 400);
            }
        }
    }

    private function isValidIPv4Prefix($prefix) {
        if (!strpos($prefix, '/')) return false;
        [$ip, $mask] = explode('/', $prefix);
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && 
               is_numeric($mask) && $mask >= 0 && $mask <= 32;
    }

    private function isValidIPv6Prefix($prefix) {
        if (!strpos($prefix, '/')) return false;
        [$ip, $mask] = explode('/', $prefix);
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && 
               is_numeric($mask) && $mask >= 0 && $mask <= 128;
    }

    private function checkRateLimit() {
        $ip = $this->clientIP;
        $cacheDir = sys_get_temp_dir() . '/lg_rate_limit/';
        
        // Crear directorio si no existe
        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0777, true);
        }
        
        // Archivos para tracking
        $minuteFile = $cacheDir . md5($ip . date('Y-m-d-H-i')) . '.minute';
        $hourFile = $cacheDir . md5($ip . date('Y-m-d-H')) . '.hour';
        
        // Contar requests por minuto
        $minuteCount = file_exists($minuteFile) ? (int)file_get_contents($minuteFile) : 0;
        $minuteCount++;
        file_put_contents($minuteFile, $minuteCount);
        
        // Contar requests por hora
        $hourCount = file_exists($hourFile) ? (int)file_get_contents($hourFile) : 0;
        $hourCount++;
        file_put_contents($hourFile, $hourCount);
        
        // Verificar límites - usar variables de entorno si existen
        $limitsPerMinute = (int)(getenv('RATE_LIMIT_PER_MINUTE') ?: ($this->rateLimiter['commands_per_minute'] ?? 10));
        $limitsPerHour = (int)(getenv('RATE_LIMIT_PER_HOUR') ?: ($this->rateLimiter['commands_per_hour'] ?? 100));
        
        if ($minuteCount > $limitsPerMinute) {
            throw new Exception("Límite de rate excedido: máximo $limitsPerMinute comandos por minuto", 429);
        }
        
        if ($hourCount > $limitsPerHour) {
            throw new Exception("Límite de rate excedido: máximo $limitsPerHour comandos por hora", 429);
        }
        
        // Limpiar archivos antiguos (más de 2 horas)
        $files = glob($cacheDir . '*.minute') + glob($cacheDir . '*.hour');
        $now = time();
        foreach ($files as $file) {
            if ($now - filemtime($file) > 7200) {
                @unlink($file);
            }
        }
        
        return true;
    }

    private function logCommand($command, $target, $router) {
        if (!$this->logger['enabled']) return;

        $logEntry = [
            'timestamp' => date('c'),
            'client_ip' => $this->clientIP,
            'command' => $command,
            'target' => $target,
            'router' => $router,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];

        // Intentar escribir el log, pero no fallar si hay error
        @file_put_contents(
            $this->logger['file'], 
            json_encode($logEntry) . "\n", 
            FILE_APPEND | LOCK_EX
        );
    }
    
    private function verifyRecaptcha($response, $version = 'v3') {
        if (empty($response)) {
            return false;
        }
        
        // Determinar qué secret key usar según la versión
        if ($version === 'v2') {
            // Primero intentar obtener de config, luego de env
            $secretKey = $this->config['recaptcha']['v2']['secret_key'] ?? '';
            if ($secretKey === 'USE_ENV_VARIABLE' || empty($secretKey)) {
                $secretKey = getenv('RECAPTCHA_V2_SECRET_KEY') ?: '';
            }
        } else {
            // v3 por defecto
            $secretKey = $this->config['recaptcha']['v3']['secret_key'] ?? '';
            if ($secretKey === 'USE_ENV_VARIABLE' || empty($secretKey)) {
                $secretKey = getenv('RECAPTCHA_V3_SECRET_KEY') ?: '';
            }
        }
        
        // Log de secret key removido para producción
        
        if (empty($secretKey) || $secretKey === 'TU_SECRET_KEY_AQUI' || $secretKey === 'USE_ENV_VARIABLE') {
            error_log("reCAPTCHA: Secret key no configurada correctamente");
            return false;
        }
        
        $url = 'https://www.google.com/recaptcha/api/siteverify';
        $data = [
            'secret' => $secretKey,
            'response' => $response,
            'remoteip' => $this->clientIP
        ];
        
        // Logs de verificación removidos para producción
        
        $options = [
            'http' => [
                'method' => 'POST',
                'header' => 'Content-Type: application/x-www-form-urlencoded',
                'content' => http_build_query($data),
                'timeout' => 5
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false
            ]
        ];
        
        $context = stream_context_create($options);
        $result = @file_get_contents($url, false, $context);
        
        if ($result === false) {
            error_log("reCAPTCHA: Error al verificar con Google");
            return false;
        }
        
        $responseData = json_decode($result, true);
        
        // Log de respuesta removido para producción
        
        if ($responseData && isset($responseData['success']) && $responseData['success']) {
            // Para reCAPTCHA v3, verificar el score
            if ($version === 'v3' && isset($responseData['score'])) {
                $score = $responseData['score'];
                $action = $responseData['action'] ?? 'unknown';
                $minScore = 0.8; // Umbral alto como querías
                
                // Solo loguear scores bajos
                if ($score < $minScore) {
                    error_log("reCAPTCHA v3: Score bajo detectado - Score: $score, IP: " . $this->clientIP);
                }
                
                if ($score >= $minScore) {
                    return true;
                } else {
                    return 'low_score'; // Indicar que necesita v2
                }
            }
            
            // Para reCAPTCHA v2, solo verificar success
            if ($version === 'v2') {
                return true;
            }
            
            // Si no hay score pero success es true
            return true;
        }
        
        error_log("reCAPTCHA $version: Verificación fallida");
        return false;
    }
    
    /**
     * SEGURIDAD: Obtener IP real del cliente validando proxies confiables
     */
    private function getClientIP() {
        // Lista de proxies/load balancers confiables
        $trusted_proxies = [
            '127.0.0.1',
            '::1',
            // Agregar IPs de tus load balancers/proxies aquí
            // Ejemplo: '10.0.0.1', '10.0.0.2'
        ];

        // Rangos de Cloudflare (si usas Cloudflare)
        $cloudflare_ranges = [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
        ];

        $remote_addr = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

        // Verificar si la conexión viene de un proxy confiable
        $is_trusted = in_array($remote_addr, $trusted_proxies);

        // Verificar rangos de Cloudflare
        if (!$is_trusted) {
            foreach ($cloudflare_ranges as $range) {
                if ($this->ipInRange($remote_addr, $range)) {
                    $is_trusted = true;
                    break;
                }
            }
        }

        // Si viene de proxy confiable, usar headers de forwarding
        if ($is_trusted) {
            $headers = [
                'HTTP_CF_CONNECTING_IP',     // Cloudflare
                'HTTP_X_FORWARDED_FOR',      // Load Balancer/Proxy estándar
                'HTTP_X_REAL_IP',            // Nginx proxy
            ];

            foreach ($headers as $header) {
                if (!empty($_SERVER[$header])) {
                    $ips = explode(',', $_SERVER[$header]);
                    $ip = trim($ips[0]);

                    // Validar que sea una IP válida
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        return $ip;
                    }
                }
            }
        }

        // Si no viene de proxy confiable, usar REMOTE_ADDR directamente
        return $remote_addr;
    }

    /**
     * Verificar si una IP está en un rango CIDR
     */
    private function ipInRange($ip, $range) {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }

        list($subnet, $bits) = explode('/', $range);

        // Solo IPv4 por ahora
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) &&
            filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);
            $mask = -1 << (32 - $bits);

            return ($ip_long & $mask) == ($subnet_long & $mask);
        }

        return false;
    }
}

// Capturar cualquier salida no deseada
ob_start();

// Registrar errores en log en lugar de mostrarlos
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    error_log("PHP Error [$errno]: $errstr in $errfile:$errline");
    return true;
});

// Manejar la request
try {
    $api = new LookingGlassAPI();
    $result = $api->handleRequest();
    
    // Limpiar cualquier salida previa
    ob_clean();
    
    // Asegurar que solo se envíe JSON
    header('Content-Type: application/json');
    echo json_encode($result, JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    // Limpiar cualquier salida previa
    ob_clean();
    
    http_response_code($e->getCode() ?: 500);
    header('Content-Type: application/json');
    echo json_encode([
        'error' => true,
        'message' => $e->getMessage(),
        'timestamp' => date('c')
    ], JSON_PRETTY_PRINT);
} catch (Error $e) {
    // Capturar errores fatales
    ob_clean();
    
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode([
        'error' => true,
        'message' => 'Error interno del servidor: ' . $e->getMessage(),
        'timestamp' => date('c')
    ], JSON_PRETTY_PRINT);
}

// Finalizar el buffer y enviar
ob_end_flush();
?>
