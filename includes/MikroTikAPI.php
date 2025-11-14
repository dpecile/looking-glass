<?php

/**
 * Implementación real de la API de MikroTik para Looking Glass
 * Requiere: php-sockets extension
 */
class MikroTikAPI {
    private $socket;
    private $timeout;
    private $connected = false;
    private $debug = false;
    
    public function __construct($timeout = 30, $debug = false) {
        $this->timeout = $timeout;
        $this->debug = $debug;
    }
    
    /**
     * Conectar al router MikroTik
     */
    public function connect($host, $port, $username, $password) {
        try {
            // Crear socket
            $this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            if (!$this->socket) {
                throw new Exception('No se pudo crear socket: ' . socket_strerror(socket_last_error()));
            }
            
            // Configurar timeout
            socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, 
                ['sec' => $this->timeout, 'usec' => 0]);
            socket_set_option($this->socket, SOL_SOCKET, SO_SNDTIMEO, 
                ['sec' => $this->timeout, 'usec' => 0]);
            
            // Conectar
            if (!socket_connect($this->socket, $host, $port)) {
                throw new Exception('No se pudo conectar: ' . socket_strerror(socket_last_error($this->socket)));
            }
            
            // Autenticar
            if (!$this->login($username, $password)) {
                throw new Exception('Error en proceso de login');
            }
            $this->connected = true;
            
            if ($this->debug) {
                error_log("MikroTik API: Conectado a $host:$port");
            }
            
            return true;
            
        } catch (Exception $e) {
            $this->disconnect();
            throw new Exception('Error de conexión MikroTik: ' . $e->getMessage());
        }
    }
    
    /**
     * Login al router
     */
    private function login($username, $password) {
        try {
            // Primero intentar login con método nuevo (sin challenge)
            if ($this->debug) {
                error_log("MikroTik API: Intentando login directo para $username");
            }
            
            $this->writeCommand([
                '/login',
                '=name=' . $username,
                '=password=' . $password
            ]);
            
            $response = $this->readResponse();
            
            if ($this->debug) {
                error_log("MikroTik API: Respuesta login directo: " . json_encode($response));
            }
            
            // Si no hay error, login exitoso
            if (empty($response) || !isset($response[0]['message'])) {
                if ($this->debug) {
                    error_log("MikroTik API: Login directo exitoso");
                }
                return true;
            }
            
            // Si falla, intentar método con challenge
            if ($this->debug) {
                error_log("MikroTik API: Login directo falló, intentando con challenge");
            }
            
        } catch (Exception $e) {
            if ($this->debug) {
                error_log("MikroTik API: Error en login directo: " . $e->getMessage());
            }
        }
        
        // Método legacy con challenge
        $this->writeCommand(['/login']);
        $response = $this->readResponse();
        
        if ($this->debug) {
            error_log("MikroTik API: Respuesta challenge: " . json_encode($response));
        }
        
        if (!isset($response[0]['ret'])) {
            throw new Exception('No se recibió challenge del router');
        }
        
        // Calcular hash MD5 con challenge
        $challenge = $response[0]['ret'];
        $hash = md5(chr(0) . $password . pack('H*', $challenge));
        
        // Enviar credenciales
        $this->writeCommand([
            '/login',
            '=name=' . $username,
            '=response=00' . $hash
        ]);
        
        $loginResponse = $this->readResponse();
        
        if (isset($loginResponse[0]['message'])) {
            throw new Exception('Login fallido: ' . $loginResponse[0]['message']);
        }
        
        if ($this->debug) {
            error_log("MikroTik API: Login exitoso con challenge para usuario $username");
        }
        
        return true;
    }
    
    /**
     * Ejecutar comando genérico
     */
    public function execute($command) {
        if (!$this->connected) {
            throw new Exception('No conectado al router');
        }
        
        if ($this->debug) {
            error_log("MikroTik API: Ejecutando comando: " . json_encode($command));
        }
        
        try {
            $this->writeCommand($command);
            $response = $this->readResponse();
            
            if ($this->debug) {
                error_log("MikroTik API: Respuesta: " . json_encode($response));
            }
            
            return $response;
        } catch (Exception $e) {
            if ($this->debug) {
                error_log("MikroTik API: Error ejecutando comando: " . $e->getMessage());
            }
            throw $e;
        }
    }
    
    /**
     * COMANDO BGP - Consultar rutas BGP
     */
    public function getBGPRoute($prefix, $protocol = 'ipv4') {
        if (!$this->connected) {
            throw new Exception('No conectado al router');
        }
        
        try {
            if ($protocol === 'ipv6') {
                $command = [
                    '/routing/bgp/route/ipv6/print',
                    '?dst-address=' . $prefix,
                    '?active=true'
                ];
            } else {
                $command = [
                    '/routing/bgp/route/print',
                    '?dst-address=' . $prefix,
                    '?active=true'
                ];
            }
            
            $this->writeCommand($command);
            $response = $this->readResponse();
            
            if ($this->debug) {
                error_log("MikroTik BGP Query: " . json_encode($command));
                error_log("MikroTik BGP Response: " . json_encode($response));
            }
            
            return $this->formatBGPResponse($response, $prefix, $protocol);
            
        } catch (Exception $e) {
            throw new Exception('Error ejecutando consulta BGP: ' . $e->getMessage());
        }
    }
    
    /**
     * COMANDO PING
     */
    public function executePing($target_ip, $count = 5, $protocol = 'ipv4') {
        if (!$this->connected) {
            throw new Exception('No conectado al router');
        }
        
        try {
            $command = [
                '/ping',
                '=address=' . $target_ip,
                '=count=' . $count,
                '=size=56',
                '=interval=1'
            ];
            
            $this->writeCommand($command);
            $response = $this->readResponse();
            
            if ($this->debug) {
                error_log("MikroTik Ping Command: " . json_encode($command));
                error_log("MikroTik Ping Response: " . json_encode($response));
            }
            
            return $this->formatPingResponse($response, $target_ip);
            
        } catch (Exception $e) {
            throw new Exception('Error ejecutando ping: ' . $e->getMessage());
        }
    }
    
    /**
     * COMANDO TRACEROUTE
     */
    public function executeTraceroute($target_ip, $max_hops = 15, $protocol = 'ipv4') {
        if (!$this->connected) {
            throw new Exception('No conectado al router');
        }
        
        try {
            $command = [
                '/tool/traceroute',
                '=address=' . $target_ip,
                '=count=3',
                '=max-hops=' . $max_hops,
                '=timeout=5',
                '=use-dns=yes'
            ];
            
            $this->writeCommand($command);
            $response = $this->readResponse();
            
            if ($this->debug) {
                error_log("MikroTik Traceroute Command: " . json_encode($command));
                error_log("MikroTik Traceroute Response: " . json_encode($response));
            }
            
            return $this->formatTracerouteResponse($response, $target_ip);
            
        } catch (Exception $e) {
            throw new Exception('Error ejecutando traceroute: ' . $e->getMessage());
        }
    }
    
    /**
     * Formatear respuesta BGP
     */
    private function formatBGPResponse($response, $prefix, $protocol) {
        $output = "BGP routing table entry for $prefix ($protocol)\n";
        $output .= "Timestamp: " . date('d/m/Y, H:i:s') . "\n";
        $output .= "Protocol: " . strtoupper($protocol) . "\n\n";
        
        if (empty($response) || !isset($response[0]['dst-address'])) {
            $output .= "No se encontraron rutas BGP para el prefijo especificado.\n";
            return $output;
        }
        
        $route = $response[0];
        
        $output .= "Ruta encontrada:\n";
        $output .= "Path: " . ($route['bgp-as-path'] ?? 'Local') . "\n";
        $output .= "  Next-hop: " . ($route['gateway'] ?? 'N/A') . "\n";
        $output .= "  Origin: " . strtoupper($route['bgp-origin'] ?? 'IGP') . "\n";
        $output .= "  Local Pref: " . ($route['bgp-local-pref'] ?? '100') . "\n";
        $output .= "  MED: " . ($route['bgp-med'] ?? '0') . "\n";
        
        if (isset($route['bgp-communities'])) {
            $output .= "  Communities: " . $route['bgp-communities'] . "\n";
        }
        
        $output .= "  Status: " . ($route['active'] === 'true' ? 'Active, Best' : 'Inactive') . "\n";
        
        return $output;
    }
    
    /**
     * Formatear respuesta Ping
     */
    private function formatPingResponse($response, $target_ip) {
        $output = "PING $target_ip ($target_ip):\n";
        $output .= "Timestamp: " . date('d/m/Y, H:i:s') . "\n\n";
        
        $sent = 0;
        $received = 0;
        $times = [];
        
        foreach ($response as $ping) {
            if (isset($ping['status'])) {
                $sent++;
                if ($ping['status'] === 'reply') {
                    $received++;
                    $time = isset($ping['time']) ? $ping['time'] : 'N/A';
                    $ttl = isset($ping['ttl']) ? $ping['ttl'] : 'N/A';
                    $size = isset($ping['size']) ? $ping['size'] : '56';
                    
                    $output .= "$size bytes from $target_ip: time=$time ttl=$ttl\n";
                    
                    if (is_numeric(str_replace('ms', '', $time))) {
                        $times[] = floatval(str_replace('ms', '', $time));
                    }
                } else {
                    $output .= "Request timeout\n";
                }
            }
        }
        
        $loss = $sent > 0 ? round((($sent - $received) / $sent) * 100, 1) : 100;
        $output .= "\n--- $target_ip ping statistics ---\n";
        $output .= "$sent packets transmitted, $received received, {$loss}% packet loss\n";
        
        if (!empty($times)) {
            $min = min($times);
            $max = max($times);
            $avg = round(array_sum($times) / count($times), 3);
            $output .= "round-trip min/avg/max = {$min}/{$avg}/{$max} ms\n";
        }
        
        return $output;
    }
    
    /**
     * Formatear respuesta Traceroute
     */
    private function formatTracerouteResponse($response, $target_ip) {
        $output = "Traceroute to $target_ip:\n";
        $output .= "Timestamp: " . date('d/m/Y, H:i:s') . "\n\n";
        
        $hop = 1;
        $current_address = '';
        
        foreach ($response as $trace) {
            if (isset($trace['address']) && $trace['address'] !== $current_address) {
                $current_address = $trace['address'];
                $time = isset($trace['time']) ? $trace['time'] : '*';
                $status = isset($trace['status']) ? $trace['status'] : 'timeout';
                
                if ($status === 'reply') {
                    $output .= sprintf("%2d  %s  %s\n", $hop, $current_address, $time);
                } else {
                    $output .= sprintf("%2d  *\n", $hop);
                }
                $hop++;
            }
        }
        
        return $output;
    }
    
    /**
     * Escribir comando al socket
     */
    private function writeCommand($command) {
        foreach ($command as $word) {
            $this->writeWord($word);
        }
        $this->writeWord('');
    }
    
    /**
     * Escribir palabra al socket
     */
    private function writeWord($word) {
        $length = strlen($word);
        
        if ($length < 0x80) {
            $lengthBytes = chr($length);
        } elseif ($length < 0x4000) {
            $lengthBytes = chr(0x80 | ($length >> 8)) . chr($length & 0xFF);
        } elseif ($length < 0x200000) {
            $lengthBytes = chr(0xC0 | ($length >> 16)) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        } else {
            $lengthBytes = chr(0xE0 | ($length >> 24)) . chr(($length >> 16) & 0xFF) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        }
        
        socket_write($this->socket, $lengthBytes . $word);
    }
    
    /**
     * Leer respuesta del socket
     */
    private function readResponse() {
        $response = [];
        $currentItem = [];
        $done = false;
        
        while (!$done) {
            $word = $this->readWord();
            
            if ($word === false) {
                break;
            }
            
            if ($word === '') {
                if (!empty($currentItem)) {
                    $response[] = $currentItem;
                    $currentItem = [];
                }
                continue;
            }
            
            if ($word === '!done') {
                if (!empty($currentItem)) {
                    $response[] = $currentItem;
                }
                $done = true;
            } elseif ($word === '!re') {
                if (!empty($currentItem)) {
                    $response[] = $currentItem;
                    $currentItem = [];
                }
            } elseif ($word === '!trap' || $word === '!fatal') {
                // Error message follows
                continue;
            } elseif (substr($word, 0, 1) === '=' || substr($word, 0, 1) === '.') {
                // Attribute
                $pos = strpos($word, '=', 1);
                if ($pos !== false) {
                    $key = substr($word, 1, $pos - 1);
                    $value = substr($word, $pos + 1);
                    $currentItem[$key] = $value;
                }
            }
        }
        
        return $response;
    }
    
    /**
     * Leer palabra del socket
     */
    private function readWord() {
        $length = $this->readLength();
        if ($length === false) {
            return false;
        }
        
        if ($length === 0) {
            return '';
        }
        
        $word = '';
        while (strlen($word) < $length) {
            $data = socket_read($this->socket, $length - strlen($word));
            if ($data === false) {
                return false;
            }
            $word .= $data;
        }
        
        return $word;
    }
    
    /**
     * Leer longitud del socket
     */
    private function readLength() {
        $byte = socket_read($this->socket, 1);
        if ($byte === false) {
            return false;
        }
        
        $length = ord($byte);
        
        if ($length < 0x80) {
            return $length;
        } elseif ($length < 0xC0) {
            $byte = socket_read($this->socket, 1);
            return (($length & 0x7F) << 8) + ord($byte);
        } elseif ($length < 0xE0) {
            $bytes = socket_read($this->socket, 2);
            return (($length & 0x3F) << 16) + (ord($bytes[0]) << 8) + ord($bytes[1]);
        } else {
            $bytes = socket_read($this->socket, 3);
            return (($length & 0x1F) << 24) + (ord($bytes[0]) << 16) + (ord($bytes[1]) << 8) + ord($bytes[2]);
        }
    }
    
    /**
     * Parsear atributos de respuesta
     */
    private function parseAttributes($sentence) {
        $attributes = [];
        $pairs = explode('=', substr($sentence, 1));
        
        for ($i = 0; $i < count($pairs) - 1; $i += 2) {
            if (isset($pairs[$i + 1])) {
                $key = $pairs[$i];
                $value = $pairs[$i + 1];
                $attributes[$key] = $value;
            }
        }
        
        return $attributes;
    }
    
    /**
     * Desconectar del router
     */
    public function disconnect() {
        if ($this->socket) {
            socket_close($this->socket);
            $this->socket = null;
        }
        $this->connected = false;
        
        if ($this->debug) {
            error_log("MikroTik API: Desconectado");
        }
    }
    
    /**
     * Destructor
     */
    public function __destruct() {
        $this->disconnect();
    }
}

/**
 * Ejemplo de uso:
 */

/*
try {
    $api = new MikroTikAPI(30, true); // 30 segundos timeout, debug habilitado
    
    // Conectar
    $api->connect('192.168.1.1', 8728, 'lg_user', 'password');
    
    // Ejecutar comandos
    $bgp_result = $api->getBGPRoute('8.8.8.0/24', 'ipv4');
    $ping_result = $api->executePing('8.8.8.8', 5);
    $trace_result = $api->executeTraceroute('1.1.1.1', 15);
    
    echo $bgp_result;
    echo $ping_result; 
    echo $trace_result;
    
    // Desconectar (automático en destructor)
    $api->disconnect();
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
*/
?>
