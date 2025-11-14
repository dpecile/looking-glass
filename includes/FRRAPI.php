<?php

require_once __DIR__ . '/rpki-validator.php';

/**
 * Clase para interactuar con FRR (Free Range Routing)
 * Usa vtysh para ejecutar comandos
 */
class FRRAPI {
    private $vtysh_path = '/usr/bin/vtysh';
    private $timeout;
    private $debug;
    private $host;
    private $ssh_user;
    
    public function __construct($config = []) {
        // Si se pasa un string como primer parámetro (compatibilidad hacia atrás)
        if (is_string($config)) {
            $this->host = $config;
            $this->ssh_user = func_get_arg(1) ?? 'www-data';
            $this->timeout = func_get_arg(2) ?? 10;
            $this->debug = func_get_arg(3) ?? false;
        } else {
            // Configuración por array
            $this->host = $config['host'] ?? 'localhost';
            $this->ssh_user = $config['ssh_user'] ?? 'www-data';
            $this->timeout = $config['timeout'] ?? 10;
            $this->debug = $config['debug'] ?? false;
        }
        
        // Si es localhost, verificar que vtysh existe
        if ($this->host === 'localhost' && !file_exists($this->vtysh_path)) {
            throw new Exception('vtysh no encontrado. ¿Está FRR instalado?');
        }
    }

    /**
     * Sanitizar comando para prevenir inyección
     */
    private function sanitizeCommand($command) {
        // SEGURIDAD: Caracteres peligrosos que podrían permitir inyección de comandos
        $dangerous = [';', '&', '|', '$', '`', '(', ')', '<', '>', "\n", "\r", "\t", '\\', '{', '}'];

        foreach ($dangerous as $char) {
            if (strpos($command, $char) !== false) {
                error_log("SECURITY: Comando vtysh bloqueado por carácter peligroso '$char': $command");
                throw new Exception('Comando contiene caracteres no permitidos');
            }
        }

        // Validar que solo contenga comandos show válidos
        if (!preg_match('/^show (bgp|ip|ipv6) /', $command)) {
            error_log("SECURITY: Comando vtysh bloqueado por no ser comando show válido: $command");
            throw new Exception('Solo se permiten comandos show bgp/ip/ipv6');
        }

        return $command;
    }

    /**
     * Ejecutar comando en vtysh
     */
    private function executeVtysh($command) {
        // SEGURIDAD: Sanitizar comando antes de ejecutar
        $command = $this->sanitizeCommand($command);

        // AUDITORÍA: Registrar todos los comandos vtysh ejecutados
        openlog("looking-glass", LOG_PID, LOG_LOCAL0);
        syslog(LOG_WARNING, sprintf(
            "VTYSH: ip=%s user=%s host=%s cmd=%s",
            $_SERVER['REMOTE_ADDR'] ?? 'cli',
            $_SERVER['PHP_AUTH_USER'] ?? 'anonymous',
            $this->host,
            substr($command, 0, 200) // Limitar longitud
        ));
        closelog();

        if ($this->host === 'localhost') {
            // Ejecución local
            $full_command = sprintf(
                'timeout %d %s -c %s 2>&1',
                $this->timeout,
                escapeshellcmd($this->vtysh_path),
                escapeshellarg($command)
            );
        } else {
            // Ejecución remota via SSH
            $full_command = sprintf(
                'timeout %d ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no %s@%s %s -c %s 2>&1',
                $this->timeout,
                escapeshellarg($this->ssh_user),
                escapeshellarg($this->host),
                escapeshellarg($this->vtysh_path),
                escapeshellarg($command)
            );
        }
        
        if ($this->debug) {
            error_log("FRR: Ejecutando: $full_command");
        }
        
        // Ejecutar comando
        $output = shell_exec($full_command);
        
        if ($this->debug) {
            error_log("FRR: Salida: " . substr($output, 0, 500));
        }
        
        return $output;
    }
    
    /**
     * Obtener información de ruta BGP
     */
    public function getBGPRoute($prefix, $protocol = 'ipv4') {
        if ($protocol === 'ipv6') {
            $command = "show bgp ipv6 unicast $prefix";
        } else {
            $command = "show bgp ipv4 unicast $prefix";
        }
        
        $output = $this->executeVtysh($command);
        
        // Si la red específica no está en la tabla, mostrar el mensaje original
        if (strpos($output, 'Network not in table') !== false) {
            // Verificar si el usuario consultó una red con prefijo (ej: /23, /22)
            if (strpos($prefix, '/') !== false) {
                // Retornar el mensaje exacto de FRR
                return "% Network not in table";
            }
            
            // Solo si consultó una IP sin prefijo, intentar buscar con menos especificidad
            $ip = explode('/', $prefix)[0];
            if ($protocol === 'ipv6') {
                $command = "show bgp ipv6 unicast $ip";
            } else {
                $command = "show bgp ipv4 unicast $ip";
            }
            $output = $this->executeVtysh($command);
            
            // Si aún no encuentra nada, retornar el mensaje original
            if (strpos($output, 'Network not in table') !== false) {
                return "% Network not in table";
            }
        }
        
        // Verificar si es un error de AFI IPv6 no configurado
        if ($protocol === 'ipv6' && strpos($output, 'Cannot specify IPv6 address or prefix with IPv4 AFI') !== false) {
            return "IPv6 BGP no está configurado en este router.\n\nPara habilitar IPv6 BGP, contacte al administrador del sistema.";
        }
        
        $result = $this->parseBGPOutput($output, $prefix, $protocol);
        
        // Formatear salida como texto
        if (empty($result['paths']) && strpos($output, 'Network not in table') !== false) {
            return "% Network not in table";
        }
        
        // Formatear como texto profesional para Looking Glass
        $formatted = $this->formatBGPOutput($result, $output, $prefix);
        return $formatted;
    }
    
    /**
     * Formatear salida BGP en estilo profesional
     */
    private function formatBGPOutput($result, $rawOutput, $prefix) {
        // Extraer información adicional del output raw
        $version = '';
        $lastUpdate = '';
        $pathCount = count($result['paths']);
        
        if (preg_match('/version (\d+)/', $rawOutput, $matches)) {
            $version = $matches[1];
        }
        
        if (preg_match('/Last update: (.+)/', $rawOutput, $matches)) {
            $lastUpdate = $matches[1];
        }
        
        // Obtener el prefijo real de la salida de FRR
        $realPrefix = $prefix;
        if (preg_match('/BGP routing table entry for ([^\s,]+)/', $rawOutput, $matches)) {
            $realPrefix = $matches[1];
        }
        
        // Construir salida formateada
        $formatted = "BGP routing table entry for $realPrefix";
        if ($version) {
            $formatted .= ", version $version";
        }
        $formatted .= "\n";
        
        if ($lastUpdate) {
            $formatted .= "Last Modified: $lastUpdate\n";
        }
        
        $formatted .= "Paths: ($pathCount available";
        if ($result['best_path']) {
            $formatted .= ", best #1";
        }
        $formatted .= ")\n\n";
        
        // Verificar RPKI y agregar mensaje después de "Paths:" pero antes de mostrar los paths
        $rpkiStatus = $this->checkRPKIStatus($rawOutput, $result);
        if ($rpkiStatus === 'valid') {
            $formatted .= "The active path has a valid matching Route Origin Authorization (ROA) record.\n\n";
        } else if ($rpkiStatus === 'invalid') {
            $formatted .= "⚠️ The active path has an INVALID Route Origin Authorization (ROA) record.\n\n";
        } else {
            // Si no hay RPKI o es notfound, mostrar mensaje de unknown
            $formatted .= "The active path do not have a matching Route Origin Authorization (ROA) record but is still the best route.\n\n";
        }
        
        // Mostrar cada path
        $pathNum = 1;
        foreach ($result['paths'] as $path) {
            $isBest = $path['best'];
            
            $formatted .= "  Path #$pathNum:";
            if ($isBest) {
                $formatted .= " (best)";
            }
            $formatted .= "\n";
            
            // AS Path - FRR ya lo muestra en formato estándar [local] ... [origen]
            $asPath = $path['as_path'] ?: 'Local';
            $formatted .= "  " . $asPath . "\n";
            
            // Next hop y peer
            if ($path['next_hop']) {
                $formatted .= "    {$path['next_hop']}";
                if (preg_match('/' . preg_quote($path['next_hop']) . ' from ([0-9.]+) \(([0-9.]+)\)/', $rawOutput, $matches)) {
                    $formatted .= " from {$matches[1]} ({$matches[2]})";
                }
                $formatted .= "\n";
            }
            
            // Origin y atributos
            $formatted .= "      Origin " . ($path['origin'] ?: 'unknown');
            if ($path['local_pref']) {
                $formatted .= ", localpref {$path['local_pref']}";
            }
            $formatted .= ", valid";
            
            // Detectar si es external/internal
            if (strpos($rawOutput, 'external') !== false) {
                $formatted .= ", external";
            } else if (strpos($rawOutput, 'internal') !== false) {
                $formatted .= ", internal";
            }
            
            if ($isBest) {
                $formatted .= ", best";
            }
            
            // Agregar estado RPKI del FRR si existe para este path
            if (preg_match('/rpki validation-state: (valid|invalid|notfound)/i', $rawOutput, $rpkiMatch)) {
                $formatted .= ", rpki validation-state: " . strtolower($rpkiMatch[1]);
            }
            
            $formatted .= "\n";
            
            // Communities
            if (!empty($path['communities'])) {
                $formatted .= "      Communities: " . implode(' ', $path['communities']) . "\n";
            }
            
            // Extended Communities
            if (isset($path['extended_communities']) && !empty($path['extended_communities'])) {
                $formatted .= "      Extended Communities: " . implode(' ', $path['extended_communities']) . "\n";
            }
            
            
            $formatted .= "\n";
            $pathNum++;
        }
        
        // Si no hay paths parseados pero hay output, incluir información básica
        if (empty($result['paths']) && !empty($rawOutput)) {
            // Limpiar warnings de permisos
            $cleanOutput = preg_replace('/^.*Permission denied.*\n/m', '', $rawOutput);
            $cleanOutput = preg_replace('/^.*Configuration file.*\n/m', '', $cleanOutput);
            $formatted .= "\nDetalle:\n" . trim($cleanOutput) . "\n";
        }
        
        return $formatted;
    }
    
    /**
     * Verificar estado RPKI/ROA
     */
    private function checkRPKIStatus($rawOutput, $result) {
        // Buscar indicadores RPKI en la salida de FRR
        if (preg_match('/rpki validation-state: valid/i', $rawOutput)) {
            return 'valid';
        }
        
        if (preg_match('/rpki validation-state: invalid/i', $rawOutput)) {
            return 'invalid';
        }
        
        if (preg_match('/rpki validation-state: notfound/i', $rawOutput)) {
            return 'notfound';
        }
        
        // Buscar formato antiguo
        if (preg_match('/\(RPKI state Valid\)/', $rawOutput)) {
            return 'valid';
        }
        
        if (preg_match('/\(RPKI state Invalid\)/', $rawOutput)) {
            return 'invalid';
        }
        
        // Buscar códigos RPKI en la tabla (V>, I>, N>)
        if (preg_match('/^V>/m', $rawOutput)) {
            return 'valid';
        }
        
        if (preg_match('/^I>/m', $rawOutput)) {
            return 'invalid';
        }
        
        // Si no hay información RPKI explícita, podemos hacer una validación básica
        // basada en prefijos conocidos (esto es opcional y se puede expandir)
        if ($result['best_path']) {
            $prefix = $result['prefix'];
            $asPath = $result['best_path']['origin_as'] ?? $result['best_path']['as_path'];
            
            // Obtener el AS de origen (último en el path original de FRR)
            $asNumbers = explode(' ', $asPath);
            $originAs = end($asNumbers); // Último elemento del path original
            
            // Usar el validador RPKI
            return RPKIValidator::validateROA($prefix, $originAs);
        }
        
        return 'unknown';
    }
    
    /**
     * Parsear salida de BGP
     */
    private function parseBGPOutput($output, $prefix, $protocol) {
        $lines = explode("\n", $output);
        $result = [
            'prefix' => $prefix,
            'paths' => [],
            'best_path' => null
        ];
        
        $current_path = null;
        $in_path = false;
        
        foreach ($lines as $line) {
            // Detectar inicio de información de ruta
            if (preg_match('/BGP routing table entry for (.+)/', $line, $matches)) {
                $result['prefix'] = $matches[1];
                continue;
            }
            
            // Detectar paths
            if (strpos($line, 'Paths:') !== false) {
                $in_path = true;
                continue;
            }
            
            // Parsear información del path
            if ($in_path && trim($line) !== '') {
                // AS Path - buscar línea que contiene solo números separados por espacios (sin IPs)
                if (preg_match('/^\s*(\d+(?:\s+\d+)*)$/', trim($line), $matches)) {
                    if ($current_path !== null) {
                        $result['paths'][] = $current_path;
                    }
                    $current_path = [
                        'as_path' => $matches[1],
                        'origin_as' => $matches[1], // Guardar AS path original para RPKI
                        'next_hop' => null,
                        'origin' => null,
                        'local_pref' => null,
                        'communities' => [],
                        'best' => false
                    ];
                }
                
                // Next hop - buscar línea con IP y "from"
                else if (preg_match('/^\s+([0-9.]+)\s+from\s+([0-9.]+)/', $line, $matches)) {
                    if ($current_path) {
                        $current_path['next_hop'] = $matches[1];
                    }
                }
                
                // Origin
                if (preg_match('/Origin (\w+),/', $line, $matches)) {
                    if ($current_path) {
                        $current_path['origin'] = $matches[1];
                    }
                }
                
                // Local preference
                if (preg_match('/localpref (\d+)/', $line, $matches)) {
                    if ($current_path) {
                        $current_path['local_pref'] = $matches[1];
                    }
                }
                
                // Best path
                if (strpos($line, 'best') !== false) {
                    if ($current_path) {
                        $current_path['best'] = true;
                        $result['best_path'] = $current_path;
                    }
                }
                
                // Communities
                if (preg_match('/Community: (.+)/', $line, $matches)) {
                    if ($current_path) {
                        $communities = trim($matches[1]);
                        // Separar communities regulares de RT (Route Target)
                        $regularComms = [];
                        $extComms = [];
                        
                        foreach (explode(' ', $communities) as $comm) {
                            if (strpos($comm, 'RT:') === 0) {
                                $extComms[] = $comm;
                            } else {
                                $regularComms[] = $comm;
                            }
                        }
                        
                        if (!empty($regularComms)) {
                            $current_path['communities'] = array_merge(
                                $current_path['communities'],
                                $regularComms
                            );
                        }
                        
                        if (!empty($extComms)) {
                            if (!isset($current_path['extended_communities'])) {
                                $current_path['extended_communities'] = [];
                            }
                            $current_path['extended_communities'] = array_merge(
                                $current_path['extended_communities'],
                                $extComms
                            );
                        }
                    }
                }
                
                // Extended Communities
                if (preg_match('/Extended Community: (.+)/', $line, $matches)) {
                    if ($current_path) {
                        if (!isset($current_path['extended_communities'])) {
                            $current_path['extended_communities'] = [];
                        }
                        $current_path['extended_communities'][] = trim($matches[1]);
                    }
                }
            }
        }
        
        // Agregar último path si existe
        if ($current_path !== null) {
            $result['paths'][] = $current_path;
            if ($current_path['best'] && $result['best_path'] === null) {
                $result['best_path'] = $current_path;
            }
        }
        
        return $result;
    }
    
    /**
     * Ejecutar ping desde FRR
     */
    public function executePing($target, $count = 5, $protocol = 'ipv4') {
        // FRR no tiene ping integrado, usar sistema
        if ($protocol === 'ipv6') {
            $ping_cmd = sprintf('ping6 -c %d -W 1 %s', $count, escapeshellarg($target));
        } else {
            $ping_cmd = sprintf('ping -c %d -W 1 %s', $count, escapeshellarg($target));
        }
        
        if ($this->host === 'localhost') {
            $output = shell_exec($ping_cmd . ' 2>&1');
        } else {
            // Ejecución remota via SSH
            $full_command = sprintf(
                'timeout %d ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no %s@%s %s 2>&1',
                $this->timeout,
                escapeshellarg($this->ssh_user),
                escapeshellarg($this->host),
                escapeshellarg($ping_cmd)
            );
            $output = shell_exec($full_command);
        }
        
        $result = $this->parsePingOutput($output, $target, $protocol);
        
        // Formatear salida como texto
        $formatted = "PING $target (" . strtoupper($protocol) . ")\n";
        $formatted .= "================================================\n\n";
        
        if (!empty($result['responses'])) {
            foreach ($result['responses'] as $response) {
                $formatted .= sprintf("64 bytes from %s: icmp_seq=%d ttl=%d time=%s ms\n",
                    $target,
                    $response['seq'],
                    $response['ttl'],
                    $response['time']
                );
            }
        } else if (!empty($output)) {
            // Si no pudimos parsear pero hay salida, mostrarla
            $formatted .= $output;
        }
        
        $formatted .= "\n--- $target ping statistics ---\n";
        $formatted .= sprintf("%d packets transmitted, %d received, %.1f%% packet loss\n",
            $result['packets_sent'],
            $result['packets_received'],
            $result['packet_loss']
        );
        
        if ($result['min_rtt'] !== null) {
            $formatted .= sprintf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n",
                $result['min_rtt'],
                $result['avg_rtt'],
                $result['max_rtt']
            );
        }
        
        return $formatted;
    }
    
    /**
     * Parsear salida de ping
     */
    private function parsePingOutput($output, $target, $protocol) {
        $lines = explode("\n", $output);
        $result = [
            'target' => $target,
            'packets_sent' => 0,
            'packets_received' => 0,
            'packet_loss' => 100,
            'min_rtt' => null,
            'avg_rtt' => null,
            'max_rtt' => null,
            'responses' => []
        ];
        
        foreach ($lines as $line) {
            // Respuestas individuales
            if (preg_match('/bytes from .+: icmp_seq=(\d+) ttl=(\d+) time=([\d.]+) ms/', $line, $matches)) {
                $result['responses'][] = [
                    'seq' => $matches[1],
                    'ttl' => $matches[2],
                    'time' => $matches[3]
                ];
            }
            
            // Estadísticas
            if (preg_match('/(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss/', $line, $matches)) {
                $result['packets_sent'] = intval($matches[1]);
                $result['packets_received'] = intval($matches[2]);
                $result['packet_loss'] = floatval($matches[3]);
            }
            
            // RTT
            if (preg_match('/min\/avg\/max\/mdev = ([\d.]+)\/([\d.]+)\/([\d.]+)/', $line, $matches)) {
                $result['min_rtt'] = floatval($matches[1]);
                $result['avg_rtt'] = floatval($matches[2]);
                $result['max_rtt'] = floatval($matches[3]);
            }
        }
        
        return $result;
    }
    
    /**
     * Ejecutar traceroute
     */
    public function executeTraceroute($target, $max_hops = 15, $protocol = 'ipv4') {
        if ($protocol === 'ipv6') {
            $trace_cmd = sprintf('traceroute6 -m %d -w 3 %s', $max_hops, escapeshellarg($target));
        } else {
            $trace_cmd = sprintf('traceroute -m %d -w 3 %s', $max_hops, escapeshellarg($target));
        }
        
        if ($this->host === 'localhost') {
            $output = shell_exec($trace_cmd . ' 2>&1');
        } else {
            // Ejecución remota via SSH
            $full_command = sprintf(
                'timeout %d ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no %s@%s %s 2>&1',
                $this->timeout * 2, // Traceroute puede tomar más tiempo
                escapeshellarg($this->ssh_user),
                escapeshellarg($this->host),
                escapeshellarg($trace_cmd)
            );
            $output = shell_exec($full_command);
        }
        
        return $this->parseTracerouteOutput($output, $target, $protocol);
    }
    
    /**
     * Parsear salida de traceroute
     */
    private function parseTracerouteOutput($output, $target, $protocol) {
        $lines = explode("\n", $output);
        $result = [
            'target' => $target,
            'hops' => []
        ];
        
        foreach ($lines as $line) {
            // Saltos
            if (preg_match('/^\s*(\d+)\s+(.+)/', $line, $matches)) {
                $hop_num = intval($matches[1]);
                $hop_data = trim($matches[2]);
                
                // Parsear tiempos y hosts
                $hop = [
                    'hop' => $hop_num,
                    'hosts' => [],
                    'times' => []
                ];
                
                // Extraer IPs/hosts y tiempos
                if (preg_match_all('/([a-zA-Z0-9.-]+|\*)\s+(?:\(([\d.:a-f]+)\)\s+)?([\d.]+\s*ms|\*)/', $hop_data, $matches, PREG_SET_ORDER)) {
                    foreach ($matches as $match) {
                        if ($match[1] !== '*') {
                            $hop['hosts'][] = [
                                'name' => $match[1],
                                'ip' => $match[2] ?? null
                            ];
                        }
                        if ($match[3] !== '*') {
                            $hop['times'][] = floatval(str_replace(' ms', '', $match[3]));
                        }
                    }
                }
                
                $result['hops'][] = $hop;
            }
        }
        
        return $result;
    }
    
    /**
     * Obtener resumen BGP
     */
    public function getBGPSummary($protocol = 'ipv4') {
        if ($protocol === 'ipv6') {
            $command = "show bgp ipv6 unicast summary";
        } else {
            $command = "show bgp ipv4 unicast summary";
        }
        
        $output = $this->executeVtysh($command);
        return $this->parseBGPSummary($output);
    }
    
    /**
     * Parsear resumen BGP
     */
    private function parseBGPSummary($output) {
        $lines = explode("\n", $output);
        $result = [
            'router_id' => null,
            'as_number' => null,
            'peers' => []
        ];
        
        foreach ($lines as $line) {
            // Router ID y AS
            if (preg_match('/router identifier ([\d.]+), local AS number (\d+)/', $line, $matches)) {
                $result['router_id'] = $matches[1];
                $result['as_number'] = $matches[2];
            }
            
            // Peers
            if (preg_match('/^([\d.:a-f]+)\s+4\s+(\d+)\s+/', $line, $matches)) {
                $parts = preg_split('/\s+/', $line);
                if (count($parts) >= 9) {
                    $result['peers'][] = [
                        'neighbor' => $parts[0],
                        'as' => $parts[2],
                        'msg_rcvd' => $parts[3],
                        'msg_sent' => $parts[4],
                        'up_down' => $parts[7],
                        'state_prefixes' => $parts[8]
                    ];
                }
            }
        }
        
        return $result;
    }
}
?>