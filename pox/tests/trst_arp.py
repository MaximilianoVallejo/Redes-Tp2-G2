#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from mininet.net import Mininet
from mininet.log import setLogLevel, info, error

# Importamos la topología definida en el proyecto
from topo import ProjectTopology 

# --- Constantes de Configuración ---
GHOST_IP = '192.168.2.99'
WAIT_CONTROLLER_SEC = 3
PING_COUNT = 3

def test_basic_learning(h1, h2):
    """Verifica la conectividad básica y el aprendizaje pasivo de ARP."""
    info('\n' + '='*50 + '\n')
    info(' TEST 1: Conectividad básica y Aprendizaje Dinámico (h2 -> h1)\n')
    info('='*50 + '\n')
    
    result = h2.cmd(f'ping -c {PING_COUNT} {h1.IP()}')
    info(result)
    
    # Validamos que no haya 100% de pérdida (el primer ping puede perderse por el tiempo de ARP)
    if "0% packet loss" in result or ("packet loss" in result and "100%" not in result):
        info("[PASSED] Test 1: Conectividad establecida.\n")
        return True
    
    error("[FAILED] Test 1: Pérdida total de paquetes.\n")
    return False

def test_concurrency(h1, h3, h4):
    """Ejecuta resoluciones ARP concurrentes para validar el aislamiento de flujos."""
    info('\n' + '='*50 + '\n')
    info(' TEST 2: Concurrencia de ARP (h3 y h4 hacia h1 en paralelo)\n')
    info('='*50 + '\n')
    
    # Ejecución en background enviando el output a archivos temporales
    h3.cmd(f'ping -c {PING_COUNT} {h1.IP()} > /tmp/h3_ping.log &')
    h4.cmd(f'ping -c {PING_COUNT} {h1.IP()} > /tmp/h4_ping.log &')
    
    # Esperamos el tiempo necesario para que terminen los pings
    time.sleep(PING_COUNT + 1) 
    
    try:
        with open('/tmp/h3_ping.log', 'r') as f3, open('/tmp/h4_ping.log', 'r') as f4:
            res_h3 = f3.read()
            res_h4 = f4.read()
            
        info("--- Resultado h3 ---\n", res_h3)
        info("--- Resultado h4 ---\n", res_h4)
        
        if "0% packet loss" in res_h3 and "0% packet loss" in res_h4:
            info("[PASSED] Test 2: Múltiples flujos resueltos concurrentemente.\n")
            return True
            
    except FileNotFoundError:
        error("[FAILED] Test 2: No se pudieron leer los logs de resultados temporales.\n")
        return False
        
    error("[FAILED] Test 2: Interferencia o fallo en concurrencia.\n")
    return False

def test_timeout_handling(h2):
    """Evalúa el comportamiento del controlador ante un destino inexistente."""
    info('\n' + '='*50 + '\n')
    info(' TEST 3: Destino inexistente en Red Pública (Manejo de reintentos)\n')
    info('='*50 + '\n')
    info(f"Enviando tráfico a {GHOST_IP} (Debe gatillar reintentos y descarte en POX)...\n")
    
    # Ping con timeout estricto (-W 1) a una IP que no existe en la topología
    h2.cmd(f'ping -c 1 -W 1 {GHOST_IP}')
    
    info("[INFO] Revisa la consola del controlador POX para confirmar:\n")
    info("       1. Múltiples envíos de 'ARP REQUEST'.\n")
    info("       2. Log de descarte tras superar ARP_MAX_RETRIES.\n")
    return True

def run_arp_tests():
    """Punto de entrada principal para orquestar la suite de pruebas."""
    setLogLevel('info')
    
    info('*** Inicializando topología...\n')
    net = Mininet(topo=ProjectTopology())
    
    try:
        net.start()
        info(f'*** Esperando que el controlador POX se estabilice ({WAIT_CONTROLLER_SEC}s)...\n')
        time.sleep(WAIT_CONTROLLER_SEC)

        # Extracción segura de los nodos
        h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

        # Ejecución secuencial de la suite
        test_basic_learning(h1, h2)
        test_concurrency(h1, h3, h4)
        test_timeout_handling(h2)

    except KeyError as e:
        error(f"\n[ERROR] No se encontró un host requerido en la topología: {e}\n")
    except Exception as e:
        error(f"\n[ERROR] Fallo inesperado durante la ejecución: {e}\n")
    finally:
        info('\n' + '='*50 + '\n')
        info('*** Deteniendo Mininet para liberar interfaces y recursos del sistema...\n')
        info('='*50 + '\n')
        # Garantiza el cierre limpio de OVS y procesos asociados
        net.stop()

if __name__ == '__main__':
    run_arp_tests()