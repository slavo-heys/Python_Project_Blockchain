import socket
import ipaddress
import threading
from queue import Queue
import queue # Dla wyjątku queue.Empty
import errno # Dla sprawdzania błędów jak ECONNREFUSED
from typing import List, Tuple, Optional, Union, Dict, Any
from dataclasses import dataclass

@dataclass
class HostScanResult:
    ip: str    
    ports: List[int]

# Globalna lista do przechowywania aktywnych hostów i ich otwartych portów
active_hosts_with_ports: List[HostScanResult] = []
# Blokada do synchronizacji dostępu do listy active_hosts_with_ports
list_lock = threading.Lock()

# Kolejka adresów IP do fazy odkrywania hostów
discovery_ip_queue: Queue[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = Queue()
# Lista znalezionych online hostów
online_hosts_list: List[str] = []
# Blokada do synchronizacji dostępu do online_hosts_list
discovery_list_lock = threading.Lock()

# Lista popularnych portów TCP do sprawdzenia. Możesz ją rozszerzyć.
COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # RPCbind/Portmapper
    135,   # MSRPC (Microsoft RPC)
    139,   # NetBIOS Session Service
    143,   # IMAP
    443,   # HTTPS
    445,   # Microsoft-DS (SMB/CIFS)
    993,   # IMAPS
    995,   # POP3S
    1723,  # PPTP (VPN)
    3306,  # MySQL
    3389,  # RDP (Remote Desktop Protocol)
    5432,  # PostgreSQL
    5900,  # VNC (Virtual Network Computing)
    8000,  # HTTP Alternate (często serwery deweloperskie)
    8080,  # HTTP Alternate (np. Tomcat, inne serwery proxy)
    8443   # HTTPS Alternate
]

HOST_DISCOVERY_PORT: int = 80 # Port używany do szybkiego sprawdzenia, czy host jest online
HOST_DISCOVERY_TIMEOUT: float = 0.2 # Sekundy

def get_local_ip_and_network() -> Tuple[Optional[str], Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]]:
    """
    Próbuje automatycznie ustalić lokalny adres IP użytkownika i jego sieć /24.
    Uwaga: Ta metoda może nie działać poprawnie we wszystkich konfiguracjach sieciowych.
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        network_address_str: str = ".".join(local_ip.split('.')[:3]) + ".0/24"
        return local_ip, ipaddress.ip_network(network_address_str, strict=False)
    except (socket.error, OSError):
        print("Nie udało się automatycznie ustalić lokalnego adresu IP i sieci.")
        return None, None
    finally:
        if s:
            s.close()

def discover_host_worker() -> None:
    """
    Funkcja wykonywana przez wątki robocze w fazie odkrywania hostów.
    Pobiera adresy IP z kolejki i sprawdza, czy są online.
    """
    while True:
        try:
            ip_to_scan_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = discovery_ip_queue.get(block=True, timeout=1)
            ip_to_scan_str = str(ip_to_scan_obj)
        except queue.Empty:
            return # Kolejka pusta, zakończ wątek

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(HOST_DISCOVERY_TIMEOUT)
                result = sock.connect_ex((ip_to_scan_str, HOST_DISCOVERY_PORT))
                if result == 0 or result == errno.ECONNREFUSED:
                    with discovery_list_lock:
                        online_hosts_list.append(ip_to_scan_str)
        except socket.timeout:
            pass
        except socket.error:
            pass
        finally:
            discovery_ip_queue.task_done()

def scan_ports_for_host(ip_address_str: str) -> None:
    """
    Skanuje zdefiniowane porty na podanym adresie IP.
    Wyświetla komunikaty o skanowaniu każdego portu.
    Próbuje rozwiązać nazwę hosta.
    """
    print(f"\nSkanowanie portów dla hosta: {ip_address_str}")
    open_ports_for_this_ip: List[int] = []

    for port in COMMON_PORTS:
        # Usunięto wyświetlanie informacji o nazwie hosta i OS przed skanowaniem portów
        print(f"  -> Skanowanie portu {port} na {ip_address_str}...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3)
                result = sock.connect_ex((ip_address_str, port))
                if result == 0:
                    open_ports_for_this_ip.append(port)
                    print(f"    Port {port} jest OTWARTY na {ip_address_str}")
        except socket.timeout:
            pass
        except socket.error:
            pass

    if open_ports_for_this_ip:
        with list_lock:
            active_hosts_with_ports.append(HostScanResult(
                ip=ip_address_str,                
                ports=sorted(open_ports_for_this_ip)
            ))

def main_scanner() -> None:
    print("Prosty Skaner Adresów IP i Portów w Sieci Lokalnej")
    print("=" * 50)

    local_ip_address, default_network = get_local_ip_and_network()
    network_input_str = ""

    if local_ip_address and default_network:
        print(f"Twój wykryty lokalny adres IP: {local_ip_address}")
        default_network_str = str(default_network)
        network_input_str = input(
            f"Podaj zakres sieci do skanowania (np. 192.168.1.0/24) [domyślnie: {default_network_str}]: ").strip()
        if not network_input_str:
            network_input_str = default_network_str
    else:
        network_input_str = input(
            "Podaj zakres sieci do skanowania (np. 192.168.1.0/24): ").strip()

    if not network_input_str:
        print("Nie podano zakresu sieci. Zamykanie programu.")
        return

    try:
        network_to_scan: Union[ipaddress.IPv4Network, ipaddress.IPv6Network] = ipaddress.ip_network(network_input_str, strict=False)
    except ValueError:
        print("Nieprawidłowy format adresu sieci. Przykład: 192.168.1.0/24. Zamykanie programu.")
        return

    print(f"\n--- Faza 1: Odkrywanie aktywnych hostów w sieci {network_to_scan} ---")
    host_ips_to_discover = list(network_to_scan.hosts())

    if not host_ips_to_discover:
        print(f"W podanym zakresie ({network_to_scan}) nie ma adresów hostów do skanowania.")
        print("W podanym zakresie nie ma adresów hostów do skanowania.")
        return

    for ip_obj in host_ips_to_discover:
        discovery_ip_queue.put(ip_obj)

    num_discovery_threads = min(50, len(host_ips_to_discover))

    discovery_threads: List[threading.Thread] = []
    print(f"Uruchamianie {num_discovery_threads} wątków do odkrywania hostów (port {HOST_DISCOVERY_PORT})...")

    for i in range(num_discovery_threads):
        thread = threading.Thread(target=discover_host_worker, name=f"Odkrywca-{i+1}")
        thread.daemon = True
        discovery_threads.append(thread)
        thread.start()

    discovery_ip_queue.join()
    print("Zakończono odkrywanie hostów.")

    if not online_hosts_list:
        print("\nNie znaleziono żadnych aktywnych hostów w podanym zakresie.")
        # Skanowanie zakończone zostanie wyświetlone na końcu funkcji
        return

    online_hosts_list.sort(key=ipaddress.ip_address)

    print("\nZnaleziono następujące aktywne hosty:")
    for host_ip in online_hosts_list:
        print(f"  - {host_ip}")

    print(f"\n--- Faza 2: Skanowanie portów dla {len(online_hosts_list)} aktywnych hostów ---")

    for host_ip_str in online_hosts_list:
        scan_ports_for_host(host_ip_str)

    print("\n--- Wyniki Skanowania Otwartych Portów ---")
    if active_hosts_with_ports:
        sorted_results: List[HostScanResult] = sorted(active_hosts_with_ports, key=lambda x: ipaddress.ip_address(x.ip))
        print(f"Znaleziono otwarte porty na {len(sorted_results)} hostach:")
        # Dostosowanie szerokości kolumn
        print(f"  {'Adres IP':<15} | {'Otwarte Porty'}")
        print(f"  {'-'*15} | {'-'*20}")
        for host_info in sorted_results:
            print(f"  {host_info.ip:<15} | {', '.join(map(str, host_info.ports))}")
    else:
        print("Nie znaleziono żadnych otwartych popularnych portów na aktywnych hostach.")

    print("\nSkanowanie zakończone.")

if __name__ == "__main__":
    main_scanner()
