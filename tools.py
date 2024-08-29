import socket
import re
import nmap
from scapy.all import IP, TCP, UDP, sr1, ICMP

print("========================================================================")
print("*   Octlivatua Patricia Disiulina  *")
print("*          Network Tools           *")
print("*       Source: Youtube.com        *")
print("========================================================================")

choose = input("""Choose an Option below: 
                1. Version of services running 
                2. Vulnerabilities
                3. Protocol Scanner
option: """)

if choose == '1':
    def scan_port(ip, port):
        try:
            # buat socket untuk menghubungkan IP dan port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # timeout 1 detik
            result = sock.connect_ex((ip, port))
        
            if result == 0:
                print(f"Port {port} terbuka pada {ip}")
                # mengirim request untuk mendapat versi dari servis yang berjalan
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    response = sock.recv(1024)
                    version = extract_version(response)
                    if version:
                        print(f"Detected service version: {version}")
                    else:
                        print("Service version could not be detected.")
                except Exception as e:
                    print(f"Could not retrieve version: {e}")
        
            sock.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")

    def extract_version(response):
        # ekstrak versi dari respons
        try:
            # mencocokkan header
            response = response.decode('utf-8', errors='ignore')
            version = re.search(r'Server: (.+)', response)
            if version:
                return version.group(1)
            else:
                return None
        except Exception as e:
            print(f"Error extracting version: {e}")
            return None

    def main_version_scan():
        ip = input('Enter IP: ')  # ip yang jadi tujuan
        ports = range(1, 10001)   # range ports yang akan di scan

        for port in ports:
            scan_port(ip, port)

    main_version_scan()

elif choose == '2':
    def check_vulnerability(ip):
        n = nmap.PortScanner()

        print(f"scanning {ip} for vulnerabilities..")

        n.scan(ip, arguments="--script vuln")
        for host in n.all_hosts():
            print(f'\nHost:  {host}')
            print(f'State: {n[host].state()}')

            if 'hostscript' in n[host]:
                for script in n[host]['hostscript']:
                    print(f"Vulnerability: {script}")
                    print(f"Details: {n[host]['hostscript'][script]}")
    
    def main_vulnerabilies():
        ip = input('Enter IP: ') 
        check_vulnerability(ip)
    
    main_vulnerabilies()


elif choose == '3':
    def protocol_scan(ip, port_range=1024):
        # range port yang akan discan
        ports = range(1, port_range + 1)

        print(f"Scanning IP: {ip} (Port range: 1-{port_range})")

        # SYN/ACK (TCP) Scan
        print("\nStarting SYN/ACK Scan:")
        tcp_ports = []
        for port in ports:
            syn_ack_packet = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
            if syn_ack_packet is not None:
                if syn_ack_packet.haslayer(TCP) and syn_ack_packet[TCP].flags == "SA":
                    tcp_ports.append(port)

        if tcp_ports:
            print(f"Open TCP Ports (SYN/ACK): {tcp_ports}")
        else:
            print("No open TCP ports found.")

        # UDP Scan
        print("\nStarting UDP Scan:")
        udp_ports = []
        for port in ports:
            udp_packet = sr1(IP(dst=ip)/UDP(dport=port), timeout=1, verbose=0)
            if udp_packet is None:
                udp_ports.append(port)
            elif udp_packet.haslayer(ICMP):
                if udp_packet[ICMP].type == 3 and udp_packet[ICMP].code == 3:
                    continue

        if udp_ports:
            print(f"Open UDP Ports: {udp_ports}")
        else:
            print("No open UDP ports found.")

    
    ip_address = input("Masukkan IP yang akan discan: ")
    port_range = int(input("Masukkan range port yang akan discan: "))
    protocol_scan(ip_address, port_range)

elif choose >= '4':
    print(f'Pilihan anda tidak ditemukan. Silahkan masukan angka yang valid!')