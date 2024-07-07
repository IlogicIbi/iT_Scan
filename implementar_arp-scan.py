import subprocess
import re
import socket
import netifaces

def run_arp_scan(interface):
    try:
        print(f"Running ARP scan on interface {interface}...")
        arp_command = ["arp", "-a", "-i", interface]
        result = subprocess.run(arp_command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running ARP scan on interface {interface}: {e}")
        return ""

def get_interfaces():
    interfaces = netifaces.interfaces()
    return interfaces

def choose_interface(interfaces):
    print("Available interfaces:")
    for i, iface in enumerate(interfaces, start=1):
        print(f"{i}. {iface}")
    choice = input("Choose the interface number for ARP scan: ")
    try:
        index = int(choice) - 1
        if 0 <= index < len(interfaces):
            return interfaces[index]
        else:
            return None
    except ValueError:
        return None

def run_nmap(ip):
    try:
        print(f"Running nmap on {ip}...")
        nmap_command = ["sudo", "nmap", "-p-", "-sV", "-sS", "--min-rate", "5000", "--open", ip]
        result = subprocess.run(nmap_command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running nmap on {ip}: {e}")
        return ""

def parse_nmap_output(nmap_output):
    open_ports = []
    for line in nmap_output.split('\n'):
        if "/tcp" in line and "open" in line:
            port_info = re.split(r'\s+', line)
            port = port_info[0].split('/')[0]
            service = port_info[2]
            version = " ".join(port_info[3:]) if len(port_info) > 3 else "Unknown"
            open_ports.append((port, service, version))
    return open_ports

def run_gobuster(ip, port):
    try:
        print(f"Running gobuster on {ip}:{port}...")
        url = f"http://{ip}/"
        gobuster_command = ["gobuster", "dir", "-u", url, "-w", "/home/ibi/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt", "-t", "50"]
        result = subprocess.run(gobuster_command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        error_message = f"Error running gobuster on {ip}:{port}: {e}"
        return error_message

def get_domain(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
        return domain
    except socket.herror:
        return None

def format_output(ip, open_ports, gobuster_outputs, domain):
    output = f"IP: {ip}\n"
    output += f"Dominio principal: {domain if domain else 'No se pudo determinar el dominio principal'}\n"
    output += f"{'Servicio':<20}{'Puerto':<10}{'Versiones'}\n"
    for port, service, version in open_ports:
        output += f"{service:<20}{port:<10}{version}\n"
    if gobuster_outputs:
        output += "\nGobuster Output:\n"
        output += gobuster_outputs + "\n"
    else:
        output += f"\nError running gobuster:\n{gobuster_outputs}\n"
    return output

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def main():
    arp_choice = input("Do you want to perform an ARP scan on your local network? (y/n): ").lower()
    if arp_choice == "y":
        interfaces = get_interfaces()
        if interfaces:
            chosen_interface = choose_interface(interfaces)
            if chosen_interface:
                arp_output = run_arp_scan(chosen_interface)
                print("\nARP Scan Results:")
                print(arp_output)
            else:
                print("Invalid interface choice.")
        else:
            print("No interfaces found.")
    elif arp_choice == "n":
        print("Skipping ARP scan.")

    target_ips = input("Enter the target IP addresses (comma separated): ")
    output_file = input("Enter the output file name: ")
    ips = [ip.strip() for ip in target_ips.split(',')]

    for ip in ips:
        if not validate_ip(ip):
            print(f"Invalid IP address: {ip}")
            continue
        
        nmap_output = run_nmap(ip)
        open_ports = parse_nmap_output(nmap_output)
        gobuster_outputs = ""
        domain = None

        for port, service, version in open_ports:
            if service in ["http", "http-alt", "https"]:
                gobuster_output = run_gobuster(ip, port)
                gobuster_outputs += gobuster_output
                if port == "80":
                    domain = get_domain(ip)

        formatted_output = format_output(ip, open_ports, gobuster_outputs, domain)
        with open(output_file, 'a') as file:
            file.write(formatted_output + "\n\n")

if __name__ == "__main__":
    main()
