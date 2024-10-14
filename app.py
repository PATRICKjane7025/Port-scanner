from flask import Flask, render_template, request
import socket
from datetime import datetime
import concurrent.futures

app = Flask(__name__)

# List of top 20 common ports
TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080, 8443, 3306, 1723, 5900, 111, 515, 993]

# Mapping ports to their services and descriptions
PORT_DETAILS = {
    21: ("FTP", "File Transfer Protocol"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Telnet Protocol"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "HyperText Transfer Protocol"),
    110: ("POP3", "Post Office Protocol 3"),
    139: ("NetBIOS", "NetBIOS Session Service"),
    143: ("IMAP", "Internet Message Access Protocol"),
    443: ("HTTPS", "HyperText Transfer Protocol Secure"),
    445: ("SMB", "Server Message Block"),
    3389: ("RDP", "Remote Desktop Protocol"),
    8080: ("HTTP-ALT", "Alternative HTTP Protocol"),
    8443: ("HTTPS-ALT", "Alternative HTTPS Protocol"),
    3306: ("MySQL", "MySQL Database Service"),
    1723: ("PPTP", "Point-to-Point Tunneling Protocol"),
    5900: ("VNC", "Virtual Network Computing"),
    111: ("rpcbind", "RPC Portmapper"),
    515: ("LPR", "Line Printer Daemon"),
    993: ("IMAPS", "IMAP Secure")
}

def scan_port(target_ip, port):
    """Scans a single port and returns the result."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = sock.connect_ex((target_ip, port))
    if result == 0:
        status = 'Open'
    else:
        status = 'Closed'
    sock.close()
    service, description = PORT_DETAILS.get(port, ("Unknown", "No description available"))
    return (port, status, service, description)

def port_scanner(target, ports):
    """Performs a concurrent port scan."""
    target_ip = socket.gethostbyname(target)
    results = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_port = {executor.submit(scan_port, target_ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            results.append(future.result())
    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target_host = request.form['target']
        selected_ports = request.form.getlist('ports')
        selected_ports = [int(port) for port in selected_ports]

        start_time = datetime.now()
        scan_results = port_scanner(target_host, selected_ports)
        end_time = datetime.now()

        # Render both form and results on the same page
        return render_template('index.html', ports=TOP_20_PORTS, target=target_host, results=scan_results, time_taken=end_time - start_time)

    # On GET request, only show the form
    return render_template('index.html', ports=TOP_20_PORTS, target=None, results=None, time_taken=None)

if __name__ == '__main__':
    app.run(debug=True)
