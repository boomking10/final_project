""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import re
import subprocess
import traceback

import requests

"""""""""""""""""""""""""""""""""THE PROTOCOL FOR THE PACKETS"""""""""""""""""""""""
"Tor;""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""''""""""""''"""
"new_client_to_server: [mac of the new client that connected to you],[his ipv4 private], [his ipv4 public], [his port number]  client Node and main to server and server to client Nodes"
"port_of_server: [the port of the server in udp] server to everyone"
"start_first_stage_udp_hole_punching: [mac_of_the person who sent the packet],[mac of the person you want to do udp punch_hole] client Node and main to server "
"server_answer_for_first_stage_udp_hole_punching: if the server connect to the bot:[yes]?[(ipv4,port)] if not:[no] server to client Node and main "
"server_notify_bot_for_second_stage_of_udp_hole_punching: [mac of the person who wants to do udp punch]?[(ipv4,port)] server to client Node and main"
"giving_data_of_2: [mac_of_the person who sent the packet],[mac of the person you want to do udp punch_hole]"
"packet_on_the_way: [id]?[ttl]?[data] main client to client Node and client Node to Client Node"
"packet_on__the_way_back: [id]?[data] client Node to Client Node and client Node to main client "
"new_ipv6_server: [ipv6] new ipv6 server to all other ipv6 servers that he has"
"keys_for_security: [public_rsa] everyone to anyone "
"sigh_message: [signed_public_key]"
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

import random
from getmac import get_mac_address
from socket import socket, error, AF_INET6, AF_INET, SOCK_DGRAM, SOCK_STREAM, gethostbyname, gethostname, \
    timeout as socket_timeout
from concurrent.futures import ThreadPoolExecutor
import json
from collections import deque
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, PKCS1v15, MGF1
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Generate DH key pair
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA
from Crypto.Protocol.KDF import scrypt

DATA_FROM_UDP_HOLE_PUNCHING = None
Port_for_bot = None
Tor_opening_packets = 'Tor\r\n'
PORT_OF_UDP_SERVER = None
IPV4_OF_SERVER = '172.20.10.2'
IPV6_OF_SERVER = '2a06:c701:4550:a00:fad4:e6f3:25c7:8b68'
# dictionary will be like mac:(ipv4,port)
# data base with json like mac: and what server they are conncted to( his ipv6)
executor = ThreadPoolExecutor(thread_name_prefix='worker_thread_')
PACKETS_TO_HANDLE_QUEUE = deque()
# be like mac: (rsa_public,dh_public),(ipv4,port)
MAC_FOR_KEYS_IPV4_PORT = {}
Alice_dh_private_key, Alice_dh_public_key = None, None
Alice_rsa_private_key, Alice_rsa_public_key = None, None
Alice_signature = None
# ipv4_public, ipv4_private_static, port_tcp, port udp
DATA_OF_SERVERS = [('147.235.215.64', '10.0.0.11', 56789, 56779), ('188.120.157.25', '192.168.175.229', 56789, 56779),
                   ('2.52.14.104', '172.20.10.2', 56789, 56779)]


# security
###################################################################################################
def make_dh_keypair():
    p = 877
    q = 1531
    g = 131
    x = random.randint(1, q)
    y = pow(g, x, p)
    pub = DSA.construct((pow(g, y, p), p, q, g))
    priv = DSA.construct((y, p, q, g))
    return pub, priv


def generate_dh_key_pair():
    parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    return private_key, public_key


def serialize_public_key(public_key):
    serialized_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return serialized_key


def deserialize_public_key(serialized_key):
    serialized_key = serialized_key.encode('utf-8')
    public_key = serialization.load_pem_public_key(serialized_key, backend=default_backend())
    return public_key


def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(message, public_key):
    alice_signature = public_key.encrypt(
        message.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return alice_signature


def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


#########################################################################################

def sending_the_keys_for_security(packet_to_send):
    """
    adding the the public and private keys of dh and rsa to the packet for the server
    :return:
    """
    global Tor_opening_packets, Alice_dh_public_key, Alice_rsa_public_key
    rsa_public_to_send = serialize_public_key(Alice_rsa_public_key)
    rsa_public_to_send = rsa_public_to_send.decode('utf-8')
    # dh_public_to_send = serialize_public_key(Alice_dh_public_key)
    # dh_public_to_send = dh_public_to_send.decode('utf-8')
    packet_to_send += f"keys_for_security: {rsa_public_to_send}"
    return packet_to_send


def select_random_port():
    """
    selecting private port for udp
    :return:
    """
    global Port_for_bot
    Port_for_bot = random.randint(20000, 29000)


def tor_filter(payload):
    expected = 'Tor'.encode('utf-8')
    return payload[:len(expected)] == expected


def verify_packets_from_server(client_socket_tcp, client_socket_udp):
    """
    checking that the packets are really from the clients
    :return:
    """
    try:
        global PACKETS_TO_HANDLE_QUEUE
        while True:
            if len(PACKETS_TO_HANDLE_QUEUE) < 1:
                continue
            payload = PACKETS_TO_HANDLE_QUEUE.popleft()
            if tor_filter(payload):
                data_from_packet = payload.decode('utf-8')
                # print(data_from_packet)
                handle_packets_from_server(data_from_packet, client_socket_tcp, client_socket_udp)
    except Exception as e:
        print(e)


def udp_punch_hole(ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp):
    """
    creating udp punch_hole
    :param ipv4_for_punch_hole:
    :param port_for_punch_hole:
    :param client_socket_udp:
    :return: True so he can know that he can send him the actual data
    """
    global DATA_FROM_UDP_HOLE_PUNCHING, PACKETS_TO_HANDLE_QUEUE
    try:
        i = 1
        message = 'do udp punch hole'
        print('started to do udp punch hole')
        while DATA_FROM_UDP_HOLE_PUNCHING is None:
            client_socket_udp.sendto(message.encode('utf-8'), (ipv4_for_punch_hole, port_for_punch_hole))
            print(f'sent: {i} to {(ipv4_for_punch_hole, port_for_punch_hole)}')
            i += 1
            try:
                DATA_FROM_UDP_HOLE_PUNCHING, sender_address = client_socket_udp.recvfrom(1024)
                print(f'data from udp hole_punching {DATA_FROM_UDP_HOLE_PUNCHING}')
            except socket_timeout:  # !!
                continue  # !!
                # !!
            except OSError as e:
                print(f"Socket error occurred: {e}")
            except ConnectionResetError as e:
                print(f"Connection reset by peer: {e}")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
        verify_packets_from_bots(client_socket_udp, (ipv4_for_punch_hole, port_for_punch_hole))
        # PACKETS_TO_HANDLE_QUEUE.append(packet1)
    except Exception as e:
        print('tried punch')
        print(e)


def making_the_secret_key(rsa_public_key):
    pass


def handle_giving_data_of_2(mac_of_who_to_send):
    """
    giving the server my mac and who i want to do udp punch hole with
    :return:
    """
    my_mac = get_mac_address()
    my_mac = '876'
    packet_to_add = f'giving_data_of_2: {my_mac},{mac_of_who_to_send}'
    return packet_to_add


def handle_packets_from_server(raw_packet, client_socket_tcp, client_socket_udp):
    """
    handling the data in the packets
    :param raw_packet:
    :param client_socket_tcp:
    :param client_socket_udp:
    :return:
    """
    global executor, PORT_OF_UDP_SERVER, Tor_opening_packets, Alice_dh_public_key
    reply_tor = Tor_opening_packets
    try:
        lines = raw_packet.split('\r\n')
        while '' in lines:
            lines.remove('')
        print(f' the data of the incoming packet : {lines}')
        for line in lines:
            line_parts = line.split()

            # new_client_to_server: [mac of the new client that connected to you] client Node and main to server and server to client Nodes
            # -------------
            if line_parts[0] == 'new_client_to_server:':
                # add this client mac to your data base
                pass
            # -------------

            # -------------
            # [yes],[(ipv4,port)] if not:[no] server to client Node and main
            if line_parts[0] == 'server_answer_for_first_stage_udp_hole_punching:':
                l_parts = line_parts[1].split('?')
                if l_parts[0] == 'yes':
                    another = tuple(l_parts[1][1:-1].split(','))
                    ipv4_for_punch_hole = another[0]
                    port_for_punch_hole = int(another[1])
                    # opening a thread for udp punch_hole
                    executor.submit(udp_punch_hole, ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp)
                    # here he will send the packet
            # -------------

            # -------------
            # [mac],[(ipv4,port)] server to client Node and main
            if line_parts[0] == 'server_notify_bot_for_second_stage_of_udp_hole_punching:':
                # send to the server something so he will see your public ip
                l_parts = line_parts[1].split('?')
                mac_of_other_client = l_parts[0]
                reply_tor += handle_giving_data_of_2(mac_of_other_client)
                client_socket_udp.sendto(reply_tor.encode('utf-8'), (IPV4_OF_SERVER, PORT_OF_UDP_SERVER))
                another = tuple(l_parts[1][1:-1].split(','))
                # print(another)
                ipv4_for_punch_hole = another[0]
                port_for_punch_hole = int(another[1])
                # put in your dictionary the mac as key and his ipv4 and port
                # opening a thread for udp punch_hole
                executor.submit(udp_punch_hole, ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp)
            # -------------

            # -------------
            if line_parts[0] == 'port_of_server:':
                PORT_OF_UDP_SERVER = int(line_parts[1])
            # -------------

            # -------------
            # [public_rsa],[public_dh]
            if line_parts[0] == 'keys_for_security:':
                l_parts = line.split(': ')
                signed_dh = sign_message(Alice_dh_public_key, deserialize_public_key(l_parts[1]))
                reply_tor += f"sigh_message: {signed_dh.decode('utf-8')}"
                client_socket_tcp.send(reply_tor.incode('utf-8'))
            # -------------

            # -------------
            # [public_rsa],[public_dh]
            if line_parts[0] == 'sigh_message:':
                l_parts = line.split(': ')
                sign_dh = deserialize_public_key(l_parts[1])
                print(f' the sign_dh from server: {sign_dh}')

    except Exception as e:
        print(e)


def sending_the_packet_back():
    """
    sending the packet back to where i got it from
    :return:
    """
    pass


def move_the_packet_forward():
    """
    updating the data in the packet and sending to another client
    :return:
    """
    pass


def create_the_packet_and_sending():
    """
    creating the packet like it came from me and sending it to the internet
    :return:
    """
    pass


def handle_packets_from_bots(raw_packet, client_socket_udp, punch_hole_address):
    """
    handling packets from the udp hole punch
    :return:
    """
    global MAC_FOR_KEYS
    try:
        replay_tor = Tor_opening_packets
        lines = raw_packet.split('\r\n')
        while '' in lines:
            lines.remove('')
        print(f' got packet on the way from punch hole and the data: {lines}')
        for line in lines:
            line_parts = line.split()

            # -------------
            # [id]?[ttl]?[data]
            if line_parts[0] == 'packet_on_the_way:':
                # put here in a the dictionary key id: punch_hole_address so i know where to send it back
                l_parts = line_parts[1].split('?')
                # check here the ttl
                ttl = int(l_parts[1])
                if ttl == 1:
                    # here sending the packet to the internet
                    create_the_packet_and_sending()
                else:
                    ttl -= 1
                    # updating the data in the packet and sending to another bot
                    move_the_packet_forward()
            # -------------

            # -------------
            # [id]?[data]
            if line_parts[0] == 'packet_on__the_way_back:':
                l_parts = line_parts[1].split('?')
                # check from the dictionary where to send the packet
                sending_the_packet_back()
            # -------------

            # -------------
            # [id]?[data]
            if line_parts[0] == 'keys_for_security:':
                l_parts = line_parts[1].split(',')
                # check here maybe you need to change the keys to different type
                # MAC_FOR_KEYS

    except Exception as e:
        print(f' error in handling packets from bots {e}')


def verify_packets_from_bots(client_socket_udp, punch_hole_address):
    """
    verifying the packets from bots
    :return:
    """
    global DATA_FROM_UDP_HOLE_PUNCHING
    if tor_filter(DATA_FROM_UDP_HOLE_PUNCHING):
        # print('passed verify from bots')
        data_from_packet = DATA_FROM_UDP_HOLE_PUNCHING.decode('utf-8')
        handle_packets_from_bots(data_from_packet, client_socket_udp, punch_hole_address)


def get_subnet_mask():
    try:
        # Run the ipconfig command and capture the output
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, encoding='utf-8', errors='replace')

        # Print the entire ipconfig output for debugging
        # print(result.stdout)

        # Use regular expression to find the subnet mask in the output
        match = re.search(
            r"(Wi-Fi|Ethernet).*IPv4 Address.*:\s+(\d+\.\d+\.\d+\.\d+).*Subnet Mask.*:\s+(\d+\.\d+\.\d+\.\d+)",
            result.stdout, re.DOTALL)
        if match:
            interface_name = match.group(1)
            ipv4_address = match.group(2)
            subnet_mask = match.group(3)

            return subnet_mask
        else:
            print("Error: IPv4 address and subnet mask not found in the ipconfig output.")
            return None

    except Exception as e:
        print(f"Error: {e}")
        return None


def are_in_same_network(ip1, ip2, subnet_mask):
    ip1_parts = list(map(int, ip1.split('.')))
    ip2_parts = list(map(int, ip2.split('.')))
    subnet_mask_parts = list(map(int, subnet_mask.split('.')))

    # Perform bitwise AND operation for each octet
    network1 = [ip & mask for ip, mask in zip(ip1_parts, subnet_mask_parts)]
    network2 = [ip & mask for ip, mask in zip(ip2_parts, subnet_mask_parts)]

    # Check if the networks are the same
    return network1 == network2


def select_ipv4_server(servers_list):
    """
    selecting ipv4 from the list of servers and i will check if the server is in the same router as me
    if yes, i will do connect to his private ipv4 and if not so to the public one
    :return:
    """
    # ipv4_public, ipv4_private_static, port_tcp, port udp
    global IPV4_OF_SERVER
    try:
        number_of_servers = len(servers_list)
        number_of_servers -= 1
        random_server = random.randint(0, number_of_servers)
        print(f'the list now: {servers_list}. selected random: {random_server}')
        data_of_server = servers_list[random_server]
        if are_in_same_network(str(get_ipv4_address_private()), data_of_server[1], str(get_subnet_mask())):
            # the server and client are in the same network
            IPV4_OF_SERVER = data_of_server[1]
        else:
            # not in the same network
            IPV4_OF_SERVER = data_of_server[0]

        return random_server
    except Exception as e:
        print(e)
        traceback.print_exc()


def setting_client_socket_for_server_ipv6_or_ipv4():
    """
    checking what server the client can connect to
    :return:
    """
    # here he will open the json file and will pick up randomly a computer for ipv6
    # when i will have the db i will change the for
    global IPV4_OF_SERVER, IPV6_OF_SERVER, DATA_OF_SERVERS
    for i in range(1, 2):
        try:
            ipv6 = select_ipv6_server()
            client_socket = socket(AF_INET6, SOCK_STREAM)
            client_socket.connect((IPV6_OF_SERVER, 56789))
            print(f"Connected to {IPV6_OF_SERVER}:{56789}")
            return client_socket
        except Exception as e:
            print(f'your error is {e} i am trying to find another ipv6')
    print('there is no available ipv6 for you so i am trying to do it with ipv4')
    # do here the ipv4 select
    client_socket = socket(AF_INET, SOCK_STREAM)
    avilable_serves = DATA_OF_SERVERS
    a = 0
    for i in range(0, len(DATA_OF_SERVERS)):
        try:
            index_if_not_working = select_ipv4_server(avilable_serves)
            client_socket.connect((IPV4_OF_SERVER, 56789))
            a = 1
        except Exception as e:
            print(e)
            print('server is not available. trying another one.')
            del avilable_serves[index_if_not_working]
    if a == 0:
        print('there is no available server right now, please try later')
    else:
        print(f"connected to : {IPV4_OF_SERVER}")
    return client_socket


def select_ipv6_server():
    """
    selecting randomly ipv6 server
    :return: ipv6 address
    """
    return None


def setting_client_socket_for_bots():
    try:
        global Port_for_bot
        a = 0
        client_udp_socket = socket(AF_INET, SOCK_DGRAM)
        client_udp_socket.settimeout(0.2)
        # bind do !!!!!!!!!!!!!!!
        while a == 0:
            try:
                client_udp_socket.bind(('0.0.0.0', Port_for_bot))
                a = 1
            except Exception as e:
                print(f"Error: {e}, Port {Port_for_bot} is already in use.")
                select_random_port()
        return client_udp_socket
    except Exception as e:
        print(e)


def get_ipv4_address_private():
    # Get the hostname of the local machine
    hostname = gethostname()

    # Get the IPv4 address associated with the hostname
    ip_address = gethostbyname(hostname)

    return ip_address


def get_mac_address1():
    try:
        my_mac = get_mac_address()
        return my_mac
    except Exception as e:
        print(e)


def get_public_ip() -> str:
    """
    Trying to get the public IP.
    :return: <String> the public IP address.
    """

    # ----------------
    # Try to get public IP address from multiple external APIs
    api_urls = [
        'https://ipinfo.io/ip',  # returns response as plaintext
        'https://api.ipify.org?format=json',  # returns response as JSON object
        'https://api.myip.com/',  # returns response as JSON object
        'https://icanhazip.com/',  # returns response as plaintext
        'https://ifconfig.me/',  # returns response as plaintext
        'https://ip.seeip.org/',  # returns response as plaintext
        'https://www.trackip.net/ip',  # returns response as plaintext
    ]
    methods = ['GET', 'HEAD']
    for url in api_urls:
        for method in methods:
            try:
                response = requests.request(method, url, timeout=3)
                if response.status_code == 200:  # (200 is a success HTTP status code)
                    if url in ['https://api.ipify.org?format=json', 'https://api.myip.com/']:
                        # response is JSON object
                        if response.json()['ip'] != '':  # some APIs may reply with empty strings
                            return response.json()['ip']
                    # response is plaintext
                    if response.text.strip() != '':  # some APIs may reply with empty strings
                        return response.text.strip()
            except:
                pass
    # ----------------

    # If all failed
    return "[Your public IP (our system couldn't find it)]"


def notify_mac_to_server(client_socket_tcp):
    global Tor_opening_packets, Port_for_bot
    try:
        packet_to_send = Tor_opening_packets
        mac_address = get_mac_address1()
        # here instead of it i will add the mac to the dictionary
        mac_address = '876'
        # packet_to_send += f'new_client_to_server: {mac_address},{get_public_ip()},{Port_for_bot}\r\n'
        packet_to_send += f'new_client_to_server: {mac_address},{get_ipv4_address_private()},{get_public_ip()},{Port_for_bot}\r\n'
        packet_to_send = sending_the_keys_for_security(packet_to_send)
        # print(f" how keys look : {packet_to_send.encode('utf-8')}")
        client_socket_tcp.send(packet_to_send.encode('utf-8'))
        data = client_socket_tcp.recv(1024)
        if tor_filter(data):
            port_for_udp = data.decode('utf-8')
            handle_packets_from_server(port_for_udp, None, None)
    except Exception as e:
        print(e)


def main():
    try:
        global executor, Alice_dh_public_key, Alice_rsa_public_key, Alice_dh_private_key, Alice_rsa_private_key
        client_socket_tcp = setting_client_socket_for_server_ipv6_or_ipv4()
        # making keys
        Alice_dh_private_key, Alice_dh_public_key = generate_dh_key_pair()
        Alice_rsa_private_key, Alice_rsa_public_key = generate_rsa_key_pair()
        print(f'alice rsa public key: {Alice_rsa_public_key}')
        # Alice signs her DH public key
        print('did keys')
        # waits_for_server_approve = client_socket_tcp.recv(1024)
        # notifying the server about my mac
        select_random_port()
        notify_mac_to_server(client_socket_tcp)
        client_socket_udp = setting_client_socket_for_bots()
        # a thread for handling the packets
        executor.submit(verify_packets_from_server, client_socket_tcp, client_socket_udp)
        while True:
            response_from_server = client_socket_tcp.recv(1024)
            # print(response_from_server)
            # add the packets to queue
            PACKETS_TO_HANDLE_QUEUE.append(response_from_server)
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
