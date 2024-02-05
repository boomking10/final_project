""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import base64
import random

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

import traceback
import subprocess
import re
from socket import socket, AF_INET6, SOCK_DGRAM, SOCK_STREAM, AF_INET, gethostbyname, gethostname, \
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

Tor_opening_packets = 'Tor\r\n'
# creating json file with my information there. this lines will be only in my code because
# when first they install the exe they will need to know where to send first
# mac: tuple(str_ipv4, int_port), client_socket, (public_rsa, public_dh)
MY_DATA_FOR_BOTS = {}
# put here the port
PORT_FOR_UDP = 56779
executor = ThreadPoolExecutor(thread_name_prefix='worker_thread_')
Alice_dh_private_key, Alice_dh_public_key = None, None
Alice_rsa_private_key, Alice_rsa_public_key = None, None
Alice_signature = None


# # Use forward slashes or a raw string for the file path
# file_path = 'C:/Networks/last_project/server.json'
# MY_DATA_FOR_BOTS = {'Mac': 'D0-37-45-92-6C-91', 'Ipv4': '10.0.0.11', 'Port': 56779}
# with open(file_path, 'w') as json_file:
#     json.dump(MY_DATA_FOR_BOTS, json_file)
# ######################################################################
# PACKETS_TO_HANDLE_QUEUE = deque()

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
    print(public_key)
    message = serialize_public_key(message)
    #message_64 = base64.b64encode(message).decode('utf-8')
    # message = message.public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # )
    message = message.replace(b'-----BEGIN PUBLIC KEY-----\n', b'').replace(b'-----END PUBLIC KEY-----\n', b'')
    print(message)
    alice_signature = public_key.encrypt(
        message,
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

def sending_the_keys_for_security(packet_to_send, public_rsa_of_bob):
    """
    adding the the public and private keys of dh and rsa to the packet for the server
    :return:
    """
    global Tor_opening_packets, Alice_dh_public_key, Alice_rsa_public_key
    rsa_public_to_send = serialize_public_key(Alice_rsa_public_key)
    rsa_public_to_send = rsa_public_to_send.decode('utf-8')
    # dh_public_to_send = serialize_public_key(Alice_dh_public_key)
    # dh_public_to_send = dh_public_to_send.decode('utf-8')
    packet_to_send += f"keys_for_security: {rsa_public_to_send}\r\nsigh_message: {(sign_message(Alice_dh_public_key, public_rsa_of_bob)).decode('utf-8')}"
    return packet_to_send


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


def server_notify_bot_for_second_stage_of_udp_hole_punching(mac_of_the_1, ip, port, server_socket_udp):
    global MY_DATA_FOR_BOTS
    try:
        packet_to_add = None
        if mac_of_the_1 in MY_DATA_FOR_BOTS:
            data_for_person = MY_DATA_FOR_BOTS[mac_of_the_1][0]
            # if the in the same internet
            if are_in_same_network(data_for_person[0], ip, str(get_subnet_mask())):
                packet_to_add = f'server_notify_bot_for_second_stage_of_udp_hole_punching: {mac_of_the_1}?({data_for_person[0]},{data_for_person[2]})'
            # if not
            else:
                packet_to_add = f'server_notify_bot_for_second_stage_of_udp_hole_punching: {mac_of_the_1}?({ip},{port})'
        return packet_to_add
    except Exception as e:
        traceback.print_exc()
        print(e)


def handle_first_stage_udp_hole_punching(mac_of_the_person2, ip, port):
    """

    :param mac_of_1: the one that started punch hole
    :param mac_of_the_person2:
    :param ip:
    :param port:
    :return:
    """
    global MY_DATA_FOR_BOTS
    try:
        data_for_person = MY_DATA_FOR_BOTS[mac_of_the_person2][0]
        # if same internet
        if are_in_same_network(data_for_person[0], ip, str(get_subnet_mask())):
            packet_to_add = f'server_answer_for_first_stage_udp_hole_punching: yes?({data_for_person[0]},{data_for_person[2]})'
        # if not
        else:
            print(f'the public ip of 2: {data_for_person[1]}. the public port 2: {port}')
            packet_to_add = f'server_answer_for_first_stage_udp_hole_punching: yes?({ip},{port})'
        return packet_to_add
    except Exception as e:
        print(e)


def updating_data_base():
    pass


def handle_packets_from_computers(raw_packet, client_socket, client_address, server_socket_udp):
    """
    handeling all the packets coming to the server
    :param raw_packet:
    :param client_socket:
    :param client_address:
    :param server_socket_udp:
    :return:
    """
    global executor, Tor_opening_packets, MY_DATA_FOR_BOTS, PORT_FOR_UDP
    replay_tor = Tor_opening_packets
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
                l_parts = line_parts[1].split(',')
                mac_of_bot = l_parts[0]
                # (private ip, public ip, port number private, port number public), client socket
                MY_DATA_FOR_BOTS[l_parts[0]] = [(l_parts[1], l_parts[2], l_parts[3]), client_socket]
                # add this client mac in line_parts[1] to your data base and with his address
                # sending the client the port for udp
                replay_tor += f'port_of_server: {PORT_FOR_UDP}'
                # print(f'replay_tor)
                client_socket.send(replay_tor.encode('utf-8'))
                updating_data_base()
                pass
            # -------------

            # -------------
            # this packet has been sent in udp
            if line_parts[0] == 'start_first_stage_udp_hole_punching:':
                l_parts = line_parts[1].split(',')
                # in l_parts[1] you have the mac. open it from your dictionary and send server_answer_for_first_stage_udp_hole_punching
                replay_tor2 = replay_tor
                # and do notify the other bot
                client_address_from_2 = None
                # the public port and ip of the person that started the punch hole
                public_port_of_1 = client_address[1]
                public_ip_of_1 = client_address[0]
                print(f'the public ip of 1: {public_ip_of_1}. the public port 1: {public_port_of_1}')
                # updating the dictionary of the bot
                replay_tor2 += server_notify_bot_for_second_stage_of_udp_hole_punching(l_parts[0], public_ip_of_1,
                                                                                       public_port_of_1,
                                                                                       server_socket_udp)
                if l_parts[1] in MY_DATA_FOR_BOTS:
                    print(f' what i am sending to the second bot in punch hole: {replay_tor2}')
                    MY_DATA_FOR_BOTS[l_parts[1]][1].send(replay_tor2.encode('utf-8'))
                else:
                    replay_tor += f'server_answer_for_first_stage_udp_hole_punching: no'
                    MY_DATA_FOR_BOTS[l_parts[0]][1].send(replay_tor.encode('utf-8'))
            # -------------

            # -------------
            # this packet has been sent in udp
            if line_parts[0] == 'giving_data_of_2:':
                l_parts = line_parts[1].split(',')
                replay_tor += handle_first_stage_udp_hole_punching(l_parts[0], client_address[0], client_address[1])
                # sending to the client i got the packet from
                print(f' what i am sending to the first bot in punch hole: {replay_tor}')
                client_socket = MY_DATA_FOR_BOTS[l_parts[1]][1]
                client_socket.send(replay_tor.encode('utf-8'))
                print('finished sending each of the bots data')

            # -------------

            # -------------
            if line_parts[0] == 'keys_for_security:':
                l_parts = line.split(': ')
                MY_DATA_FOR_BOTS[mac_of_bot].append(
                    [deserialize_public_key(l_parts[1]), None])
                # print(f' the data of the bot: {MY_DATA_FOR_BOTS[mac_of_bot]}')
                packet_to_send = Tor_opening_packets
                # sending the clients the server public keys
                # print(f'the public rsa of bob: {deserialize_public_key(l_parts[1])}')
                # print(type(deserialize_public_key(l_parts[1])))
                packet_to_send = sending_the_keys_for_security(packet_to_send, deserialize_public_key(l_parts[1]))
                client_socket.send(packet_to_send.encode('utf-8'))
            # -------------

            # -------------
            if line_parts[0] == 'sigh_message:':
                l_parts = line.split(': ')
                sign_dh = deserialize_public_key(l_parts[1])
                print(f' the sign_dh from server: {sign_dh}')

    except Exception as e:
        traceback.print_exc()
        print(e)


def tor_filter(payload):
    # print('got here')
    # print(payload.decode('utf-8'))
    expected = 'Tor'.encode('utf-8')
    return payload[:len(expected)] == expected


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


def select_random_port():
    global PORT_FOR_UDP
    PORT_FOR_UDP = random.randint(20000, 29000)


def handle_packet_from_udp(server_socket_udp):
    """
    recving packets in udp
    :return:
    """
    while True:
        try:
            data, client_address = server_socket_udp.recvfrom(1024)
        except socket_timeout:  # !!
            continue  # !!
        # !!
        except OSError as e:
            print(f"Socket error occurred: {e}")

        except ConnectionResetError as e:
            print(f"Connection reset by peer: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        # adds the payload to the queue to wait for being handled
        if tor_filter(data):
            data_from_packet = data.decode('utf-8')
            handle_packets_from_computers(data_from_packet, None, client_address, server_socket_udp)


def get_ipv4_address_private():
    # Get the hostname of the local machine
    hostname = gethostname()

    # Get the IPv4 address associated with the hostname
    ip_address = gethostbyname(hostname)
    # print(f'your ipv4 is: {ip_address}')
    return ip_address


def set_socket_udp():
    """
    Setting a socket object of AF_INET (IPv4) and S (TCP).
    :return: <Socket> the socket object.
    """
    global PORT_FOR_UDP
    # setting an IPv4/TCP socket
    server_socket = socket(AF_INET, SOCK_DGRAM)
    # binding the server socket
    # select_random_port()
    server_socket.bind(('0.0.0.0', PORT_FOR_UDP))
    return server_socket


def set_socket_tcp():
    """
    Setting a socket object of AF_INET (IPv4) and S (TCP).
    :return: <Socket> the socket object.
    """
    # setting an IPv4/TCP socket
    server_socket = socket(AF_INET, SOCK_STREAM)
    # binding the server socket
    server_socket.bind(('0.0.0.0', 56789))
    return server_socket


def new_clients(client_socket, client_address, server_socket_udp):
    """
    verifying the packet
    and listening to packets
    :param client_socket:
    :param client_address:
    :param server_socket_udp:
    :return:
    """
    global executor
    # telling the client my port for udp
    # executor.submit(handle_packet_from_udp, server_socket_udp)
    # response = client_socket.recv(1024)
    # if tor_filter(response):
    #     data_from_packet = response.decode('utf-8')
    #     handle_packets_from_computers(data_from_packet, client_socket, client_address, server_socket_udp)
    while True:
        incoming_packet = client_socket.recv(1024)
        if tor_filter(incoming_packet):
            # print('passed')
            data_from_packet = incoming_packet.decode('utf-8')
            # print(data_from_packet)
            handle_packets_from_computers(data_from_packet, client_socket, client_address, server_socket_udp)


def main():
    try:
        global executor, Alice_dh_public_key, Alice_rsa_public_key, Alice_dh_private_key, Alice_rsa_private_key
        server_socket_tcp = set_socket_tcp()
        server_socket_udp = set_socket_udp()
        print(f'your private ip: {get_ipv4_address_private()}')
        print(f'your public ip: {get_public_ip()}')
        # making keys
        #Alice_dh_private_key, Alice_dh_public_key = generate_dh_key_pair()
        Alice_rsa_private_key, Alice_rsa_public_key = generate_rsa_key_pair()
        Alice_dh_public_key, Alice_dh_private_key = make_dh_keypair()
        #print(sign_message(Alice_dh_public_key, Alice_rsa_public_key))
        alice_dh_public_bytes = Alice_dh_public_key.export_key()
        #print(sign_message(alice_dh_public_bytes, Alice_rsa_public_key))
        Alice_rsa_public_key = RSA.import_key(alice_dh_public_bytes)
        # Alice signs her DH public key
        # print(serialize_dh_public_key(Alice_rsa_public_key))
        print('did keys')
        # print(get_subnet_mask())
        # setting a thread which will handle new clients.
        executor.submit(handle_packet_from_udp, server_socket_udp)
        while True:
            try:  # !!
                server_socket_tcp.listen(1)  # getting incoming packets
                client_socket, client_address = server_socket_tcp.accept()
                print(f' the address of the client who connected: {client_address}')
                executor.submit(new_clients, client_socket, client_address, server_socket_udp)
                # PACKETS_TO_HANDLE_QUEUE.append((client_socket, client_address))
            except Exception as e:
                print(e)
    except Exception as e:
        traceback.print_exc()
        print(e)


if __name__ == "__main__":
    main()
