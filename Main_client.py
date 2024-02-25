""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import os
import re
import subprocess

import requests

"""""""""""""""""""""""""""""""""THE PROTOCOL FOR THE PACKETS"""""""""""""""""""""""
"Tor;""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""''""""""""''"""
"new_client_to_server_main or _node: [mac of the new client that connected to you] if its node so without that,[his ipv4 private], [his ipv4 public], [his port number]  client Node and main to server and server to client Nodes"
"port_of_server: [the port of the server in udp] server to everyone"
"start_first_stage_udp_hole_punching: [mac_of_the person who sent the packet],[mac of the person you want to do udp punch_hole] client Node and main to server "
"server_answer_for_first_stage_udp_hole_punching: if the server connect to the bot:[yes]?[(ipv4,port)]?[mac_of_other_bot] if not:[no] server to client Node and main "
"server_notify_bot_for_second_stage_of_udp_hole_punching: [mac of the person who wants to do udp punch]?[(ipv4,port)] server to client Node and main"
"giving_data_of_2: [mac_of_the person who sent the packet],[mac of the person you want to do udp punch_hole]"
"packet_on_the_way: [id]?[ttl]?[data] main client to client Node and client Node to Client Node"
"packet_on__the_way_back: [id]?[data] client Node to Client Node and client Node to main client "
"new_ipv6_server: [ipv6] new ipv6 server to all other ipv6 servers that he has"
"keys_for_security: [public_rsa] everyone to anyone "
"sigh_message: [signed_public_key]"
"sigh_message_for_computer: [signed_public_key]"
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

import traceback
import random
import time
from getmac import get_mac_address
import uuid
from socket import socket, error, AF_INET6, AF_INET, SOCK_DGRAM, SOCK_STREAM, gethostbyname, gethostname, \
    timeout as socket_timeout
from concurrent.futures import ThreadPoolExecutor
import json
from collections import deque
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, PKCS1v15, MGF1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

THE_PACKET_GOT_BACK = None
DATA_FROM_UDP_HOLE_PUNCHING = None
# dictionary of all the available bots i have mac: (cipher object)
AVAILABLE_BOTS = {}
# data base with json like mac: and what server they are connected to( his ipv6)
Port_for_bot = None
PORT_OF_UDP_SERVER = None
IPV4_OF_SERVER = '172.20.10.2'
IPV6_OF_SERVER = '2a06:c701:4550:a00:fad4:e6f3:25c7:8b68'
Tor_opening_packets = 'Tor\r\n'
Packet_to_internet = None
executor = ThreadPoolExecutor(thread_name_prefix='worker_thread_')
PACKETS_TO_HANDLE_QUEUE = deque()
Alice_dh_private_key, Alice_dh_public_key = None, None
Alice_rsa_private_key, Alice_rsa_public_key = None, None
Alice_signature = None
Shared_key_with_server = None
Mac_address = None
Iv_with_server = None
Padder = padding.PKCS7(128).padder()
Unpadder = padding.PKCS7(128).unpadder()
# ipv4_public, ipv4_private_static, port_tcp, port udp
DATA_OF_SERVERS = [('147.235.215.64', '10.0.0.11', 56789, 56779), ('188.120.157.25', '192.168.175.229', 56789, 56779), ('2.52.14.104', '172.20.10.2', 56789, 56779)]


# security
###################################################################################################
def generate_dh_key_pair():
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    g = 2

    params_numbers = dh.DHParameterNumbers(p, g)
    parameters = params_numbers.parameters(default_backend())
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
        key_size=4096,
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



def encrypt_server(plaintext):
    global Shared_key_with_server
    # (encryptor, decryptor, padder, unpadder)
    #print(f' the plaint text before encrypting: {plaintext}')
    padder = padding.PKCS7(128).padder()
    cipher = Shared_key_with_server
    encryptor = cipher.encryptor()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext


def decrypt_server(ciphertext):
    try:
        global Shared_key_with_server
        # (encryptor, decryptor, padder, unpadder)
        cipher = Shared_key_with_server
        unpadder = padding.PKCS7(128).unpadder()
        decryptor = cipher.decryptor()
        decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the decrypted plaintext
        #print(f' my unpadder: {Shared_key_with_server[3].block_size}')
        plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
        return plaintext
    except:
        traceback.print_exc()


def encrypt_bot(plaintext, cipher):
    global Shared_key_with_server
    # (encryptor, decryptor, padder, unpadder)
    #print(f' the plaint text before encrypting: {plaintext}')
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext


def decrypt_bot(ciphertext, cipher):
    global Shared_key_with_server
    # (encryptor, decryptor, padder, unpadder)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted plaintext
    #print(f' my unpadder: {Shared_key_with_server[3].block_size}')
    plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
    return plaintext


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
            # print(len(PACKETS_TO_HANDLE_QUEUE))
            # print('passed')
            payload = PACKETS_TO_HANDLE_QUEUE.popleft()
            plaint_text = decrypt_server(payload)
            if tor_filter(plaint_text):
                if b'goren' in plaint_text:
                    data1 = plaint_text.split(b'goren')[0]
                else:
                    data1 = plaint_text
                data_from_packet = data1.decode('utf-8')
                # print(data_from_packet)
                handle_packets_from_server(data_from_packet, client_socket_tcp, client_socket_udp, plaint_text)
    except Exception as e:
        traceback.print_exc()
        print(e)


def keeping_the_udp_punch_hole_alive(ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp):
    """
    keeping the udp punch hole alive until i get the packet back.
    :param ipv4_for_punch_hole:
    :param port_for_punch_hole:
    :param client_socket_udp:
    :return:
    """
    global DATA_FROM_UDP_HOLE_PUNCHING
    packet_to_keep_alive = 'keeping alive punch hole'
    while DATA_FROM_UDP_HOLE_PUNCHING is None:
        client_socket_udp.sendto(packet_to_keep_alive.encode('utf-8'), (ipv4_for_punch_hole, port_for_punch_hole))
        time.sleep(30)


def udp_punch_hole(ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp, cipher):
    """
    creating udp punch_hole and sending the packet to the internet and waiting for the packet to come back
    :param cipher:
    :param ipv4_for_punch_hole:
    :param port_for_punch_hole:
    :param client_socket_udp:
    :return: True so he can know that he can send him the actual data
    """
    global DATA_FROM_UDP_HOLE_PUNCHING, Packet_to_internet
    try:
        i = 1
        print('starting the udp punch hole')
        # put here the real message you want to send
        #ciphertext = encrypt_bot(Packet_to_internet.encode('utf-8'), cipher)
        while DATA_FROM_UDP_HOLE_PUNCHING is None:
            client_socket_udp.sendto(Packet_to_internet, (ipv4_for_punch_hole, port_for_punch_hole))
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
            # adds the payload to the queue to wait for being handled
        DATA_FROM_UDP_HOLE_PUNCHING = None
        # print('exchanging security keys')
        # sending_the_keys_for_security(client_socket_udp, (ipv4_for_punch_hole, port_for_punch_hole))

        # waiting for the packet to come back
        while DATA_FROM_UDP_HOLE_PUNCHING is None:
            try:
                data, sender_address = client_socket_udp.recvfrom(1024)
                if data != 'do udp punch hole':
                    DATA_FROM_UDP_HOLE_PUNCHING = data
                    print(f'data from udp hole_punching on the way back {DATA_FROM_UDP_HOLE_PUNCHING}')
            except socket_timeout:  # !!
                continue  # !!
        PACKETS_TO_HANDLE_QUEUE.append(DATA_FROM_UDP_HOLE_PUNCHING)
        DATA_FROM_UDP_HOLE_PUNCHING = None
        # i want to keep the connection
    except Exception as e:
        traceback.print_exc()
        print(e)


def handle_packets_from_server(raw_packet, client_socket_tcp, client_socket_udp, payload):
    """
    handling the data in the packets
    :param packet_to_internet:
    :param raw_packet:
    :param client_socket_tcp:
    :param client_socket_udp:
    :return:
    """
    global executor, Tor_opening_packets, Packet_to_internet, PORT_OF_UDP_SERVER, Alice_dh_public_key, Mac_address, Shared_key_with_server, Iv_with_server, AVAILABLE_BOTS
    replay_tor = Tor_opening_packets
    is_bytes = False
    try:
        if b'sigh_message_for_computer:' in payload:
            lines = payload.split(b'\r\n')
            is_bytes =True
            while b'' in lines:
                lines.remove(b'')
        else:
            lines = raw_packet.split('\r\n')
            while '' in lines:
                lines.remove('')
        print(f' the data of the packet: {lines}')
        for line in lines:
            if is_bytes:
                if b'sigh_message_for_compute' in line:
                    line_parts = line.split(b'goren')
                else:
                    line_parts = line.split()
            else:
                line_parts = line.split()
            # new_client_to_server: [mac of the new client that connected to you] client Node and main to server and server to client Nodes
            # -------------
            if line_parts[0] == b'new_client_to_server_node:':
                # add this client mac to your dictionary
                mac_of_new_client = line_parts[1].decode('utf-8')
                AVAILABLE_BOTS[mac_of_new_client] = None
                pass
            # -------------

            # -------------
            # [yes]?[(ipv4,port)] if not:[no] server to client Node and main
            if line_parts[0] == 'server_answer_for_first_stage_udp_hole_punching:':
                l_parts = line_parts[1].split('?')
                if l_parts[0] == 'yes':
                    # print(l_parts[1])
                    another = tuple(l_parts[1][1:-1].split(','))
                    # print(another)
                    ipv4_for_punch_hole = another[0]
                    port_for_punch_hole = int(another[1])
                    cipher = AVAILABLE_BOTS[l_parts[2]]
                    executor.submit(udp_punch_hole, ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp, cipher)
            # -------------

            # -------------
            # [id]?[data] client Node to Client Node and client Node to main client
            if line_parts[0] == 'packet_on__the_way_back:':
                l_parts = line_parts[1].split('?')
                # in l_parts[1] you have the data to show to the user
            # -------------

            # -------------
            # [public_rsa],[public_dh]
            if line_parts[0] == 'keys_for_security:':
                l_parts = line.split(': ')
                signed_dh = sign_message(Alice_dh_public_key, deserialize_public_key(l_parts[1]))
                replay_tor += f"mac_of_the_person_who_sent_the_packet: {Mac_address}\r\nsigh_message: goren"
                # print(f'the packet i am sending with sign: {reply_tor}')
                Iv_with_server = os.urandom(16)  # 16 bytes IV for AES
                client_socket_tcp.send(replay_tor.encode('utf-8')+signed_dh + 'amit'.encode('utf-8') + Iv_with_server)
            # -------------

            # -------------
            # [public_rsa],[public_dh]
            if line_parts[0] == 'sigh_message:':
                l_parts = payload.split(b'goren')
                bob_signature = l_parts[1]
                print(f' length of the cyphtext: {len(bob_signature)}')
                # print(f'the cyphetext: {Ciphertext_encoded}')
                decrypted_bob_dh_public_key = Alice_rsa_private_key.decrypt(
                    bob_signature,
                    OAEP(
                        mgf=MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                # print(f' the value of dh public: {decrypted_bob_dh_public_key}')
                bob_dh_public = serialization.load_pem_public_key(decrypted_bob_dh_public_key,
                                                                  backend=default_backend())
                # print(f' the dectypted public key: {decrypted_bob_dh_public_key} and type{type(decrypted_bob_dh_public_key)}')
                # print(f'the real public key: {bob_dh_public}')
                # print(f' value of dh private: {Alice_dh_private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())} and value of dh public: {serialize_public_key(bob_dh_public)}')
                #print(f'alic param p and g: {Alice_dh_private_key.parameters().parameter_numbers().p},{Alice_dh_private_key.parameters().parameter_numbers().g} and bob params p and g: {bob_dh_public.public_numbers().parameter_numbers.p},{bob_dh_public.public_numbers().parameter_numbers.g}')
                Shared_key_with_server = Alice_dh_private_key.exchange(bob_dh_public)
                Shared_key_with_server = Shared_key_with_server[:32]
                print(f'the len of shared key: {len(Shared_key_with_server)}')
                cipher = Cipher(algorithms.AES(Shared_key_with_server), modes.CBC(Iv_with_server),
                                backend=default_backend())

                # Create a Padder for adding padding to the message
                Shared_key_with_server = cipher
                print(f' the shared from server: {Shared_key_with_server}')
            # -------------

            # -------------
            # [public_rsa],[public_dh]
            if line_parts[0] == b'sigh_message_for_computer: ':
                bob_public_dh_and_iv = line_parts[1].split(b'amit')
                bob_public_dh = bob_public_dh_and_iv[0]
                bob_iv = bob_public_dh_and_iv[1]
                print(f'bob iv len: {len(bob_iv)}')
                shared_secret = Alice_dh_private_key.exchange(serialization.load_pem_public_key(bob_public_dh, backend=default_backend()))[:32]
                cipher = Cipher(algorithms.AES(shared_secret),
                                modes.CBC(bob_iv),
                                backend=default_backend())
                # opening a thread for udp punch_hole
                AVAILABLE_BOTS[mac_of_new_client] = cipher
                #executor.submit(udp_punch_hole, ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp, cipher)
                print(f'new client connected to server: {AVAILABLE_BOTS}')
            # -------------

            # -------------
            if line_parts[0] == 'port_of_server:':
                PORT_OF_UDP_SERVER = int(line_parts[1])
            # -------------

            # -------------
            # [id]?[data]
            if line_parts[0] == 'packet_on__the_way_back:':
                l_parts = line_parts[1].split('?')
                # check from the dictionary where to send the packet
    except Exception as e:
        traceback.print_exc()
        print(line_parts)
        print(line)


def handle_packets_from_bots():
    pass


def handle_packets():
    """
    i will check here if the packets are from the server or from the bots by id.
    according to the result i will call the correct function
    :return:
    """
    pass


def select_ipv6_server():
    """
    selecting randomly ipv6 server
    :return: ipv6 address
    """
    return None


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
        data_of_server = servers_list[random_server]
        print(f'the list now: {servers_list}. selected random: {random_server}')
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
            break
        except Exception as e:
            print(e)
            print('server is not available. trying another one.')
            del avilable_serves[index_if_not_working]
    if a == 0:
        print('there is no available server right now, please try later')
    else:
        print(f"connected to : {IPV4_OF_SERVER}")
    return client_socket


def setting_client_socket_for_bots():
    try:
        global Port_for_bot
        a = 0
        client_udp_socket = socket(AF_INET, SOCK_DGRAM)
        client_udp_socket.settimeout(0.2)
        # do bind !!!!!!!!!!!!!!!
        # client_udp_socket.bind((get_ipv4_address(), Port_for_bot))
        while a == 0:
            # print('69')
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


def handling_keys_from_server(data):
    """
    getting the keys from the server
    :param data:
    :return:
    """
    global SERVER_FOR_KEYS
    if tor_filter(data):
        data_from_packet = data.decode('utf-8')
        handle_packets_from_server(data_from_packet, None, None)


def random_id():
    """
    :return: returning a random number between 1-10
    """


def random_ttl():
    """
    :return: random ttl. if i have more than 3 computers so it will be between 3-computers i have.
    but if less so the number of computers i have
    """
    global AVAILABLE_BOTS
    if len(AVAILABLE_BOTS) < 3:
        return len(AVAILABLE_BOTS)
    ttl = random.randint(3, len(AVAILABLE_BOTS))
    return ttl


def select_bot():
    """
    select a bot by random from the list of bots i have. i have the ttl and the * id
    :return: list of the bots that will participate in the tor
    """
    global AVAILABLE_BOTS
    way_to_destination = []
    # choosing how much computer i will pass
    last_integer = None
    ttl = random_ttl()
    print(AVAILABLE_BOTS)
    for i in range(0, ttl):
        while True:
            random_bot_id = random.choice(list(AVAILABLE_BOTS.keys()))
            if last_integer != random_bot_id:
                last_integer = random_bot_id
                way_to_destination.append(random_bot_id)
                break
    return way_to_destination


def get_mac_address1():
    try:
        my_mac = get_mac_address()
        return my_mac
    except Exception as e:
        print(e)


def check_user_info(client_socket_udp, client_socket_tcp):
    """
    checking here if the user typed something.
    if he did so i will call 3 functions:
    1 for selecting the ttl
    2 for choosing the id of the packet
    building the packet with id?ttl?data
    3 for choosing the next bot to move
    (in this function i will send the server a packet for information about the bot i selected and i will do a receive here also)
    :return: nothing, i am putting in the global Packet_to_internet the new value
    """
    try:
        global Tor_opening_packets, Packet_to_internet, IPV4_OF_SERVER, PORT_OF_UDP_SERVER, AVAILABLE_BOTS, Port_for_bot, Mac_address
        data = None
        while True:
            user_input = input()
            if user_input == 'start':
                data = user_input.encode('utf-8')
                mac_bot_list = select_bot()
                ttl = 1
                id1 = 1
                mac_bot = '876'
                first_packet = Tor_opening_packets
                # Packet_to_internet = Tor_opening_packets.encode('utf-8')
                print(f'the random way of the packet {mac_bot_list}')
                # first_bot = mac_bot_list.pop(0)
                if len(mac_bot_list) > 1:
                    i = 1
                    for bot in reversed(mac_bot_list):
                        if i == 1:
                            i += 1
                            Packet_to_internet = f'{Tor_opening_packets}id_of_packet: {Port_for_bot}\r\npacket_on_the_way: first_person{Mac_address}buda_end'.encode('utf-8') + data
                            Packet_to_internet = encrypt_bot(Packet_to_internet, AVAILABLE_BOTS[mac_bot_list[-1]])
                        else:
                            Packet_to_internet = f'{Tor_opening_packets}id_of_packet: {Port_for_bot}\r\npacket_on_the_way: start{Mac_address},{who_to_send}finished'.encode('utf-8') + Packet_to_internet
                            print(f'tha packet to send to the internet now: {Packet_to_internet}')
                            if i != len(mac_bot_list):
                                i += 1
                                Packet_to_internet = encrypt_bot(Packet_to_internet, AVAILABLE_BOTS[bot])
                        who_to_send = bot
                    # Packet_to_internet = Tor_opening_packets.encode('utf-8') + Packet_to_internet
                    Packet_to_internet = encrypt_bot(Packet_to_internet, AVAILABLE_BOTS[mac_bot_list[0]])
                else:
                    Packet_to_internet = Tor_opening_packets.encode('utf-8') + f'id_of_packet: {Port_for_bot}\r\npacket_on_the_way: first_person{Mac_address}buda_end'.encode('utf-8') + data
                    Packet_to_internet = encrypt_bot(Packet_to_internet, AVAILABLE_BOTS[mac_bot_list[0]])
                # Packet_to_internet += f'packet_on_the_way: {id1}?{ttl}?{data}'
                # Packet_to_internet += f'packet_on_the_way: {id1}?{ttl}?{data}'
                first_packet += f'start_first_stage_udp_hole_punching: {Mac_address},{mac_bot_list[0]}'
                ciphertext = encrypt_server(first_packet.encode('utf-8'))
                #print(f' the packet i am sending to the server for moving the packet: {ciphertext}')
                client_socket_udp.sendto(ciphertext, (IPV4_OF_SERVER, PORT_OF_UDP_SERVER))
                # response_from_server = client_socket_tcp.recv(1024)
                # PACKETS_TO_HANDLE_QUEUE.append(response_from_server)
                # print('got here')
    except Exception as e:
        traceback.print_exc()
        print(f' got it here {e}')


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
    global Tor_opening_packets, Port_for_bot, Mac_address
    try:
        packet_to_send = Tor_opening_packets
        Mac_address = get_mac_address1()
        # packet_to_send += f'new_client_to_server: {mac_address},{get_public_ip()},{Port_for_bot}\r\n'
        packet_to_send += f'new_client_to_server_main: {Mac_address},{get_ipv4_address_private()},{get_public_ip()},{Port_for_bot}\r\n'
        packet_to_send = sending_the_keys_for_security(packet_to_send)
        # print(f" how keys look : {packet_to_send.encode('utf-8')}")
        client_socket_tcp.send(packet_to_send.encode('utf-8'))
        data = client_socket_tcp.recv(4096)
        if tor_filter(data):
            if b'goren' in data:
                data1 = data.split(b'goren')[0]
            else:
                data1 = data
            port_for_udp = data1.decode('utf-8')
            handle_packets_from_server(port_for_udp, client_socket_tcp, None, data)
    except Exception as e:
        print(e)


def main():
    try:
        global executor, Alice_dh_public_key, Alice_rsa_public_key, Alice_dh_private_key, Alice_rsa_private_key
        client_socket_tcp = setting_client_socket_for_server_ipv6_or_ipv4()
        # making keys
        Alice_dh_private_key, Alice_dh_public_key = generate_dh_key_pair()
        Alice_rsa_private_key, Alice_rsa_public_key = generate_rsa_key_pair()
        # Alice signs her DH public key
        print('did keys')

        # waits_for_server_approve = client_socket_tcp.recv(1024)
        # print(waits_for_server_approve)
        # notifying the server about my mac
        select_random_port()
        notify_mac_to_server(client_socket_tcp)
        # print('1')
        # here getting the keys from the server
        # data = client_socket_tcp.recv(1024)
        # handling_keys_from_server(data)
        client_socket_udp = setting_client_socket_for_bots()
        # print('2')
        # calling the function who checks if the user typed something
        executor.submit(check_user_info, client_socket_udp, client_socket_tcp)
        # print('3')
        # a thread for handling the packets
        executor.submit(verify_packets_from_server, client_socket_tcp, client_socket_udp)
        while True:
            response_from_server = client_socket_tcp.recv(4096)
            # print(response_from_server)
            # add the packets to queue
            PACKETS_TO_HANDLE_QUEUE.append(response_from_server)
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
