""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import os
import re
import subprocess
import traceback

import requests

"""""""""""""""""""""""""""""""""THE PROTOCOL FOR THE PACKETS"""""""""""""""""""""""
"Tor;""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""''""""""""''"""
"new_client_to_server_main or _node: [mac of the new client that connected to you],[his ipv4 private], [his ipv4 public], [his port number]  client Node and main to server and server to client Nodes"
"port_of_server: [the port of the server in udp] server to everyone"
"start_first_stage_udp_hole_punching: [mac_of_the person who sent the packet],[mac of the person you want to do udp punch_hole] client Node and main to server "
"server_answer_for_first_stage_udp_hole_punching: if the server connect to the bot:[yes]?[(ipv4,port)]?[mac_of_other_bot] if not:[no] server to client Node and main "
"server_notify_bot_for_second_stage_of_udp_hole_punching: [mac of the person who wants to do udp punch]?[(ipv4,port)] server to client Node and main"
"giving_data_of_2: [mac_of_the person who sent the packet],[mac of the person you want to do udp punch_hole]"
"packet_on_the_way: [id]?[ttl]?[data] main client to client Node and client Node to Client Node"
"packet_on__the_way_back: [id]?[data] client Node to Client Node and client Node to main client "
"new_ipv6_server: [ipv6] new ipv6 server to all other ipv6 servers that he has"
"keys_for_security: [public_rsa] everyone to anyone "
"mac_of_the_person_who_sent_the_packet: [mac]"
"sigh_message: goren[signed_public_key]amit[iv] the part with the iv happens only when the clients send to the server"
"sigh_message_for_computer: [signed_public_key]amit[iv] server to clients"
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

import random
import time
from getmac import get_mac_address
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



DATA_FROM_UDP_HOLE_PUNCHING = None
Port_for_bot = None
Tor_opening_packets = 'Tor\r\n'
PORT_OF_UDP_SERVER = None
IPV4_OF_SERVER = '172.20.10.2'
IPV6_OF_SERVER = '2a06:c701:4550:a00:fad4:e6f3:25c7:8b68'
# dictionary will be like mac:(ipv4,port)
# data base with json like mac: and what server they are conncted to( his ipv6)
executor = ThreadPoolExecutor(thread_name_prefix='worker_thread_', max_workers=20)
PACKETS_TO_HANDLE_QUEUE = deque()
PACKETS_TO_HANDLE_QUEUE_FOR_BOTS = deque()
# dictionary of all the available bots i have mac: (cipher object)
Alice_dh_private_key, Alice_dh_public_key = None, None
Alice_rsa_private_key, Alice_rsa_public_key = None, None
Alice_signature = None
Shared_key_with_server = None  # (encryptor, decryptor, padder, unpadder)
My_id = None
# the key is the mac of the main client. mac: cipher object
CIPHERS_FOR_MAIN_CLIENTS = {}
Iv_with_server = None
Padder = padding.PKCS7(128).padder()
Unpadder = padding.PKCS7(128).unpadder()
# () of the sender: data of the rest of the packet
Packets_to_the_internet = {}
# dictionary that contains all of the data for each thread. () of the sender: data if none or not, how many times from the same bot
Thread_holder = {}
# id for packets
# ipv4_public, ipv4_private_static, port_tcp, port udp
DATA_OF_SERVERS = [('147.235.215.64', '10.0.0.11', 56789, 56779), ('188.120.157.25', '192.168.175.229', 56789, 56779),
                   ('2.52.14.104', '172.20.10.2', 56789, 56779), ('176.230.36.233', '192.168.1.149', 56789, 56779)]


# security
###################################################################################################
# def make_dh_keypair():
#     p = 877
#     q = 1531
#     g = 131
#     x = random.randint(1, q)
#     y = pow(g, x, p)
#     pub = DSA.construct((pow(g, y, p), p, q, g))
#     priv = DSA.construct((y, p, q, g))
#     return pub, priv


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
    # print(f' the plaint text before encrypting: {plaintext}')
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
        # print(f' my unpadder: {Shared_key_with_server[3].block_size}')
        plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
        return plaintext
    except:
        traceback.print_exc()


def encrypt_bot(plaintext, cipher):
    global Shared_key_with_server
    # (encryptor, decryptor, padder, unpadder)
    # print(f' the plaint text before encrypting: {plaintext}')
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext


def decrypt_bot(ciphertext, cipher):
    try:
        global Shared_key_with_server
        # (encryptor, decryptor, padder, unpadder)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the decrypted plaintext
        # print(f' my unpadder: {Shared_key_with_server[3].block_size}')
        plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
        return plaintext
    except Exception as e:
        traceback.print_exc()


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
            # print(f'the packet that does problomes: {payload}')
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


def udp_punch_hole(ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp, cipher, id_to_thread):
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
        while True:
            if Thread_holder[id_to_thread][2]:
                break
        message = f'{id_to_thread}do udp punch hole'.encode('utf-8')
        print(f'started to do udp punch hole and the key is: {id_to_thread} and the thread holder is: {Thread_holder}')
        while Thread_holder[id_to_thread][0] is None:
            client_socket_udp.sendto(message, (ipv4_for_punch_hole, port_for_punch_hole))
            Thread_holder[id_to_thread][1] += 1
            print(f'sent: {i} to {(ipv4_for_punch_hole, port_for_punch_hole)}')
            i += 1
        data_from_hole_punch = Thread_holder[id_to_thread][0]
        del Thread_holder[id_to_thread]
        verify_packets_from_bots(client_socket_udp, (ipv4_for_punch_hole, port_for_punch_hole), data_from_hole_punch, cipher)
        # PACKETS_TO_HANDLE_QUEUE.append(packet1)
    except Exception as e:
        traceback.print_exc()


def udp_punch_hole_that_i_started(ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp, cipher, packet_to_send, id_to_thread):
    """
    creating udp punch_hole
    :param ipv4_for_punch_hole:
    :param port_for_punch_hole:
    :param client_socket_udp:
    :return: True so he can know that he can send him the actual data
    """
    global DATA_FROM_UDP_HOLE_PUNCHING, PACKETS_TO_HANDLE_QUEUE, Thread_holder
    try:
        i = 1
        # data_from_hole_punch = None
        print(f'started to do udp punch hole i started and the key is: {id_to_thread} and the thread holder is: {Thread_holder}')
        while Thread_holder[id_to_thread][0] is None:
            #print('got in sending')
            client_socket_udp.sendto(packet_to_send, (ipv4_for_punch_hole, port_for_punch_hole))
            Thread_holder[id_to_thread][1] += 1
            print(f'sent: {i} to {(ipv4_for_punch_hole, port_for_punch_hole)}')
            i += 1
        #data_from_hole_punch = Thread_holder[id_to_thread]
        del Thread_holder[id_to_thread]
        # verify_packets_from_bots(client_socket_udp, (ipv4_for_punch_hole, port_for_punch_hole), data_from_hole_punch, cipher)
        # PACKETS_TO_HANDLE_QUEUE.append(packet1)
    except Exception as e:
        traceback.print_exc()


def handle_giving_data_of_2(mac_of_who_to_send):
    """
    giving the server my mac and who i want to do udp punch hole with
    :return:
    """
    global My_id
    packet_to_add = f'giving_data_of_2: {My_id},{mac_of_who_to_send}'
    return packet_to_add


def handle_packets_from_server(raw_packet, client_socket_tcp, client_socket_udp, payload):
    """
    handling the data in the packets
    :param payload:
    :param raw_packet:
    :param client_socket_tcp:
    :param client_socket_udp:
    :return:
    """
    global executor, PORT_OF_UDP_SERVER, Tor_opening_packets, Alice_dh_public_key, Shared_key_with_server, Alice_rsa_private_key, My_id, Alice_dh_private_key, Iv_with_server, Packets_to_the_internet, My_id, CIPHERS_FOR_MAIN_CLIENTS, Thread_holder
    reply_tor = Tor_opening_packets
    is_bytes = False
    have_the_id = None
    # print(f' raw packet: {payload}')
    try:
        if b'sigh_message_for_computer:' in payload:
            lines = payload.split(b'\r\n')
            is_bytes = True
            while b'' in lines:
                lines.remove(b'')
        else:
            lines = raw_packet.split('\r\n')
            while '' in lines:
                lines.remove('')
        # print(f' the data of the incoming packet : {lines}')
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
            if line_parts[0] == b'new_client_to_server_main:':
                # add this client mac to your data base
                mac_of_new_client = line_parts[1].decode('utf-8')
                CIPHERS_FOR_MAIN_CLIENTS[mac_of_new_client] = None
            # -------------

            # -------------
            if line_parts[0] == 'your_id:':
                # your id
                print(f'your id is: {line_parts[1]}')
                My_id = line_parts[1]
            # -------------

            # -------------
            if line_parts[0] == 'id_of_packet:':
                # your id
                have_the_id = line_parts[1]
                # print(f'got the id of packet {have_the_id}')
            # -------------

            # -------------
            if line_parts[0] == 'person_started_tor:':
                # your id
                person_started_tor = line_parts[1]
            # -------------

            # -------------
            # [yes],[(ipv4,port)] if not:[no] server to client Node and main
            if line_parts[0] == 'server_answer_for_first_stage_udp_hole_punching:':
                l_parts = line_parts[1].split('?')
                if l_parts[0] == 'yes':
                    # print(l_parts[1])
                    another = tuple(l_parts[1][1:-1].split(','))
                    # print(another)
                    ipv4_for_punch_hole = another[0]
                    port_for_punch_hole = int(another[1])
                    packet_to_send = Packets_to_the_internet[have_the_id][-1][0]
                    packet_to_send = f'{have_the_id}to_know_which_thread'.encode('utf-8') + packet_to_send
                    cipher = None
                    Thread_holder[have_the_id] = [None, 0]
                    executor.submit(udp_punch_hole_that_i_started, ipv4_for_punch_hole, port_for_punch_hole,
                                    client_socket_udp, cipher, packet_to_send, have_the_id)
            # -------------

            # -------------
            # [mac]?[(ipv4,port)] server to client Node and main
            if line_parts[0] == 'server_notify_bot_for_second_stage_of_udp_hole_punching:':
                # send to the server something so he will see your public ip
                l_parts = line_parts[1].split('?')
                mac_of_other_client = l_parts[0]
                reply_tor += f'id_of_packet: {have_the_id}\r\n'
                reply_tor += handle_giving_data_of_2(mac_of_other_client)
                ciphertext = encrypt_server(reply_tor.encode('utf-8'))
                client_socket_udp.sendto(ciphertext, (IPV4_OF_SERVER, PORT_OF_UDP_SERVER))
                another = tuple(l_parts[1][1:-1].split(','))
                # print(another)
                ipv4_for_punch_hole = another[0]
                port_for_punch_hole = int(another[1])
                if have_the_id is None:
                    key_to_thread = mac_of_other_client
                    Thread_holder[mac_of_other_client] = [None, 0, False]
                    cipher = CIPHERS_FOR_MAIN_CLIENTS[mac_of_other_client]
                else:
                    Thread_holder[have_the_id] = [None, 0, False]
                    cipher = CIPHERS_FOR_MAIN_CLIENTS[person_started_tor]
                    key_to_thread = have_the_id
                    have_the_id = None
                # print('did server_notify_bot_for_second_stage_of_udp_hole_punching')
                executor.submit(udp_punch_hole, ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp, cipher, key_to_thread)
                # put in your dictionary the mac as key and his ipv4 and port
            # -------------

            # -------------
            if line_parts[0] == 'start_punch_hole:':
                Thread_holder[line_parts[1]][2] = True
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
                reply_tor += f"mac_of_the_person_who_sent_the_packet: {My_id}\r\nsigh_message: goren"
                # print(f'the packet i am sending with sign: {reply_tor}')
                Iv_with_server = os.urandom(16)  # 16 bytes IV for AES
                client_socket_tcp.send(reply_tor.encode('utf-8') + signed_dh + 'amit'.encode('utf-8') + Iv_with_server)
            # -------------

            # -------------
            # [public_rsa],[public_dh]
            if line_parts[0] == 'sigh_message:':
                l_parts = payload.split(b'goren')
                bob_signature = l_parts[1]
                # print(f' length of the cyphtext: {len(bob_signature)}')
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
                # print(f'alic param p and g: {Alice_dh_private_key.parameters().parameter_numbers().p},{Alice_dh_private_key.parameters().parameter_numbers().g} and bob params p and g: {bob_dh_public.public_numbers().parameter_numbers.p},{bob_dh_public.public_numbers().parameter_numbers.g}')
                Shared_key_with_server = Alice_dh_private_key.exchange(bob_dh_public)
                # too long
                Shared_key_with_server = Shared_key_with_server[:32]
                # print(f'the len of shared key: {len(Shared_key_with_server)}')
                cipher = Cipher(algorithms.AES(Shared_key_with_server), modes.CBC(Iv_with_server),
                                backend=default_backend())

                Shared_key_with_server = cipher
                print(f' the shared from server: {Shared_key_with_server}')
            # -------------

            # -------------
            # [public_rsa],[public_dh]
            if line_parts[0] == b'sigh_message_for_computer: ':
                bob_public_dh_and_iv = line_parts[1].split(b'amit')
                bob_public_dh = bob_public_dh_and_iv[0]
                bob_iv = bob_public_dh_and_iv[1]
                shared_secret = Alice_dh_private_key.exchange(
                    serialization.load_pem_public_key(bob_public_dh, backend=default_backend()))[:32]
                cipher = Cipher(algorithms.AES(shared_secret),
                                modes.CBC(bob_iv),
                                backend=default_backend())
                CIPHERS_FOR_MAIN_CLIENTS[mac_of_new_client] = cipher
                print(f'new main_client connected to server: {CIPHERS_FOR_MAIN_CLIENTS}')
    except Exception as e:
        traceback.print_exc()


def sending_the_packet_back():
    """
    sending the packet back to where i got it from
    :return:
    """
    pass


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
        time.sleep(25)


def move_the_packet_forward():
    """
    updating the data in the packet and sending to another client
    :return:
    """
    pass


def create_the_packet_and_sending(data_to_internet):
    """
    creating the packet like it came from me and sending it to google
    :return:
    """
    data_from_internet = b'got the data from the internet'
    print('sent data to internet')
    return data_from_internet


def making_sure_the_thread_stopped(ciphertext, client_socket_udp, key_to_thread):
    """

    :param ciphertext:
    :param client_udp:
    :param address:
    :return:
    """
    global Thread_holder, IPV4_OF_SERVER, PORT_OF_UDP_SERVER
    while True:
        # checking if finished the last thread of the same packet
        if key_to_thread not in Thread_holder:
            print('last thread finished')
            client_socket_udp.sendto(ciphertext, (IPV4_OF_SERVER, PORT_OF_UDP_SERVER))
            return


def handle_packets_from_bots(raw_packet, client_socket_udp, punch_hole_address, buda_end, payload):
    """
    handling packets from the udp hole punch
    :return:
    """
    global My_id, IPV4_OF_SERVER, PORT_OF_UDP_SERVER, Packets_to_the_internet, Tor_opening_packets, Thread_holder, executor
    try:
        replay_tor = Tor_opening_packets
        lines = raw_packet.split('\r\n')
        while '' in lines:
            lines.remove('')
        # print(f' got packet on the way from punch hole and the data: {lines}')
        for line in lines:
            line_parts = line.split()

            # -------------

            # -------------
            if line_parts[0] == 'id_of_packet:':
                # your id
                id_for_packet = line_parts[1]
            # -------------
            # [id]?[ttl]?[data]
            if line_parts[0] == 'packet_on_the_way:':
                # put here in a the dictionary key id: punch_hole_address so i know where to send it back
                if b'buda_end' in payload:
                    data_to_send = payload.split(b'buda_end')[1]
                    who_started_the_packet = raw_packet.split('first_person')[1]
                    answer_from_google = create_the_packet_and_sending(data_to_send)
                    ciphertext = encrypt_bot(answer_from_google, CIPHERS_FOR_MAIN_CLIENTS[who_started_the_packet])
                    answer_from_google = Tor_opening_packets.encode('utf-8') + f'id_of_packet: {id_for_packet}\r\n'.encode('utf-8') + 'packet_on__the_way_back: answer_from_google'.encode('utf-8') + ciphertext
                    # the punchole is still alive so i can send the packet direct to the person
                    client_socket_udp.sendto(answer_from_google, punch_hole_address)
                elif b'finished' in payload:
                    data_to_send = payload.split(b'finished')
                    two_computers = data_to_send[0].split(b'start')[1].decode('utf-8')
                    two_computers = two_computers.split(',')
                    who_started_the_packet = two_computers[0]
                    who_to_send = two_computers[1]
                    # the part of the packet i am about to move forward
                    if id_for_packet in Packets_to_the_internet:
                        Packets_to_the_internet[id_for_packet].append((data_to_send[1], who_started_the_packet, punch_hole_address))
                    else:
                        Packets_to_the_internet[id_for_packet] = [(data_to_send[1], who_started_the_packet, punch_hole_address)]
                    replay_tor += f'person_started_tor: {who_started_the_packet}\r\nid_of_packet: {id_for_packet}\r\nstart_first_stage_udp_hole_punching: {My_id},{who_to_send}'
                    # print(f'what i am sending: {replay_tor}')

                    ciphertext = encrypt_server(replay_tor.encode('utf-8'))
                    executor.submit(making_sure_the_thread_stopped, ciphertext, client_socket_udp, id_for_packet)
                    # print(f' the packet i am sending to the server for moving the packet: {ciphertext}')
                    # here sending the packet to the internet
                else:
                    # updating the data in the packet and sending to another bot
                    move_the_packet_forward()
            # -------------

            # -------------
            # [id]?[data]
            if line_parts[0] == 'packet_on__the_way_back:':
                data_from_google = payload.split(b'answer_from_google')[1]
                mac_of_main_client = Packets_to_the_internet[id_for_packet][-1][1]
                #print(Packets_to_the_internet)
                cipher = CIPHERS_FOR_MAIN_CLIENTS[mac_of_main_client]
                ciphertext = encrypt_bot(data_from_google, cipher)
                answer_from_google = Tor_opening_packets.encode('utf-8') + f'id_of_packet: {id_for_packet}\r\n'.encode('utf-8') + 'packet_on__the_way_back: answer_from_google'.encode('utf-8') + ciphertext
                # the punchole is still alive so i can send the packet direct to the person
                client_socket_udp.sendto(answer_from_google, Packets_to_the_internet[id_for_packet][-1][2])
                del Packets_to_the_internet[id_for_packet][-1]
    except Exception as e:
        traceback.print_exc()


def verify_packets_from_bots(client_socket_udp, punch_hole_address, payload, cipher):
    """
    
    :param client_socket_udp: 
    :param punch_hole_address: 
    :param data_from_punch_hole: 
    :param cipher: 
    :return: 
    """
    try:
        if b'answer_from_google' in payload:
            pass
        elif b'do udp punch hole' in payload:
            return
        else:
            payload = decrypt_bot(payload, cipher)
        buda_end = False
        # print(f'did decrypting for bot{data_from_punch_hole}')
        if tor_filter(payload):
            # print('passed verify from bots')
            if b'buda_end' in payload:
                data1 = payload.split(b'buda_end')[0]
                buda_end = True
            elif b'finished' in payload:
                data1 = payload.split(b'finished')[0]
            elif b'answer_from_google' in payload:
                data1 = payload.split(b'answer_from_google')[0]
            else:
                data1 = payload
            handle_packets_from_bots(data1.decode('utf-8'), client_socket_udp, punch_hole_address, buda_end,
                                     payload)
    except:
        traceback.print_exc()


def checking_if_got_packets_from_bots(client_socket_udp):
    """
    verifying the packets from bots
    :return:
    """
    try:
        global DATA_FROM_UDP_HOLE_PUNCHING, PACKETS_TO_HANDLE_QUEUE_FOR_BOTS, Thread_holder
        while True:
            if len(PACKETS_TO_HANDLE_QUEUE_FOR_BOTS) < 1:
                continue
            payload_address = PACKETS_TO_HANDLE_QUEUE_FOR_BOTS.popleft()
            print(f'got to the paoload : {payload_address}')
            payload = payload_address[0]
            address = payload_address[1]
            if b'to_know_which_thread' in payload:
                id_payload = payload.split(b'to_know_which_thread')
                if id_payload[0].decode('utf-8') in Thread_holder:
                    if Thread_holder[id_payload[0].decode('utf-8')][1] > 0:
                        Thread_holder[id_payload[0].decode('utf-8')][0] = id_payload[1]
                #print(f'closed the thread and his key was: {id_payload[0]}')
            elif b'do udp punch hole' in payload:
                id_payload = payload.split(b'do')
                if id_payload[0].decode('utf-8') in Thread_holder:
                    #print('has the key in ')
                    if Thread_holder[id_payload[0].decode('utf-8')][1] > 0:
                        Thread_holder[id_payload[0].decode('utf-8')][0] = id_payload[1]
            else:
                verify_packets_from_bots(client_socket_udp, address, payload, None)
    except:
        traceback.print_exc()


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
        traceback.print_exc()
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
        traceback.print_exc()


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
        traceback.print_exc()


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
                traceback.print_exc()
    # ----------------

    # If all failed
    return "[Your public IP (our system couldn't find it)]"


def notify_mac_to_server(client_socket_tcp):
    global Tor_opening_packets, Port_for_bot, My_id
    try:
        packet_to_send = Tor_opening_packets
        My_id = '876'
        # packet_to_send += f'new_client_to_server: {mac_address},{get_public_ip()},{Port_for_bot}\r\n'
        packet_to_send += f'new_client_to_server_node: {My_id},{get_ipv4_address_private()},{get_public_ip()},{Port_for_bot}\r\n'
        print(f'the packet i am sending before first connected: {packet_to_send}')
        packet_to_send = sending_the_keys_for_security(packet_to_send)
        # print(f" how keys look : {packet_to_send.encode('utf-8')}")
        client_socket_tcp.send(packet_to_send.encode('utf-8'))
        # print('sent to server')
        data = client_socket_tcp.recv(4096)
        # print('waiting for answer')
        if tor_filter(data):
            if b'goren' in data:
                data1 = data.split(b'goren')[0]
            else:
                data1 = data
            port_for_udp = data1.decode('utf-8')
            handle_packets_from_server(port_for_udp, client_socket_tcp, None, data)
    except Exception as e:
        traceback.print_exc()


def listening_to_udp(client_socket_udp):
    """

    :param client_socket_udp:
    :return:
    """
    global PACKETS_TO_HANDLE_QUEUE_FOR_BOTS
    try:
        while True:
            try:
                response_from_bots, address = client_socket_udp.recvfrom(16384)
            except socket_timeout:
                continue
            #print(f'got anything from udp: {response_from_bots}')
            PACKETS_TO_HANDLE_QUEUE_FOR_BOTS.append((response_from_bots, address))
    except:
        traceback.print_exc()


def main():
    try:
        global executor, Alice_dh_public_key, Alice_rsa_public_key, Alice_dh_private_key, Alice_rsa_private_key, PACKETS_TO_HANDLE_QUEUE_FOR_BOTS
        client_socket_tcp = setting_client_socket_for_server_ipv6_or_ipv4()
        # making keys
        Alice_dh_private_key, Alice_dh_public_key = generate_dh_key_pair()
        Alice_rsa_private_key, Alice_rsa_public_key = generate_rsa_key_pair()
        print(f'alice rsa public key: {type(serialize_public_key(Alice_rsa_public_key))}')
        # Alice signs her DH public key
        print('did keys')
        # waits_for_server_approve = client_socket_tcp.recv(1024)
        # notifying the server about my mac
        select_random_port()
        # print('selected port')
        notify_mac_to_server(client_socket_tcp)
        # print('notified to server')
        client_socket_udp = setting_client_socket_for_bots()
        # a thread for listening to udp packets
        executor.submit(listening_to_udp, client_socket_udp)
        # a thread for handeling packets from bots
        executor.submit(checking_if_got_packets_from_bots, client_socket_udp)
        # a thread for handling the packets
        executor.submit(verify_packets_from_server, client_socket_tcp, client_socket_udp)
        while True:
            response_from_server = client_socket_tcp.recv(16384)
            PACKETS_TO_HANDLE_QUEUE.append(response_from_server)
    except Exception as e:
        traceback.print_exc()


if __name__ == "__main__":
    main()
