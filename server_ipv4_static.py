""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import base64
import random

import requests

"""""""""""""""""""""""""""""""""THE PROTOCOL FOR THE PACKETS"""""""""""""""""""""""
"Tor;""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""''""""""""''"""
"new_client_to_server: [mac of the new client that connected to you],[his ipv4 private], [his ipv4 public], [his port number]  client Node and main to server and server to client Nodes"
"port_of_server: [the port of the server in udp] server to everyone"
"start_first_stage_udp_hole_punching: [mac_of_the person who sent the packet],[mac of the person you want to do udp punch_hole] client Node and main to server "
"server_answer_for_first_stage_udp_hole_punching: if the server connect to the bot:[yes]?[(ipv4,port)]?[mac_of_other_bot] if not:[no] server to client Node and main "
"server_notify_bot_for_second_stage_of_udp_hole_punching: [mac of the person who wants to do udp punch]?[(ipv4,port)] server to client Node and main"
"giving_data_of_2: [mac_of_the person who sent the packet],[mac of the person you want to do udp punch_hole]"
"packet_on_the_way: [id]?[ttl]?[data] main client to client Node and client Node to Client Node"
"packet_on__the_way_back: [id]?[data] client Node to Client Node and client Node to main client "
"new_ipv6_server: [ipv6] new ipv6 server to all other ipv6 servers that he has"
"keys_for_security: [public_rsa] everyone to anyone "
"sigh_message: goren[signed_public_key]amit[iv] the part with the iv happens only when the clients send to the server"
"sigh_message_for_computer: [signed_public_key]amit[iv] server to clients"
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

import traceback
import subprocess
import re
import time
from socket import socket, AF_INET6, SOCK_DGRAM, SOCK_STREAM, AF_INET, gethostbyname, gethostname, \
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
import os

Tor_opening_packets = 'Tor\r\n'
# creating json file with my information there. this lines will be only in my code because
# when first they install the exe they will need to know where to send first
# mac: tuple(str_ipv4, int_port), client_socket, [public_rsa, public_dh, shared_key_with_him:(encryptor, decryptor, padder, unpadder), bob iv]
# the key will be the id
MY_DATA_FOR_CLIENTS_NODES = {}
# the key will be the mac
MY_DATA_FOR_MAIN_CLIENTS = {}
# put here the port
PORT_FOR_UDP = 56779
executor = ThreadPoolExecutor(thread_name_prefix='worker_thread_', max_workers=80)
Alice_dh_private_key, Alice_dh_public_key = None, None
Alice_rsa_private_key, Alice_rsa_public_key = None, None
Alice_signature = None
Padder = padding.PKCS7(128).padder()
Unpadder = padding.PKCS7(128).unpadder()
Id_for_clients = 1
# list that will contain queus for each client
LIST_OF_QUEUES_FOR_EACH_CLIENT = {}


# # Use forward slashes or a raw string for the file path
# file_path = 'C:/Networks/last_project/server.json'
# MY_DATA_FOR_BOTS = {'Mac': 'D0-37-45-92-6C-91', 'Ipv4': '10.0.0.11', 'Port': 56779}
# with open(file_path, 'w') as json_file:
#     json.dump(MY_DATA_FOR_BOTS, json_file)
# ######################################################################
# PACKETS_TO_HANDLE_QUEUE = deque()

# security
###################################################################################################

def generate_dh_key_pair():
    """
    generating dh key pair with statics params 1024 bits
    :return:
    """
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    g = 2

    params_numbers = dh.DHParameterNumbers(p, g)
    parameters = params_numbers.parameters(default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    return private_key, public_key


def serialize_public_key(public_key):
    """
    transferring the key to a form that i can send in packet
    :param public_key:
    :return:
    """
    serialized_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return serialized_key


def deserialize_public_key(serialized_key):
    """
    transferring the key to his object
    :param serialized_key:
    :return:
    """
    serialized_key = serialized_key.encode('utf-8')
    public_key = serialization.load_pem_public_key(serialized_key, backend=default_backend())
    return public_key


def generate_rsa_key_pair():
    """
    generating rsa key pair
    :return:
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(message, public_key):
    """
    encrypting the packet with public rsa so only the person who has the private rsa can see my public dh
    :param message:
    :param public_key:
    :return:
    """
    message = serialize_public_key(message)
    alice_signature = public_key.encrypt(
        message,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # alice_signature = alice_signature.decode('utf-8')
    # print(f' before turning to string: {alice_signature} and len{len(alice_signature)}')
    # alice_signature1 = str(alice_signature)
    # # alice_signature1 = alice_signature1[2:-1]
    # # print(alice_signature1)
    # # alice_signature1 = alice_signature1.encode('utf-8')
    # print(f' after turning to string: {alice_signature1}')
    # print(f'len of cypghtext after turning: {len(alice_signature1)}')
    return alice_signature


def encrypt(plaintext, mac):
    """
    encrypting the packet
    :param plaintext:
    :param mac:
    :return:
    """
    global MY_DATA_FOR_CLIENTS_NODES, MY_DATA_FOR_MAIN_CLIENTS
    # mac: tuple(str_ipv4, int_port), client_socket, [public_rsa, public_dh, shared_key_with_him:(encryptor, decryptor, padder, unpadder)]
    # (encryptor, decryptor, padder, unpadder)
    if mac in MY_DATA_FOR_CLIENTS_NODES:
        print('encrypted to node')
        cipher = MY_DATA_FOR_CLIENTS_NODES[mac][2][2]
    else:
        cipher = MY_DATA_FOR_MAIN_CLIENTS[mac][2][2]
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    # print(f' padder block size: {MY_DATA_FOR_BOTS[mac][2][2][2].block_size}')
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext


def decrypt(ciphertext, mac):
    """
    decrypting the packet
    :param ciphertext:
    :param mac:
    :return:
    """
    global MY_DATA_FOR_CLIENTS_NODES, MY_DATA_FOR_MAIN_CLIENTS
    # mac: tuple(str_ipv4, int_port), client_socket, [public_rsa, public_dh, shared_key_with_him:(encryptor, decryptor, padder, unpadder)]
    # (encryptor, decryptor, padder, unpadder)
    if mac in MY_DATA_FOR_CLIENTS_NODES:
        cipher = MY_DATA_FOR_CLIENTS_NODES[mac][2][2]
    elif mac in MY_DATA_FOR_MAIN_CLIENTS:
        cipher = MY_DATA_FOR_MAIN_CLIENTS[mac][2][2]
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    # (encryptor, decryptor, padder, unpadder)
    decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted plaintext
    # print(f' the cipher text before unpadding: {decrypted_padded_plaintext}')
    plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
    return plaintext


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
    # print(f' bob rsa public: {public_rsa_of_bob}')
    signed_public_key = sign_message(Alice_dh_public_key, public_rsa_of_bob)
    # print(signed_public_key)
    # signed_public_key = signed_public_key.decode('utf-8')
    packet_to_send += f"keys_for_security: {rsa_public_to_send}\r\nsigh_message: goren"
    return packet_to_send, signed_public_key


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


def are_in_same_network(ip1, ip2, subnet_mask):
    """
    :param ip1:
    :param ip2:
    :param subnet_mask:
    :return:
    """
    ip1_parts = list(map(int, ip1.split('.')))
    ip2_parts = list(map(int, ip2.split('.')))
    # print(f' the subnet mask: {subnet_mask}')
    subnet_mask_parts = list(map(int, subnet_mask.split('.')))

    # Perform bitwise AND operation for each octet
    network1 = [ip & mask for ip, mask in zip(ip1_parts, subnet_mask_parts)]
    network2 = [ip & mask for ip, mask in zip(ip2_parts, subnet_mask_parts)]

    # Check if the networks are the same
    return network1 == network2


def server_notify_bot_for_second_stage_of_udp_hole_punching(mac_of_the_1, ip, port, mac_of_the_2):
    global MY_DATA_FOR_MAIN_CLIENTS, MY_DATA_FOR_CLIENTS_NODES
    same_network = False
    try:
        packet_to_add = None
        if mac_of_the_1 in MY_DATA_FOR_MAIN_CLIENTS:
            data_for_person = MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_1][0]
            # if the in the same internet
            if (data_for_person[-1] == MY_DATA_FOR_CLIENTS_NODES[mac_of_the_2][0][-1]) and (
                    are_in_same_network(data_for_person[0], MY_DATA_FOR_CLIENTS_NODES[mac_of_the_2][0][0],
                                        data_for_person[-1])):  # !!!!!!!!!
                same_network = True
                packet_to_add = f'same_network: {mac_of_the_1},{data_for_person[0]},{data_for_person[2]}'
                # packet_to_add = f'server_notify_bot_for_second_stage_of_udp_hole_punching: {mac_of_the_1}?({data_for_person[0]},{data_for_person[2]})'
            # if not
            else:
                print(' not in the same network')
                packet_to_add = f'server_notify_bot_for_second_stage_of_udp_hole_punching: {mac_of_the_1}?({ip},{port})'
        elif mac_of_the_1 in MY_DATA_FOR_CLIENTS_NODES:
            data_for_person = MY_DATA_FOR_CLIENTS_NODES[mac_of_the_1][0]
            # if the in the same internet
            if (data_for_person[-1] == MY_DATA_FOR_CLIENTS_NODES[mac_of_the_2][0][-1]) and (
                    are_in_same_network(data_for_person[0], MY_DATA_FOR_CLIENTS_NODES[mac_of_the_2][0][0],
                                        data_for_person[-1])):  # !!!!!!!!!
                same_network = True
                packet_to_add = f'same_network: {mac_of_the_1},{data_for_person[0]},{data_for_person[2]}'
                # packet_to_add = f'server_notify_bot_for_second_stage_of_udp_hole_punching: {mac_of_the_1}?({data_for_person[0]},{data_for_person[2]})'
            # if not
            else:
                print(' not in the same network')
                packet_to_add = f'server_notify_bot_for_second_stage_of_udp_hole_punching: {mac_of_the_1}?({ip},{port})'
        return packet_to_add, same_network
    except Exception as e:
        traceback.print_exc()


def handle_first_stage_udp_hole_punching(mac_of_the_person2, ip, port):
    """

    :param mac_of_1: the one that started punch hole
    :param mac_of_the_person2:
    :param ip:
    :param port:
    :return:
    """
    global MY_DATA_FOR_MAIN_CLIENTS, MY_DATA_FOR_CLIENTS_NODES
    try:
        # if same internet
        if mac_of_the_person2 in MY_DATA_FOR_MAIN_CLIENTS:
            data_for_person = MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_person2][0]
            # if are_in_same_network(data_for_person[0], ip, str(get_subnet_mask())):
            #     print('in the same network')
            #     packet_to_add = f'server_answer_for_first_stage_udp_hole_punching: yes?({data_for_person[0]},{data_for_person[2]})?{mac_of_the_person2}'
            # # if not
            # else:
            #     print('not in the same network')
            packet_to_add = f'server_answer_for_first_stage_udp_hole_punching: yes?({ip},{port})?{mac_of_the_person2}'
        elif mac_of_the_person2 in MY_DATA_FOR_CLIENTS_NODES:
            data_for_person = MY_DATA_FOR_CLIENTS_NODES[mac_of_the_person2][0]
            # if are_in_same_network(data_for_person[0], ip, str(get_subnet_mask())):
            #     print('in the same network')
            #     packet_to_add = f'server_answer_for_first_stage_udp_hole_punching: yes?({data_for_person[0]},{data_for_person[2]})?{mac_of_the_person2}'
            # # if not
            # else:
            #     print('not in the same network')
            packet_to_add = f'server_answer_for_first_stage_udp_hole_punching: yes?({ip},{port})?{mac_of_the_person2}'
        return packet_to_add
    except Exception as e:
        traceback.print_exc()


def notify_all_main_clients(id1):
    global MY_DATA_FOR_MAIN_CLIENTS, Tor_opening_packets
    message = Tor_opening_packets.encode('utf-8') + f'node_disconnect: {id1}'.encode('utf-8')
    for key, value in MY_DATA_FOR_MAIN_CLIENTS.items():
        client_socket = value[1]
        ciphertext = encrypt(message, key)
        client_socket.send(ciphertext)


def notify_all_nodes(mac):
    global MY_DATA_FOR_CLIENTS_NODES, Tor_opening_packets
    message = Tor_opening_packets.encode('utf-8') + f'main_disconnect: {mac}'.encode('utf-8')
    for key, value in MY_DATA_FOR_CLIENTS_NODES.items():
        client_socket = value[1]
        ciphertext = encrypt(message, key)
        client_socket.send(ciphertext)


def notify_a_new_client_for_other_clients(public_dh_of_new, bob_iv, mac_of_the_new_client, client_socket_of_new_client):
    """
    notifying all other clients about the new client
    :param public_dh_of_new:
    :param client_socket_of_new_client:
    :param mac_of_the_new_client:
    :param bob_iv:
    :return:
    """
    global MY_DATA_FOR_MAIN_CLIENTS, MY_DATA_FOR_CLIENTS_NODES, Tor_opening_packets
    # mac: tuple(str_ipv4, int_port), client_socket, [public_rsa, public_dh, cipher, bob iv]
    add_sign_to_new = b''
    message = Tor_opening_packets
    message += f'new_client_to_server_main: {mac_of_the_new_client}\r\nsigh_message_for_computer: goren'
    add_sign = message.encode('utf-8') + serialize_public_key(public_dh_of_new) + 'amit'.encode(
        'utf-8') + bob_iv
    message_to_all = ''
    if mac_of_the_new_client in MY_DATA_FOR_MAIN_CLIENTS:
        for key, value in MY_DATA_FOR_CLIENTS_NODES.items():
            # first sending to the other client
            client_socket = value[1]
            cipher_text = encrypt(add_sign, key)
            client_socket.send(cipher_text)
            # then sending to the new client
            # message = Tor_opening_packets
            message_to_all = f'new_client_to_server_node: {key}\r\nsigh_message_for_computer: goren'
            add_sign_to_new += message_to_all.encode('utf-8') + serialize_public_key(value[2][1]) + 'amit'.encode(
                'utf-8') + bob_iv + '\r\n'.encode('utf-8')
        if add_sign_to_new != b'':
            add_sign_to_new = Tor_opening_packets.encode('utf-8') + add_sign_to_new
            cipher_text = encrypt(add_sign_to_new, mac_of_the_new_client)
            print(f' notifying new client: {cipher_text}')
            client_socket_of_new_client.send(cipher_text)
    elif mac_of_the_new_client in MY_DATA_FOR_CLIENTS_NODES:
        message = Tor_opening_packets
        message += f'new_client_to_server_node: {mac_of_the_new_client}\r\nsigh_message_for_computer: goren'
        add_sign = message.encode('utf-8') + serialize_public_key(public_dh_of_new) + 'amit'.encode(
            'utf-8') + bob_iv
        for key, value in MY_DATA_FOR_MAIN_CLIENTS.items():
            # first sending to the other client
            client_socket = value[1]
            cipher_text = encrypt(add_sign, key)
            client_socket.send(cipher_text)
            # then sending to the new client
            # message = Tor_opening_packets
            message_to_all = f'new_client_to_server_main: {key}\r\nsigh_message_for_computer: goren'
            add_sign_to_new += message_to_all.encode('utf-8') + serialize_public_key(value[2][1]) + 'amit'.encode(
                'utf-8') + bob_iv + '\r\n'.encode('utf-8')
        if add_sign_to_new != b'':
            add_sign_to_new = Tor_opening_packets.encode('utf-8') + add_sign_to_new
            print(f' notifying new client: {add_sign_to_new}')
            cipher_text = encrypt(add_sign_to_new, mac_of_the_new_client)
            client_socket_of_new_client.send(cipher_text)


def handle_packets_from_computers(raw_packet, client_socket, client_address, server_socket_udp, payload, mac):
    """
    handeling all the packets coming to the server
    :param raw_packet:
    :param client_socket:
    :param client_address:
    :param server_socket_udp:
    :return:
    """
    global executor, Tor_opening_packets, PORT_FOR_UDP, Alice_rsa_private_key, Alice_dh_private_key, MY_DATA_FOR_CLIENTS_NODES, MY_DATA_FOR_MAIN_CLIENTS, Id_for_clients, LIST_OF_QUEUES_FOR_EACH_CLIENT
    replay_tor = Tor_opening_packets
    id_to_pass = None
    mac_of_the_person_who_sent_the_packet = None
    try:
        lines = raw_packet.split('\r\n')
        while '' in lines:
            lines.remove('')
        print(f' the data of the incoming packet : {lines}')
        for line in lines:
            line_parts = line.split()
            # new_client_to_server: [mac of the new client that connected to you] client Node and main to server and server to client Nodes
            # -------------
            if line_parts[0] == 'new_client_to_server_main:':
                l_parts = line_parts[1].split(',')
                mac_of_bot = l_parts[0]
                # (private ip, public ip, port number private), client socket
                print('new main client')
                MY_DATA_FOR_MAIN_CLIENTS[l_parts[0]] = [(l_parts[1], l_parts[2], l_parts[3], str(client_address[1]), l_parts[4]), client_socket]
                # add this client mac in line_parts[1] to your data base and with his address
                # sending the client the port for udp
                replay_tor += f'port_of_server: {PORT_FOR_UDP}\r\n'
                # print(f'replay_tor)
                replay_tor = replay_tor.encode('utf-8')
                # client_socket.send(replay_tor.encode('utf-8'))
                pass
            # -------------
            if line_parts[0] == 'new_client_to_server_node:':
                print('new client node')
                l_parts = line_parts[1].split(',')
                # (private ip, public ip, port number private), client socket
                replay_tor += f'your_id: {Id_for_clients}\r\n'
                Id_for_clients = str(Id_for_clients)
                mac_of_bot = Id_for_clients
                MY_DATA_FOR_CLIENTS_NODES[Id_for_clients] = [(l_parts[1], l_parts[2], l_parts[3], str(client_address[1]), l_parts[4]),
                                                             client_socket]
                Id_for_clients = int(Id_for_clients)
                Id_for_clients += 1
                # add this client mac in line_parts[1] to your data base and with his address
                # sending the client the port for udp
                #
                replay_tor += f'port_of_server: {PORT_FOR_UDP}\r\n'
                # print(f'replay_tor)
                replay_tor = replay_tor.encode('utf-8')
                # client_socket.send(replay_tor.encode('utf-8'))
                pass
            # -------------

            # -------------
            if line_parts[0] == 'id_of_packet:':
                print('got in id of packet')
                id_to_pass = line_parts[1]
            # -------------

            # -------------
            if line_parts[0] == 'person_started_tor:':
                print('got in id of packet')
                person_started_tor = line_parts[1]
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
                if id_to_pass is not None:
                    print(f'id to pass is not None: {id_to_pass}')
                    replay_tor2 += f'person_started_tor: {person_started_tor}\r\nid_of_packet: {id_to_pass}\r\n'
                replay_tor_and_interntet = server_notify_bot_for_second_stage_of_udp_hole_punching(l_parts[0],
                                                                                                   public_ip_of_1,
                                                                                                   public_port_of_1,
                                                                                                   l_parts[1])
                # replay_tor2 += '\r\nsigh_message_for_computer: goren'
                replay_tor2 += replay_tor_and_interntet[0]
                if replay_tor_and_interntet[1]:
                    if id_to_pass is None:
                        replay_tor4 = Tor_opening_packets + f'same_network: {MY_DATA_FOR_CLIENTS_NODES[l_parts[1]][0][0]},{MY_DATA_FOR_CLIENTS_NODES[l_parts[1]][0][2]}'
                        ciphertext = encrypt(replay_tor4.encode('utf-8'), l_parts[0])
                        MY_DATA_FOR_MAIN_CLIENTS[l_parts[0]][1].send(ciphertext)
                    else:
                        replay_tor4 = Tor_opening_packets + f'same_network: {id_to_pass},{MY_DATA_FOR_CLIENTS_NODES[l_parts[1]][0][0]},{MY_DATA_FOR_CLIENTS_NODES[l_parts[1]][0][2]}'
                        ciphertext = encrypt(replay_tor4.encode('utf-8'), l_parts[0])
                        MY_DATA_FOR_CLIENTS_NODES[l_parts[0]][1].send(ciphertext)

                else:
                    if l_parts[1] in MY_DATA_FOR_MAIN_CLIENTS:

                        print(f' what i am sending to the second bot in punch hole: {replay_tor2}')
                        # add_sign = replay_tor2.encode('utf-8') + serialize_public_key(
                        #     MY_DATA_FOR_BOTS[l_parts[0]][2][1]) + 'amit'.encode('utf-8') + MY_DATA_FOR_BOTS[l_parts[0]][2][
                        #                3]
                        ciphertext = encrypt(replay_tor2.encode('utf-8'), l_parts[1])
                        MY_DATA_FOR_MAIN_CLIENTS[l_parts[1]][1].send(ciphertext)
                    elif l_parts[1] in MY_DATA_FOR_CLIENTS_NODES:
                        print(f' what i am sending to the second bot in punch hole: {replay_tor2}')
                        # add_sign = replay_tor2.encode('utf-8') + serialize_public_key(
                        #     MY_DATA_FOR_BOTS[l_parts[0]][2][1]) + 'amit'.encode('utf-8') + MY_DATA_FOR_BOTS[l_parts[0]][2][
                        #                3]
                        ciphertext = encrypt(replay_tor2.encode('utf-8'), l_parts[1])
                        MY_DATA_FOR_CLIENTS_NODES[l_parts[1]][1].send(ciphertext)
                    else:
                        replay_tor += f'server_answer_for_first_stage_udp_hole_punching: no'
                        if l_parts[0] in MY_DATA_FOR_MAIN_CLIENTS:
                            where_to_send = MY_DATA_FOR_MAIN_CLIENTS[l_parts[0]][1]
                        elif l_parts[0] in MY_DATA_FOR_CLIENTS_NODES:
                            where_to_send = MY_DATA_FOR_CLIENTS_NODES[l_parts[0]][1]
                        ciphertext = encrypt(replay_tor.encode('utf-8'), l_parts[0])
                        where_to_send.send(ciphertext)
            # -------------

            # -------------
            # if line_parts[0] == 'same_network:':
            #     mac_of_same_network = line_parts[1]
            #     ipv4 = client_address[0]
            #     port = client_address[1]
            #     packet_to_send = Tor_opening_packets + f'same_network'
            #     ciphertext = encrypt()
            #     if mac_of_same_network in MY_DATA_FOR_MAIN_CLIENTS:
            #
            # -------------

            # -------------
            # this packet has been sent in udp
            if line_parts[0] == 'giving_data_of_2:':
                l_parts = line_parts[1].split(',')
                replay_tor += f'id_of_packet: {id_to_pass}\r\n'
                replay_tor += handle_first_stage_udp_hole_punching(l_parts[0], client_address[0], client_address[1])
                # sending to the client i got the packet from
                if l_parts[1] in MY_DATA_FOR_CLIENTS_NODES:
                    key_to_thread = id_to_pass
                    client_socket = MY_DATA_FOR_CLIENTS_NODES[l_parts[1]][1]
                elif l_parts[1] in MY_DATA_FOR_MAIN_CLIENTS:
                    key_to_thread = l_parts[1]
                    client_socket = MY_DATA_FOR_MAIN_CLIENTS[l_parts[1]][1]
                # replay_tor += '\r\nsigh_message_for_computer: goren'
                # send_key = replay_tor.encode('utf-8') + serialize_public_key(
                #     MY_DATA_FOR_BOTS[l_parts[0]][2][1]) + 'amit'.encode('utf-8') + MY_DATA_FOR_BOTS[l_parts[1]][2][3]
                replay_tor3 = Tor_opening_packets + f'start_punch_hole: {key_to_thread}'
                ciphertext = encrypt(replay_tor3.encode('utf-8'), l_parts[0])
                where_to_send = MY_DATA_FOR_CLIENTS_NODES[l_parts[0]][1]
                # notifying the other bot he can start the punch hole
                where_to_send.send(ciphertext)
                print(f' what i am sending to the first bot in punch hole: {replay_tor}')
                ciphertext = encrypt(replay_tor.encode('utf-8'), l_parts[1])
                client_socket.send(ciphertext)
                print('finished sending each of the bots data')

            # -------------

            # -------------
            if line_parts[0] == 'keys_for_security:':
                l_parts = line.split(': ')
                if mac_of_bot in MY_DATA_FOR_MAIN_CLIENTS:
                    MY_DATA_FOR_MAIN_CLIENTS[mac_of_bot].append(
                        [deserialize_public_key(l_parts[1]), None, None, None])
                elif mac_of_bot in MY_DATA_FOR_CLIENTS_NODES:
                    MY_DATA_FOR_CLIENTS_NODES[mac_of_bot].append(
                        [deserialize_public_key(l_parts[1]), None, None, None])
                # print(f' the data of the bot: {MY_DATA_FOR_BOTS[mac_of_bot]}')
                # packet_to_send = ''
                # sending the clients the server public keys
                # print(f'the public rsa of bob: {deserialize_public_key(l_parts[1])}')
                # print(type(deserialize_public_key(l_parts[1])))
                print(print(f' the public key: {l_parts[1]}'))
                packet_to_send, encrypted_key = sending_the_keys_for_security('',
                                                                              deserialize_public_key(l_parts[1]))
                # Generate a random IV (Initialization Vector)
                # iv = os.urandom(16)  # 16 bytes IV for AES
                replay_tor += packet_to_send.encode('utf-8') + encrypted_key
                print(f"the packet i am sending with sign: {replay_tor}")
                client_socket.send(replay_tor)
            # -------------

            # -------------
            if line_parts[0] == 'mac_of_the_person_who_sent_the_packet:':
                mac_of_the_person_who_sent_the_packet = line_parts[1]
            # -------------

            # -------------
            if line_parts[0] == 'sigh_message:':
                l_parts = payload.split(b'goren')
                bob_signature_and_iv = l_parts[1].split(b'amit')
                bob_signature = bob_signature_and_iv[0]
                bob_iv = bob_signature_and_iv[1]
                # print(f' length of the cyphtext: {len(bob_signature)} and the iv{bob_iv}')
                decrypted_bob_dh_public_key = Alice_rsa_private_key.decrypt(
                    bob_signature,
                    OAEP(
                        mgf=MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(f'the id or mack of the person {mac_of_the_person_who_sent_the_packet}')
                if mac_of_the_person_who_sent_the_packet in MY_DATA_FOR_MAIN_CLIENTS:
                    MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_person_who_sent_the_packet][2][
                        1] = serialization.load_pem_public_key(
                        decrypted_bob_dh_public_key, backend=default_backend())
                    MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_person_who_sent_the_packet][2][
                        2] = Alice_dh_private_key.exchange(
                        MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_person_who_sent_the_packet][2][1])
                    # Create a Cipher object
                    # too long
                    MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_person_who_sent_the_packet][2][2] = \
                        MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_person_who_sent_the_packet][2][2][:32]
                    cipher = Cipher(
                        algorithms.AES(MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_person_who_sent_the_packet][2][2]),
                        modes.CBC(bob_iv),
                        backend=default_backend())
                    MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_person_who_sent_the_packet][2][2] = cipher
                    MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_person_who_sent_the_packet][2][3] = bob_iv
                    print(
                        f' shared with main client: {MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_person_who_sent_the_packet][2][2]}')
                    notify_a_new_client_for_other_clients(
                        MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_person_who_sent_the_packet][2][1],
                        os.urandom(16), mac_of_the_person_who_sent_the_packet,
                        MY_DATA_FOR_MAIN_CLIENTS[mac_of_the_person_who_sent_the_packet][1])
                elif mac_of_the_person_who_sent_the_packet in MY_DATA_FOR_CLIENTS_NODES:
                    MY_DATA_FOR_CLIENTS_NODES[mac_of_the_person_who_sent_the_packet][2][
                        1] = serialization.load_pem_public_key(
                        decrypted_bob_dh_public_key, backend=default_backend())
                    MY_DATA_FOR_CLIENTS_NODES[mac_of_the_person_who_sent_the_packet][2][
                        2] = Alice_dh_private_key.exchange(
                        MY_DATA_FOR_CLIENTS_NODES[mac_of_the_person_who_sent_the_packet][2][1])
                    # Create a Cipher object
                    # too long
                    MY_DATA_FOR_CLIENTS_NODES[mac_of_the_person_who_sent_the_packet][2][2] = \
                        MY_DATA_FOR_CLIENTS_NODES[mac_of_the_person_who_sent_the_packet][2][2][:32]
                    cipher = Cipher(
                        algorithms.AES(MY_DATA_FOR_CLIENTS_NODES[mac_of_the_person_who_sent_the_packet][2][2]),
                        modes.CBC(bob_iv),
                        backend=default_backend())
                    MY_DATA_FOR_CLIENTS_NODES[mac_of_the_person_who_sent_the_packet][2][2] = cipher
                    MY_DATA_FOR_CLIENTS_NODES[mac_of_the_person_who_sent_the_packet][2][3] = bob_iv
                    print(
                        f' shared with clients Nodes: {MY_DATA_FOR_CLIENTS_NODES[mac_of_the_person_who_sent_the_packet][2][2]}')
                    notify_a_new_client_for_other_clients(
                        MY_DATA_FOR_CLIENTS_NODES[mac_of_the_person_who_sent_the_packet][2][1],
                        os.urandom(16), mac_of_the_person_who_sent_the_packet,
                        MY_DATA_FOR_CLIENTS_NODES[mac_of_the_person_who_sent_the_packet][1])
            # -------------

            # -------------
            if line_parts[0] == 'node_disconnect:':
                notify_all_main_clients(line_parts[1])
                final_message = Tor_opening_packets.encode('utf-8') + 'approved:'.encode('utf-8')
                ciphertext = encrypt(final_message, line_parts[1])
                client_socket.send(ciphertext)
                del MY_DATA_FOR_CLIENTS_NODES[line_parts[1]]
                del LIST_OF_QUEUES_FOR_EACH_CLIENT[client_socket]
                print('deleted this node')
            # -------------

            # -------------
            if line_parts[0] == 'main_disconnect:':
                notify_all_nodes(line_parts[1])
                final_message = Tor_opening_packets.encode('utf-8') + 'approved:'.encode('utf-8')
                ciphertext = encrypt(final_message, line_parts[1])
                client_socket.send(ciphertext)
                del MY_DATA_FOR_MAIN_CLIENTS[line_parts[1]]
                del LIST_OF_QUEUES_FOR_EACH_CLIENT[client_socket]
    except Exception as e:
        traceback.print_exc()


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
                traceback.print_exc()
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
            data, client_address = server_socket_udp.recvfrom(16384)
            # print(f' what i am recieving from clients: {data}')
            mac = None
            for key, value in MY_DATA_FOR_MAIN_CLIENTS.items():
                if value[0][0] == client_address[0] and value[0][2] == str(client_address[1]):
                    # so the server and the bot are on the same network
                    mac = key
                    break
                elif value[0][1] == client_address[0]:
                    mac = key
                    break
            if mac is None:
                for key, value in MY_DATA_FOR_CLIENTS_NODES.items():
                    print(
                        f'the id of the client: {key} the value of the client: {value} and the address of who sent the packet: {client_address}')
                    if value[0][0] == client_address[0] and value[0][2] == str(client_address[1]):
                        # so the server and the bot are on the same network
                        mac = key
                        break
                    elif value[0][1] == client_address[0]:
                        mac = key
                        break
            plaint_text = decrypt(data, mac)
            if tor_filter(plaint_text):
                data_from_packet = plaint_text.decode('utf-8')
                handle_packets_from_computers(data_from_packet, None, client_address, server_socket_udp, plaint_text,
                                              mac)
        except Exception as e:
            # print(f"An unexpected error occurred: {e}")
            traceback.print_exc()
        # adds the payload to the queue to wait for being handled


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
    # server_socket.settimeout(5)
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
    server_socket.settimeout(5)
    return server_socket


def verify_clients(client_socket, client_address, server_socket_udp):
    """

    :param client_socket:
    :param client_address:
    :param server_socket_udp:
    :return:
    """
    global LIST_OF_QUEUES_FOR_EACH_CLIENT
    finished_exchanging_keys = 0
    mac = None
    while client_socket in LIST_OF_QUEUES_FOR_EACH_CLIENT:
        if len(LIST_OF_QUEUES_FOR_EACH_CLIENT[client_socket]) < 1:
            continue
        print('got a packet')
        incoming_packet = LIST_OF_QUEUES_FOR_EACH_CLIENT[client_socket].popleft()
        if finished_exchanging_keys < 2:
            if tor_filter(incoming_packet):
                # print('passed')
                if b'goren' in incoming_packet:
                    data1 = incoming_packet.split(b'goren')[0]
                else:
                    data1 = incoming_packet
                data_from_packet = data1.decode('utf-8')
                finished_exchanging_keys += 1
                # print(data_from_packet)
        else:
            for key, value in MY_DATA_FOR_MAIN_CLIENTS.items():
                if value[0][0] == client_address[0] and value[0][3] == str(client_address[1]):
                    # so the server and the bot are on the same network
                    mac = key
                    break
                elif value[0][1] == client_address[0]:
                    mac = key
                    break
            if mac is None:
                print('trying for node')
                for key, value in MY_DATA_FOR_CLIENTS_NODES.items():
                    print(f'entered the for: {key},{value} and {client_address}')
                    if value[0][0] == client_address[0] and value[0][3] == str(client_address[1]):
                        # so the server and the bot are on the same network
                        mac = key
                        print('found key')
                        break
                    elif value[0][1] == client_address[0]:
                        mac = key
                        break
            plaint_text = decrypt(incoming_packet, mac)
            if tor_filter(plaint_text):
                data_from_packet = plaint_text.decode('utf-8')
        print('calling handle')
        handle_packets_from_computers(data_from_packet, client_socket, client_address, server_socket_udp,
                                      incoming_packet, mac)
    print('no more this client4')


def new_clients(client_socket):
    """
    verifying the packet
    and listening to packets
    :param client_socket:
    :return:
    """
    global LIST_OF_QUEUES_FOR_EACH_CLIENT
    try:
        while client_socket in LIST_OF_QUEUES_FOR_EACH_CLIENT:
            try:
                incoming_packet = client_socket.recv(16384)
                #print(incoming_packet)
                LIST_OF_QUEUES_FOR_EACH_CLIENT[client_socket].append(incoming_packet)
            except socket_timeout:
                continue
        print('no more this client2')
    except Exception as e:
        pass
        # traceback.print_exc()


def main():
    try:
        global executor, Alice_dh_public_key, Alice_rsa_public_key, Alice_dh_private_key, Alice_rsa_private_key, LIST_OF_QUEUES_FOR_EACH_CLIENT
        server_socket_tcp = set_socket_tcp()
        server_socket_udp = set_socket_udp()
        print(f'your private ip: {get_ipv4_address_private()}')
        print(f'your public ip: {get_public_ip()}')
        # making keys
        Alice_dh_private_key, Alice_dh_public_key = generate_dh_key_pair()
        Alice_rsa_private_key, Alice_rsa_public_key = generate_rsa_key_pair()
        # print(sign_message(Alice_dh_public_key, Alice_rsa_public_key))
        # alice_dh_public_bytes = Alice_dh_public_key.export_key()
        # print(sign_message(Alice_dh_public_key, Alice_rsa_public_key))
        # Alice_rsa_public_key = RSA.import_key(alice_dh_public_bytes)
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
                LIST_OF_QUEUES_FOR_EACH_CLIENT[client_socket] = deque()
                executor.submit(new_clients, client_socket)
                executor.submit(verify_clients, client_socket, client_address, server_socket_udp)
                print('opend thread')
                # PACKETS_TO_HANDLE_QUEUE.append((client_socket, client_address))
            except socket_timeout:
                continue
            except Exception as e:
                traceback.print_exc()
    except Exception as e:
        traceback.print_exc()
        print(e)


if __name__ == "__main__":
    main()
