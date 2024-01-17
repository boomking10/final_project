""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import random

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
"keys_for_security: [public_rsa],[public_dh] everyone to anyone "
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

import traceback
from socket import socket, AF_INET6, SOCK_DGRAM, SOCK_STREAM, timeout as socket_timeout
from concurrent.futures import ThreadPoolExecutor
import json
from collections import deque
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, PKCS1v15
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

Tor_opening_packets = 'Tor\r\n'
# creating json file with my information there. this lines will be only in my code because
# when first they install the exe they will need to know where to send first
# mac: tuple(str_ipv4, int_port), client_socket, (public_rsa, public_dh)
MY_DATA_FOR_BOTS = {}
PORT_FOR_UDP = None
executor = ThreadPoolExecutor(thread_name_prefix='worker_thread_')
Alice_dh_private_key, Alice_dh_public_key = None, None
Alice_rsa_private_key, Alice_rsa_public_key = None, None


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


def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        PKCS1v15(),
        hashes.SHA256()
    )
    return signature


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
    dh_public_to_send = serialize_public_key(Alice_dh_public_key)
    dh_public_to_send = dh_public_to_send.decode('utf-8')
    packet_to_send += f"keys_for_security: {rsa_public_to_send},{dh_public_to_send}"
    return packet_to_send


def server_notify_bot_for_second_stage_of_udp_hole_punching(mac_of_the_other_person, port):
    global MY_DATA_FOR_BOTS
    try:
        packet_to_add = None
        if mac_of_the_other_person in MY_DATA_FOR_BOTS:
            data_for_person = MY_DATA_FOR_BOTS[mac_of_the_other_person][0]
            # if the in the same internet
            packet_to_add = f'server_notify_bot_for_second_stage_of_udp_hole_punching: {mac_of_the_other_person}?({data_for_person[0]},{data_for_person[2]})'
            # if not
            packet_to_add = f'server_notify_bot_for_second_stage_of_udp_hole_punching: {mac_of_the_other_person}?({data_for_person[1]},{port})'
        return packet_to_add
    except Exception as e:
        print(e)


def handle_first_stage_udp_hole_punching(mac_of_the_person, port):
    global MY_DATA_FOR_BOTS
    try:
        if mac_of_the_person in MY_DATA_FOR_BOTS:
            data_for_person = MY_DATA_FOR_BOTS[mac_of_the_person][0]
            # if same internet
            packet_to_add = f'server_answer_for_first_stage_udp_hole_punching: yes?({data_for_person[0]},{data_for_person[2]})'
            # if not
            packet_to_add = f'server_answer_for_first_stage_udp_hole_punching: yes?({data_for_person[1]},{port})'
        else:
            packet_to_add = f'server_answer_for_first_stage_udp_hole_punching: no'
        return packet_to_add
    except Exception as e:
        print(e)


def updating_data_base():
    pass


def handle_packets_from_computers(raw_packet, client_socket, client_address, server_socket_udp):
    global executor, Tor_opening_packets, MY_DATA_FOR_BOTS
    replay_tor = Tor_opening_packets
    try:
        lines = raw_packet.split('\r\n')
        while '' in lines:
            lines.remove('')
        print(lines)
        for line in lines:
            line_parts = line.split()
            # new_client_to_server: [mac of the new client that connected to you] client Node and main to server and server to client Nodes
            # -------------
            if line_parts[0] == 'new_client_to_server:':
                l_parts = line_parts[1].split(',')
                mac_of_bot = l_parts[0]
                # (private ip, public ip, port number private, port number public), client socket
                MY_DATA_FOR_BOTS[l_parts[0]] = [(l_parts[1], l_parts[2], l_parts[3], client_address[1]), client_socket]
                # add this client mac in line_parts[1] to your data base and with his address
                updating_data_base()
                pass
            # -------------

            # -------------
            if line_parts[0] == 'start_first_stage_udp_hole_punching:':
                l_parts = line_parts[1].split(',')
                # in l_parts[1] you have the mac. open it from your dictionary and send server_answer_for_first_stage_udp_hole_punching
                replay_tor2 = replay_tor
                # and do notify the other bot
                replay_tor2 += server_notify_bot_for_second_stage_of_udp_hole_punching(l_parts[0], client_address[1])
                replay_tor += handle_first_stage_udp_hole_punching(l_parts[1], client_address[1])
                # sending to the client i got the packet from
                print(replay_tor)
                client_socket.send(replay_tor.encode('utf-8'))
                print('did_this')
                # sending to the other client
                print(replay_tor2)
                MY_DATA_FOR_BOTS[l_parts[1]][1].send(replay_tor2.encode('utf-8'))
                print('finished start_first_stage_udp_hole_punching:')
            # -------------

            # -------------
            if line_parts[0] == 'keys_for_security:':
                l_parts = line.split(': ')
                l_parts2 = l_parts[1].split(',')
                MY_DATA_FOR_BOTS[mac_of_bot].append((deserialize_public_key(l_parts2[0]), deserialize_public_key(l_parts2[1])))
                print(f' the data of the bot: {MY_DATA_FOR_BOTS[mac_of_bot]}')
                packet_to_send = Tor_opening_packets
                # sending the clients the server public keys
                packet_to_send = sending_the_keys_for_security(packet_to_send)
                client_socket.send(packet_to_send.encode('utf-8'))
    except Exception as e:
        traceback.print_exc()
        print(e)


def tor_filter(payload):
    # print('got here')
    print(payload.decode('utf-8'))
    expected = 'Tor'.encode('utf-8')
    return payload[:len(expected)] == expected


def select_random_port():
    global PORT_FOR_UDP
    PORT_FOR_UDP = random.randint(20000, 29000)


def set_socket_udp():
    """
    Setting a socket object of AF_INET (IPv4) and S (TCP).
    :return: <Socket> the socket object.
    """
    global PORT_FOR_UDP
    # setting an IPv4/TCP socket
    server_socket = socket(AF_INET, SOCK_DGRAM)
    # binding the server socket
    select_random_port()
    server_socket.bind(('0.0.0.0', PORT_FOR_UDP))
    return server_socket


def set_socket_tcp(ipv6):
    """
    Setting a socket object of AF_INET (IPv6) and S (TCP).
    :return: <Socket> the socket object.
    """
    # setting an IPv6/TCP socket
    server_socket = socket(AF_INET6, SOCK_STREAM)
    # binding the server socket
    server_socket.bind((ipv6, 56789))
    return server_socket


def new_clients(client_socket, client_address, server_socket_udp):
    # telling the client i got the packet
    # client_socket.send('arrive'.encode('utf-8'))
    response = client_socket.recv(1024)
    if tor_filter(response):
        data_from_packet = response.decode('utf-8')
        handle_packets_from_computers(data_from_packet, client_socket, client_address, server_socket_udp)
    while True:
        incoming_packet = client_socket.recv(1024)
        if tor_filter(incoming_packet):
            print('passed')
            data_from_packet = incoming_packet.decode('utf-8')
            print(data_from_packet)
            handle_packets_from_computers(data_from_packet, client_socket, client_address, server_socket_udp)


def main(ipv6):
    try:
        global executor, Alice_dh_public_key, Alice_rsa_public_key, Alice_dh_private_key, Alice_rsa_private_key
        server_socket = set_socket_tcp(ipv6)
        server_socket_udp = set_socket_udp()
        # making keys
        Alice_dh_private_key, Alice_dh_public_key = generate_dh_key_pair()
        Alice_rsa_private_key, Alice_rsa_public_key = generate_rsa_key_pair()
        print('did keys')
        # setting a thread which will handle new clients.
        # executor.submit(verify_packets_from_computers)
        while True:
            try:  # !!
                server_socket.listen(1)  # getting incoming packets
                client_socket, client_address = server_socket.accept()
                print(client_address)
                executor.submit(new_clients, client_socket, client_address, server_socket_udp)
                # PACKETS_TO_HANDLE_QUEUE.append((client_socket, client_address))
            except Exception as e:
                print(e)
    except Exception as e:
        traceback.print_exc()
        print(e)


def get_ipv6_address():
    """
    checking if there is ipv6 and if there is i send it back
    :return: ipv6
    """
    try:
        # Connect to a remote server (e.g., Google's public DNS) over IPv6 and get the local address
        s = socket(AF_INET6, SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 80))
        ipv6_address = s.getsockname()[0]
        s.close()
        return True, ipv6_address
    except Exception as e:
        print("problem in get_ipv6_address: " + str(e))
        return False, 1


if __name__ == "__main__":
    ipv6_address = get_ipv6_address()
    if ipv6_address[0]:
        print("YOUR IPV6 IS WORKING! YOU COMPUTER CAN BE A SERVER:" + ipv6_address[1])
        main(ipv6_address[1])
    else:
        print("I AM SORRY MATE BUT YOU DON'T HAVE IPV6 WORKING")
