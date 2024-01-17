""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
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
"keys_for_security: [public_rsa],[public_dh] everyone to anyone "
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
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, PKCS1v15
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

THE_PACKET_GOT_BACK = None
DATA_FROM_UDP_HOLE_PUNCHING = None
# dictionary of all the available bots i have mac: (ipv4,port)
AVAILABLE_BOTS = {}
# dictionary will be like mac:(ipv4,port), ipv6 of the server he is connected to
MY_DATA_FOR_BOTS = {}
# data base with json like mac: and what server they are connected to( his ipv6)
Port_for_bot = None
PORT_OF_UDP_SERVER = None
IPV4_OF_SERVER = '192.168.2.135'
IPV6_OF_SERVER = '2a06:c701:4550:a00:fad4:e6f3:25c7:8b68'
Tor_opening_packets = 'Tor\r\n'
Packet_to_internet = None
executor = ThreadPoolExecutor(thread_name_prefix='worker_thread_')
PACKETS_TO_HANDLE_QUEUE = deque()
Alice_dh_private_key, Alice_dh_public_key = None, None
Alice_rsa_private_key, Alice_rsa_public_key = None, None
# ipv6: (public_rsa,public_dh)
SERVER_FOR_KEYS = {}


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
            #print(len(PACKETS_TO_HANDLE_QUEUE))
            #print('passed')
            payload = PACKETS_TO_HANDLE_QUEUE.popleft()
            if tor_filter(payload):
                data_from_packet = payload.decode('utf-8')
                #print(data_from_packet)
                handle_packets_from_server(data_from_packet, client_socket_tcp, client_socket_udp)
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


def udp_punch_hole(ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp):
    """
    creating udp punch_hole and sending the packet to the internet and waiting for the packet to come back
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
        while DATA_FROM_UDP_HOLE_PUNCHING is None:
            client_socket_udp.sendto(Packet_to_internet.encode('utf-8'), (ipv4_for_punch_hole, port_for_punch_hole))
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


def making_the_secret_key(rsa_public_key, dh_public_key):
    pass


def handle_packets_from_server(raw_packet, client_socket_tcp, client_socket_udp):
    """
    handling the data in the packets
    :param packet_to_internet:
    :param raw_packet:
    :param client_socket_tcp:
    :param client_socket_udp:
    :return:
    """
    global executor, Tor_opening_packets, Packet_to_internet, PORT_OF_UDP_SERVER
    replay_tor = Tor_opening_packets
    try:
        lines = raw_packet.split('\r\n')
        while '' in lines:
            lines.remove('')
        print(f' the data of the packet: {lines}')
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
                    #print(l_parts[1])
                    another = tuple(l_parts[1][1:-1].split(','))
                    #print(another)
                    ipv4_for_punch_hole = another[0]
                    port_for_punch_hole = int(another[1])
                    # opening a thread for udp punch_hole
                    executor.submit(udp_punch_hole, ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp)
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
                l_parts = line_parts[1].split('?')
                # in l_parts[1] you have the data to show to the user
                l_parts = line.split(': ')
                l_parts2 = l_parts[1].split(',')
                making_the_secret_key(deserialize_public_key(l_parts2[0]), deserialize_public_key(l_parts2[1]))
            # -------------

            # -------------
            if line_parts[0] == 'port_of_server:':
                PORT_OF_UDP_SERVER = int(line_parts[1])

    except Exception as e:
        traceback.print_exc()
        print(e)


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


def setting_client_socket_for_server_ipv6_or_ipv4():
    """
    checking what server the client can connect to
    :return:
    """
    # here he will open the json file and will pick up randomly a computer for ipv6
    # when i will have the db i will change the for
    global IPV4_OF_SERVER, IPV6_OF_SERVER
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
    client_socket.connect((IPV4_OF_SERVER, 56789))
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
            #print('69')
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
    but if less so between 1- computers i have
    """


def select_bot():
    """
    select a bot by random from the data base you have
    :return:
    """


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
        global Tor_opening_packets, Packet_to_internet, IPV4_OF_SERVER, PORT_OF_UDP_SERVER
        data = None
        # ttl = random_ttl()
        # id1 = random_id()
        # mac_bot = select_bot()
        ttl = 1
        id1 = 1
        mac_bot = '84-2a-fd-87-1e-1v'
        mac_bot = '876'
        first_packet = Tor_opening_packets
        Packet_to_internet = Tor_opening_packets
        Packet_to_internet += f'packet_on_the_way: {id1}?{ttl}?{data}'
        first_packet += f'start_first_stage_udp_hole_punching: {get_mac_address1()},{mac_bot}'
        client_socket_udp.sendto(first_packet.encode('utf-8'), (IPV4_OF_SERVER, PORT_OF_UDP_SERVER))
        # response_from_server = client_socket_tcp.recv(1024)
        # PACKETS_TO_HANDLE_QUEUE.append(response_from_server)
        #print('got here')
    except Exception as e:
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
    global Tor_opening_packets, Port_for_bot
    try:
        packet_to_send = Tor_opening_packets
        mac_address = get_mac_address1()
        # packet_to_send += f'new_client_to_server: {mac_address},{get_public_ip()},{Port_for_bot}\r\n'
        packet_to_send += f'new_client_to_server: {mac_address},{get_ipv4_address_private()},{get_public_ip()},{Port_for_bot}\r\n'
        packet_to_send = sending_the_keys_for_security(packet_to_send)
        #print(f" how keys look : {packet_to_send.encode('utf-8')}")
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
        print('did keys')

        # waits_for_server_approve = client_socket_tcp.recv(1024)
        # print(waits_for_server_approve)
        # notifying the server about my mac
        select_random_port()
        notify_mac_to_server(client_socket_tcp)
        #print('1')
        # here getting the keys from the server
        # data = client_socket_tcp.recv(1024)
        # handling_keys_from_server(data)
        client_socket_udp = setting_client_socket_for_bots()
        #print('2')
        # calling the function who checks if the user typed something
        executor.submit(check_user_info, client_socket_udp, client_socket_tcp)
        #print('3')
        # a thread for handling the packets
        executor.submit(verify_packets_from_server, client_socket_tcp, client_socket_udp)
        while True:
            response_from_server = client_socket_tcp.recv(1024)
            #print(response_from_server)
            # add the packets to queue
            PACKETS_TO_HANDLE_QUEUE.append(response_from_server)
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
