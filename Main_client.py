""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"""""""""""""""""""""""""""""""""THE PROTOCOL FOR THE PACKETS"""""""""""""""""""""""
"Tor;""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""''""""""""''"""
"new_client_to_server: [mac of the new client that connected to you],[his ipv4],[his port number]  client Node and main to server and server to client Nodes"
"start_first_stage_udp_hole_punching: [mac_of_the person who sent the packet],[mac of the person you want to do udp punch_hole] client Node and main to server "
"server_answer_for_first_stage_udp_hole_punching: if the server connect to the bot:[yes]?[(ipv4,port)] if not:[no] server to client Node and main "
"server_notify_bot_for_second_stage_of_udp_hole_punching: [mac]?[(ipv4,port)] server to client Node and main"
"packet_on_the_way: [id]?[ttl]?[data] main client to client Node and client Node to Client Node"
"packet_on__the_way_back: [id]?[data] client Node to Client Node and client Node to main client "
"new_ipv6_server: [ipv6] new ipv6 server to all other ipv6 servers"
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

THE_PACKET_GOT_BACK = None
DATA_FROM_UDP_HOLE_PUNCHING = None
# dictionary of all the available bots i have mac: (ipv4,port)
AVAILABLE_BOTS = {}
# dictionary will be like mac:(ipv4,port), ipv6 of the server he is connected to
MY_DATA_FOR_BOTS = {}
# data base with json like mac: and what server they are connected to( his ipv6)
Port_for_bot = None
Tor_opening_packets = 'Tor\r\n'
Packet_to_internet = None
executor = ThreadPoolExecutor(thread_name_prefix='worker_thread_')
PACKETS_TO_HANDLE_QUEUE = deque()


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
            print(len(PACKETS_TO_HANDLE_QUEUE))
            print('passed')
            payload = PACKETS_TO_HANDLE_QUEUE.popleft()
            if tor_filter(payload):
                data_from_packet = payload.decode('utf-8')
                print(data_from_packet)
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
        print('started to try here')
        # put here the real message you want to send
        message = 'do udp punch hole'
        while DATA_FROM_UDP_HOLE_PUNCHING is None:
            client_socket_udp.sendto(message.encode('utf-8'), (ipv4_for_punch_hole, port_for_punch_hole))
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
        print('sending the first packet')
        client_socket_udp.sendto(Packet_to_internet.encode('utf-8'), (ipv4_for_punch_hole, port_for_punch_hole))
        # waiting for the packet to come back
        while DATA_FROM_UDP_HOLE_PUNCHING is None:
            try:
                DATA_FROM_UDP_HOLE_PUNCHING, sender_address = client_socket_udp.recvfrom(1024)
                print(f'data from udp hole_punching on the way back {DATA_FROM_UDP_HOLE_PUNCHING}')
            except socket_timeout:  # !!
                continue  # !!
        PACKETS_TO_HANDLE_QUEUE.append(DATA_FROM_UDP_HOLE_PUNCHING)
        DATA_FROM_UDP_HOLE_PUNCHING = None
        # i want to keep the connection
    except Exception as e:
        traceback.print_exc()
        print(e)


def handle_packets_from_server(raw_packet, client_socket_tcp, client_socket_udp):
    """
    handling the data in the packets
    :param packet_to_internet:
    :param raw_packet:
    :param client_socket_tcp:
    :param client_socket_udp:
    :return:
    """
    global executor, Tor_opening_packets, Packet_to_internet
    replay_tor = Tor_opening_packets
    try:
        lines = raw_packet.split('\r\n')
        while '' in lines:
            lines.remove('')
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
                    print(l_parts[1])
                    another = tuple(l_parts[1][1:-1].split(','))
                    print(another)
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


def setting_client_socket_for_server():
    # here he will open the json file and will pick up randomly a computer for ipv6
    client_socket = socket(AF_INET6, SOCK_STREAM)
    try:
        client_socket.connect(('2a06:c701:4550:a00:fad4:e6f3:25c7:8b68', 56789))
        print(f"Connected to {'2a06:c701:4550:a00:fad4:e6f3:25c7:8b68'}:{56789}")
    except Exception as e:
        print(e)
    return client_socket


def setting_client_socket_for_bots():
    try:
        global Port_for_bot
        a = 0
        client_udp_socket = socket(AF_INET, SOCK_DGRAM)
        client_udp_socket.settimeout(0.2)
        # do bind !!!!!!!!!!!!!!!
        client_udp_socket.bind((get_ipv4_address(), Port_for_bot))
        while a == 0:
            try:
                client_udp_socket.bind((get_ipv4_address(), Port_for_bot))
                a = 1
            except error as e:
                if e.args[0] == 10048:
                    print(f"Error: Port {Port_for_bot} is already in use.")
                    select_random_port()
        return client_udp_socket
    except Exception as e:
        print(e)


def get_ipv4_address():
    # Get the hostname of the local machine
    hostname = gethostname()

    # Get the IPv4 address associated with the hostname
    ip_address = gethostbyname(hostname)

    return ip_address


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


def check_user_info(client_socket_tcp):
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
        global Tor_opening_packets, Packet_to_internet
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
        client_socket_tcp.send(first_packet.encode('utf-8'))
        response_from_server = client_socket_tcp.recv(1024)
        PACKETS_TO_HANDLE_QUEUE.append(response_from_server)
        print('got here')
    except Exception as e:
        print(f' got it here {e}')


def notify_mac_to_server(client_socket_tcp):
    global Tor_opening_packets, Port_for_bot
    try:
        packet_to_send = Tor_opening_packets
        mac_address = get_mac_address1()
        packet_to_send += f'new_client_to_server: {mac_address},{get_ipv4_address()},{Port_for_bot}'
        client_socket_tcp.send(packet_to_send.encode('utf-8'))
    except Exception as e:
        print(e)


def main():
    try:
        global executor
        client_socket_tcp = setting_client_socket_for_server()
        # waits_for_server_approve = client_socket_tcp.recv(1024)
        # print(waits_for_server_approve)
        # notifying the server about my mac
        select_random_port()
        notify_mac_to_server(client_socket_tcp)
        print('1')
        client_socket_udp = setting_client_socket_for_bots()
        print('2')
        # calling the function who checks if the user typed something
        executor.submit(check_user_info, client_socket_tcp)
        print('3')
        # a thread for handling the packets
        executor.submit(verify_packets_from_server, client_socket_tcp, client_socket_udp)
        while True:
            response_from_server = client_socket_tcp.recv(1024)
            print(response_from_server)
            # add the packets to queue
            PACKETS_TO_HANDLE_QUEUE.append(response_from_server)
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
