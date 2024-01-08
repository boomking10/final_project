""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"""""""""""""""""""""""""""""""""THE PROTOCOL FOR THE PACKETS"""""""""""""""""""""""
"Tor;""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""''""""""""''"""
"new_client_to_server: [mac of the new client that connected to you],[his ipv4],[his port number]  client Node and main to server and server to client Nodes"
"start_first_stage_udp_hole_punching: [mac_of_the person who sent the packet],[mac of the person you want to do udp punch_hole] client Node and main to server "
"server_answer_for_first_stage_udp_hole_punching: if the server connect to the bot:[yes]?[(ipv4,port)] if not:[no] server to client Node and main "
"server_notify_bot_for_second_stage_of_udp_hole_punching: [mac]?[(ipv4,port)] server to client Node and main"
"packet_on_the_way: [id]?[ttl]?[data] main client to client Node and client Node to Client Node"
"packet_on__the_way_back: [id]?[data] client Node to Client Node and client Node to main client "
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

import random
from getmac import get_mac_address
from socket import socket, error, AF_INET6, AF_INET, SOCK_DGRAM, SOCK_STREAM, gethostbyname, gethostname, \
    timeout as socket_timeout
from concurrent.futures import ThreadPoolExecutor
import json
from collections import deque

DATA_FROM_UDP_HOLE_PUNCHING = None
Port_for_bot = None
Tor_opening_packets = 'Tor\r\n'
# dictionary will be like mac:(ipv4,port)
# data base with json like mac: and what server they are conncted to( his ipv6)
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
            payload = PACKETS_TO_HANDLE_QUEUE.popleft()
            if tor_filter(payload):
                data_from_packet = payload.decode('utf-8')
                print(data_from_packet)
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
        DATA_FROM_UDP_HOLE_PUNCHING, sender = client_socket_udp.recvfrom(1024)
        print(f'getting the first packet {DATA_FROM_UDP_HOLE_PUNCHING}')
        verify_packets_from_bots(client_socket_udp, (ipv4_for_punch_hole, port_for_punch_hole))
        # PACKETS_TO_HANDLE_QUEUE.append(packet1)
    except Exception as e:
        print('tried punch')
        print(e)


def handle_packets_from_server(raw_packet, client_socket_tcp, client_socket_udp):
    """
    handling the data in the packets
    :param raw_packet:
    :param client_socket_tcp:
    :param client_socket_udp:
    :return:
    """
    global executor
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
                l_parts = line_parts[1].split('?')
                mac_of_other_client = l_parts[0]
                another = tuple(l_parts[1][1:-1].split(','))
                print(another)
                ipv4_for_punch_hole = another[0]
                port_for_punch_hole = int(another[1])
                # put in your dictionary the mac as key and his ipv4 and port
                # opening a thread for udp punch_hole
                executor.submit(udp_punch_hole, ipv4_for_punch_hole, port_for_punch_hole, client_socket_udp)
                # -------------

                # -------------

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
    try:
        lines = raw_packet.split('\r\n')
        while '' in lines:
            lines.remove('')
        print(f' got packet on the way {lines}')
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

    except Exception as e:
        print(f' error in handling packets from bots {e}')


def verify_packets_from_bots(client_socket_udp, punch_hole_address):
    """
    verifying the packets from bots
    :return:
    """
    global DATA_FROM_UDP_HOLE_PUNCHING
    if tor_filter(DATA_FROM_UDP_HOLE_PUNCHING):
        print('passed verify from bots')
        data_from_packet = DATA_FROM_UDP_HOLE_PUNCHING.decode('utf-8')
        handle_packets_from_bots(data_from_packet, client_socket_udp, punch_hole_address)


def setting_client_socket_for_server():
    # here he will open the json file and will pick up randomly a computer for ipv6
    client_socket = socket(AF_INET6, SOCK_STREAM)
    try:
        client_socket.connect(('2a06:c701:4550:a00:90c3:bd99:f717:3eb9', 56789))
        print(f"Connected to {'2a06:c701:4550:a00:90c3:bd99:f717:3eb9'}:{56789}")
    except Exception as e:
        print(e)
    return client_socket


def setting_client_socket_for_bots():
    try:
        global Port_for_bot
        a = 0
        client_udp_socket = socket(AF_INET, SOCK_DGRAM)
        client_udp_socket.settimeout(0.2)
        # bind do !!!!!!!!!!!!!!!
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


def get_mac_address1():
    try:
        my_mac = get_mac_address()
        return my_mac
    except Exception as e:
        print(e)


def notify_mac_to_server(client_socket_tcp):
    global Tor_opening_packets, Port_for_bot
    try:
        packet_to_send = Tor_opening_packets
        mac_address = get_mac_address1()
        mac_address = '876'
        packet_to_send += f'new_client_to_server: {mac_address},{get_ipv4_address()},{Port_for_bot}'
        client_socket_tcp.send(packet_to_send.encode('utf-8'))
    except Exception as e:
        print(e)


def main():
    try:
        global executor
        client_socket_tcp = setting_client_socket_for_server()
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
