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

import traceback
from socket import socket, AF_INET6, SOCK_DGRAM, SOCK_STREAM
from concurrent.futures import ThreadPoolExecutor
import json
from collections import deque

Tor_opening_packets = 'Tor\r\n'
# creating json file with my information there. this lines will be only in my code because
# when first they install the exe they will need to know where to send first
# mac: tuple(str_ipv4, int_port), client_socket
MY_DATA_FOR_BOTS = {}

executor = ThreadPoolExecutor(thread_name_prefix='worker_thread_')


# # Use forward slashes or a raw string for the file path
# file_path = 'C:/Networks/last_project/server.json'
# MY_DATA_FOR_BOTS = {'Mac': 'D0-37-45-92-6C-91', 'Ipv4': '10.0.0.11', 'Port': 56779}
# with open(file_path, 'w') as json_file:
#     json.dump(MY_DATA_FOR_BOTS, json_file)
# ######################################################################
# PACKETS_TO_HANDLE_QUEUE = deque()

def server_notify_bot_for_second_stage_of_udp_hole_punching(mac_of_the_other_person):
    global MY_DATA_FOR_BOTS
    try:
        packet_to_add = None
        if mac_of_the_other_person in MY_DATA_FOR_BOTS:
            data_for_person = MY_DATA_FOR_BOTS[mac_of_the_other_person][0]
            packet_to_add = f'server_notify_bot_for_second_stage_of_udp_hole_punching: {mac_of_the_other_person}?({data_for_person[0]},{data_for_person[1]})'
        return packet_to_add
    except Exception as e:
        print(e)


def handle_first_stage_udp_hole_punching(mac_of_the_person):
    global MY_DATA_FOR_BOTS
    try:
        if mac_of_the_person in MY_DATA_FOR_BOTS:
            data_for_person = MY_DATA_FOR_BOTS[mac_of_the_person][0]
            packet_to_add = f'server_answer_for_first_stage_udp_hole_punching: yes?({data_for_person[0]},{data_for_person[1]})'
        else:
            packet_to_add = f'server_answer_for_first_stage_udp_hole_punching: no'
        return packet_to_add
    except Exception as e:
        print(e)


def updating_data_base():
    pass


def handle_packets_from_computers(raw_packet, client_socket, client_address):
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
                MY_DATA_FOR_BOTS[l_parts[0]] = (l_parts[1], l_parts[2]), client_socket
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
                replay_tor2 += server_notify_bot_for_second_stage_of_udp_hole_punching(l_parts[0])
                replay_tor += handle_first_stage_udp_hole_punching(l_parts[1])
                # sending to the client i got the packet from
                print(replay_tor)
                client_socket.send(replay_tor.encode('utf-8'))
                print('did_this')
                # sending to the other client
                print(replay_tor2)
                MY_DATA_FOR_BOTS[l_parts[1]][1].send(replay_tor2.encode('utf-8'))
                print('finished start_first_stage_udp_hole_punching:')

    except Exception as e:
        print(e)


def tor_filter(payload):
    #print('got here')
    print(payload.decode('utf-8'))
    expected = 'Tor'.encode('utf-8')
    return payload[:len(expected)] == expected


def verify_packets_from_computers():
    try:
        global executor
        while True:
            global PACKETS_TO_HANDLE_QUEUE
            if len(PACKETS_TO_HANDLE_QUEUE) < 0:
                return None
            payload = PACKETS_TO_HANDLE_QUEUE.popleft()
            executor.submit(new_clients, payload[0], payload[1])
    except Exception as e:
        print(e)


def set_socket(ipv6):
    """
    Setting a socket object of AF_INET (IPv6) and S (TCP).
    :return: <Socket> the socket object.
    """
    # setting an IPv6/TCP socket
    server_socket = socket(AF_INET6, SOCK_STREAM)
    # binding the server socket
    server_socket.bind((ipv6, 56789))
    return server_socket


def new_clients(client_socket, client_address):
    # telling the client i got the packet
    #client_socket.send('arrive'.encode('utf-8'))
    response = client_socket.recv(1024)
    if tor_filter(response):
        data_from_packet = response.decode('utf-8')
        handle_packets_from_computers(data_from_packet, client_socket, client_address)
    while True:
        incoming_packet = client_socket.recv(1024)
        if tor_filter(incoming_packet):
            print('passed')
            data_from_packet = incoming_packet.decode('utf-8')
            print(data_from_packet)
            handle_packets_from_computers(data_from_packet, client_socket, client_address)


def main(ipv6):
    try:
        global executor
        server_socket = set_socket(ipv6)
        # setting a thread which will handle new clients.
        # executor.submit(verify_packets_from_computers)
        while True:
            try:  # !!
                server_socket.listen(1)  # getting incoming packets
                client_socket, client_address = server_socket.accept()
                print(client_address)
                executor.submit(new_clients, client_socket, client_address)
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
