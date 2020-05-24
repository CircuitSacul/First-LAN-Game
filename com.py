import threading, socket, os, sys, ipscanner, subprocess
import multiprocessing as mp

ip_list = []
message_list = []
unread_list = []

processes = [] #So they can be quit in the quit() function

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = s.getsockname()[0]
s.close()


host = ""
port = 1300
buf = 1024
addr = (host, port)
UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UDPSock.bind(addr)

target_UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def pinger(job_q, results_q):
    """
    Do Ping
    :param job_q:
    :param results_q:
    :return:
    """
    DEVNULL = open(os.devnull, 'w')
    while True:

        ip = job_q.get()

        if ip is None:
            break

        try:
            subprocess.check_call(['ping', '-c1', ip],
                                  stdout=DEVNULL)
            results_q.put(ip)
        except:
            pass
    DEVNULL.close()


def get_my_ip():
    """
    Find my IP address
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def map_network(pool_size=200):
    """
    Maps the network
    :param pool_size: amount of parallel ping processes
    :return: list of valid ip addresses
    """

    ip_list = list()

    # get my IP and compose a base like 192.168.1.xxx
    ip_parts = get_my_ip().split('.')
    base_ip = ip_parts[0] + '.' + ip_parts[1] + '.' + ip_parts[2] + '.'

    # prepare the jobs queue
    jobs = mp.Queue()
    results = mp.Queue()

    pool = [mp.Process(target=pinger, args=(jobs, results)) for i in range(pool_size)]

    for p in pool:
        p.start()

    # cue hte ping processes
    for i in range(1, 255):
        jobs.put(base_ip + '{0}'.format(i))

    for p in pool:
        jobs.put(None)

    for p in pool:
        p.join()

    # collect he results
    while not results.empty():
        ip = results.get()
        ip_list.append(ip)

    return ip_list


def update_ips():
    global ip_list
    ip_list = map_network()
    for x, ip in enumerate(ip_list):
        if ip == my_ip:
            del ip_list[x]


def repeat_update_ips():
    while True:
        update_ips()


def start_listen():
    global unread_list
    global message_list
    while True:
        received, addr = UDPSock.recvfrom(buf)
        ip, port = addr
        message_list.append([addr, received])
        unread_list.append([addr, received])


def send_message(message, ips=ip_list):
    if type(ips == list):
        for ip in ips:
            target_UDPSock.sendto(message, (ip, port))
    else:
        target_UDPSock.sendto(message, (ips, port))


def read_unreads():
    global unread_list
    return unread_list
    unread_list = []


def quit():
    for process in processes:
        process.terminate()
        process.join()
    UDPSock.close()
    target_UDPSock.close()


def init():
    global processes

    try:
        update_ips()
        update = mp.Process(target=repeat_update_ips)
        listen = mp.Process(target=start_listen)
        update.start()
        listen.start()
        processes = [update, listen]
    except Exception as e:
        print(f"{type(e)}: {e}")
        quit()
