from random import randint
import binascii
import socket
import sys
import time

def message_decoder(data):
    #Parsing the header section
    header_section = binascii.hexlify(data[0:12]).decode("utf-8")
    ID_message = header_section[0:4]
    Flags_message = header_section[4:8]
    Question_number = int(header_section[8:12], 16)
    Answer_RRs = int(header_section[12:16], 16)
    Authority_RRs = int(header_section[16:20], 16)
    Additional_RRs = int(header_section[20:24], 16)

    # Query_Section
    query_section = binascii.hexlify(data[12:25]).decode("utf-8")

    # Parsing the Answer Section
    z = 25
    while(1):
        answer_section = binascii.hexlify(data[z:z+16]).decode("utf-8")
        domain_name = answer_section[0:4]
        host_type = answer_section[4:8]
        host_class = answer_section[8:12]
        host_time_leave = answer_section[12:20]
        data_len = answer_section[20:24]
        ip = answer_section[24:32]
        z+= 16
        if(z>=89):
            break

    #parse the ip
    ip_parse = ""
    ip_i = 0
    while (1):
        y = ip[ip_i:ip_i + 2]
        x = int((y), 16)
        ip_parse += str(x) + "."
        ip_i += 2
        if (ip_i + 2 > len(ip)):
            ip_parse = ip_parse[0:int(len(ip_parse)) - 1]
            break

    return ip_parse

def message_creator(address):
    #Create a udpacket to send
    message = ""
    parameters = ""
    ID = 43690 #Identifier 16bit
    message += "{:04x}".format(ID)
    QR = 0 #QR 0 for querry 1 bit
    parameters += str(QR)
    OPCODE = 0 #4 bit
    parameters += str(OPCODE).zfill(4)
    AA = 0 #1 bit
    parameters += str(AA)
    TC = 0 #1bit
    parameters += str(TC)
    RD = 1 #1 bit
    parameters += str(RD)
    RA = 0 #1 bit
    parameters += str(RA)
    Z = 0 #3bit
    parameters += str(Z).zfill(3)
    RCODE = 0 #4bit
    parameters += str(RCODE).zfill(4)
    values = "{:04x}".format(int(parameters, 2))
    message  += values
    #All of them are 4 bits
    Qd_count = 1
    message += "{:04x}".format(Qd_count)
    An_count = 0
    message += "{:04x}".format(An_count)
    Ns_count = 0
    message += "{:04x}".format(Ns_count)
    Ar_count = 0
    message += "{:04x}".format(Ar_count)
    z ="{:04x}".format(Ar_count)

    #Formatting the address
    splitted_address = address.split(".")
    for ady in splitted_address:
        length = "{:02x}".format(len(ady))
        message +=length
        encoded_part = binascii.hexlify(ady.encode())
        message += encoded_part.decode()

    message += "00"  # Terminating bit for QNAME
    message += "{:04x}".format(1)
    QCLASS = 1
    message += "{:04x}".format(QCLASS)
    return message

Iran = ["91.245.229.1", "46.224.1.42", "185.161.112.34"]
US = ["169.237.229.88", "168.62.214.68", "104.42.159.98"]
Canada = ["136.159.85.15", "184.94.80.170", "142.103.1.1"]

address = "tmz.com"
message = message_creator(address)
message = message.replace(" ", "").replace("\n", "")

server_addr = ('169.237.229.88',53)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.sendto(binascii.unhexlify(message),server_addr)
    data, _ = sock.recvfrom(4096)
    ip = message_decoder(data)

    for i in range(len(Iran)):
        iranServer = (Iran[i], 53)
        print("Server address", iranServer)
        sock.sendto(binascii.unhexlify(message), iranServer)
        sock.settimeout(10)                         #if not found in 10 secs, switch to next ip
        start_time = time.time()
        try:
            dataIran, _ = sock.recvfrom(4096)
            total_time = time.time() - start_time   #time in seconds
            total_time = total_time * 1000          #convert time to ms
            print("Time Iran:", total_time, "ms")
            sock.settimeout(0)
            break
        except:
            print("IP", iranServer[i], "not connected")
            continue

    for i in range(len(US)):
        usServer = (US[i], 53)
        print("Server address", usServer)
        sock.sendto(binascii.unhexlify(message), usServer)
        sock.settimeout(10)                         #if not found in 10 secs, switch to next ip
        start_time = time.time()
        try:
            dataUS, _ = sock.recvfrom(4096)
            total_time = time.time() - start_time   #time in seconds
            total_time = total_time * 1000          #convert time to ms
            print("Time US:", total_time, "ms")
            sock.settimeout(0)
            break
        except:
            print("IP", usServer[i], "not connected")
            continue

    for i in range(len(Canada)):
        canadaServer = (US[i], 53)
        print("Server address", canadaServer)
        sock.sendto(binascii.unhexlify(message), canadaServer)
        sock.settimeout(10)                         #if not found in 10 secs, switch to next ip
        start_time = time.time()
        try:
            dataCanada, _ = sock.recvfrom(4096)
            total_time = time.time() - start_time   #time in seconds
            total_time = total_time * 1000          #convert time to ms
            print("Time Canada:", total_time, "ms")
            sock.settimeout(0)
            break
        except:
            print("IP", canadaServer[i], "not connected")
            continue

host = sys.argv[1]
target_host = host

target_port = 80  # create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect the client
client.connect((target_host, target_port))

# send some data
request = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" % target_host
client.send(request.encode())

# receive data
response = client.recv(4096)
http_response = repr(response)
http_response_len = len(http_response)

# display the response
with open('HTTP_Response.html', 'w') as writer:
    writer.write(response.decode("utf-8"))

sock.close()
