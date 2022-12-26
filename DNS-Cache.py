import binascii
import socket
import sys
import time
import csv



def message_creator(address):
    #Create a udpacket to send
    message = ""
    parameters = ""
    ID = 43960 #Identifier 16bit
    message += "{:04x}".format(ID)
    QR = 0 #QR 0 for querry 1 bit
    parameters += str(QR)
    OPCODE = 0 #4 bit
    parameters += str(OPCODE).zfill(4)
    AA = 0 #1 bit
    parameters += str(AA)
    TC = 0 #1bit
    parameters += str(TC)
    RD = 0 #1 bit
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

def http_decoder(data):
    # Parsing the header section
    header_section = binascii.hexlify(data[0:12]).decode("utf-8")
    ID_message = header_section[0:4]
    Flags_message = header_section[4:8]
    Question_number = int(header_section[8:12], 16)
    Answer_RRs = int(header_section[12:16], 16)
    Authority_RRs = int(header_section[16:20], 16)
    Additional_RRs = int(header_section[20:24], 16)

    # Query_Section
    query_section = binascii.hexlify(data[12:25]).decode("utf-8")
    z = 12
    while (1):
        if (binascii.hexlify(data[z:z + 1]).decode("utf-8") != "00"):
            z += 1
        else:
            break
    z += 5
    looped = 0
    stored_https = list()
    stored_ttl = list()
    stored_time = list()
    # Parsing the Answer Section
    while (1):
        start = time.time()
        answer_section = binascii.hexlify(data[z:z + 16]).decode("utf-8")
        domain_name = answer_section[0:4]
        host_type = answer_section[4:8]
        host_class = answer_section[8:12]
        host_time_leave = answer_section[12:20]
        data_len = answer_section[20:24]
        ip = answer_section[24:32]
        # parse the ip
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
        total_time = time.time() - start        #time in seconds
        total_time = total_time * 1000          #time in ms
        stored_https.append(ip_parse)
        stored_ttl.append(int(host_time_leave,16))
        stored_time.append(total_time)
        z += 16
        looped += 1
        if (looped >= Answer_RRs):
            break


    return stored_https, stored_ttl, stored_time

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

    # leave question
    z=12
    while(1):
        if (binascii.hexlify(data[z:z+1]).decode("utf-8") != "00"):
            z+= 1
        else:
            break
    z+=5
    looped = 0


    while(1):
        resource_name = binascii.hexlify(data[z:z+2]).decode("utf-8")

        server_type = binascii.hexlify(data[z+2:z+4]).decode("utf-8")
        server_class = binascii.hexlify(data[z+4:z+6]).decode("utf-8")
        res_time_leave = int(binascii.hexlify(data[z+8:z+10]).decode("utf-8"),16)
        res_len = int(binascii.hexlify(data[z+10:z+12]),16)
        # res_ip = data[data+24:data+24+res_len]
        z += 12 + res_len
        looped += 1
        if(looped >= Authority_RRs):
            break
    looped = 0
    while(1):
        name_resource = binascii.hexlify(data[z:z+2]).decode("utf-8")
        type_server = binascii.hexlify(data[z+2:z+4]).decode("utf-8")
        type_class = binascii.hexlify(data[z+4:z+6]).decode("utf-8")
        ttl_res = int(binascii.hexlify(data[z+8:z+10]).decode("utf-8"),16)
        len_res = int(binascii.hexlify(data[z+10:z+12]),16)
        z += 12
        #skip AAAAs
        if(type_server == "001c"):
            z += len_res
            continue
        res_ip = binascii.hexlify(data[z:z+len_res]).decode("utf-8")
        z += len_res
        if(type_server != "001c"):
            break
        if(looped >= Additional_RRs):
            break

    ip_parse = ""
    ip_i = 0
    while (1):
        y = res_ip[ip_i:ip_i + 2]
        x = int((y), 16)
        ip_parse += str(x) + "."
        ip_i += 2
        if (ip_i + 2 > len(res_ip)):
            ip_parse = ip_parse[0:int(len(ip_parse)) - 1]
            break


    return ip_parse
Root_servers = ["198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10",
"192.5.5.241","192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
"193.0.14.129", "199.7.83.42", "202.12.27.33"]
host = sys.argv[1]
address = host
message = message_creator(address)
message = message.replace(" ", "").replace("\n", "")
print("Domain: ", host)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    for i in range(len(Root_servers)):
        start_time = time.time()
        sock.sendto(binascii.unhexlify(message), (Root_servers[i],53))
        sock.settimeout(10)
        try:
            data, _ = sock.recvfrom(4096)
            tld_ip = message_decoder(data)
            total_time = time.time() - start_time  # time in seconds
            total_time = total_time * 1000  # convert time to ms
            print("Root Ip: ", Root_servers[i])
            print("time to root: ", total_time, " ms")
            break
        except:
            print("timeout")
            continue
sock.close()
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    start_time = time.time()
    sock.sendto(binascii.unhexlify(message), (tld_ip,53))
    sock.settimeout(10)
    data, _ = sock.recvfrom(4096)
    aut_ip = message_decoder(data)
    total_time = time.time() - start_time  # time in seconds
    total_time = total_time * 1000  # convert time to ms
    print("TLD IP: ",tld_ip)
    print("time to TLD: ", total_time, " ms")

sock.close()


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    start_time = time.time()
    sock.sendto(binascii.unhexlify(message), (aut_ip,53))
    sock.settimeout(10)
    data, _ = sock.recvfrom(4096)
    http, ttl, times = http_decoder(data)
    total_time = time.time() - start_time  # time in seconds
    total_time = total_time * 1000  # convert time to ms
    print("aut IP: ",aut_ip)
    print("time to aut: ", total_time, " ms")



def csv_checker(ip):
    with open('partcCaches.csv', 'r+') as f:
        temp_csv = []
        writer = csv.writer(f)
        f.seek(0)
        for row in f:
            csv_row = row.strip('\n').split(',')
            for x in range(len(csv_row)):
                if (ip == csv_row[1]):
                    f.close()
                    return True
        return False

# open the file in the write mode
csv_list = []
try:
    with open('partcCaches.csv', 'r', newline='') as f:
        f.close()
except:
    with open('partcCaches.csv', 'w', newline='') as f:
        f.close()

for i in range(len(http)):
    temp_list = [host]
    temp_list.append(http[i])
    temp_list.append(ttl[i])
    temp_list.append(time.time())
    csv_list.append(temp_list)
for i in range(len(csv_list)):
    flag = 0
    flag = csv_checker(csv_list[i][1])
    if(flag == True):
        continue
    else:
        with open('partcCaches.csv', 'a', newline='') as f:
            write_time = time.time()
            writer = csv.writer(f)
            writer.writerow(csv_list[i])
            f.close()


sock.close()
