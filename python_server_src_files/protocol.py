
############################## IMPORTS ###################################################3
import struct
import uuid
from database import db
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
import zlib
import socket
import os
############################## CONSTANTS ##################################################
CLIENT_VERSION = 3
SERVER_VERSION = 3
CODE_REQUESTS = {'Registration': 1100, 'Handle Public Key' : 1101, 'Handle File' : 1103, 'Valid CRC' : 1104, 'Invalid CRC 1' : 1105,
    'Invalid CRC 2' : 1106}
CODE_RESPONSE = {'Registration was successful': 2100, 'Registration Failed' : 2021, 'Public key': 2102,
                 'FileRec' : 2103, 'MSG Rec': 2104}

### Requests ###
# In order to calculate file size, We need to deduce the payload amount from request's metadata (size 275)
FILE_REQUEST_HEADER_METADATA = 275

### RESPONSES
EMPTY_PAYLOAD = 0
FILE_RECEIVED_PAYLOAD_RESPONE_SIZE = 279
SUCCESS_REGISTRATION_PAYLOAD_RESPONE_SIZE = 16
SEND_PUBLIC_KEY_PAYLOAD_SIZE = 144
###########################################################################################

def handle_server_tcp_request(sock):
    """
    Handle Server TCP Request, Handles a client request - See CODE_REQUESTS Dictionary
    """
    try:
        data_header = sock.recv(struct.calcsize('<16s B H I'))
    except:
        return
    if not data_header:
        return
    # Parse Request Header
    client_id, srv_version, request_code, payload_size = decode_request(data_header)
    # Receives payload
    data_payload = b''
    sock.settimeout(None)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    content_size = payload_size
    while content_size > 0:
            data_chunk = sock.recv(content_size)
            if not data_chunk:
                break
            content_size -= len(data_chunk)
            data_payload += data_chunk
    # Handle Request by code
    if srv_version != SERVER_VERSION:
        error_response(sock)
        return
    elif request_code == CODE_REQUESTS['Registration']:
        handle_registration(sock, data_payload, client_id)
    elif request_code == CODE_REQUESTS['Handle Public Key']:
        send_public_key(sock, client_id, data_payload)
    elif request_code == CODE_REQUESTS['Handle File']:
        handle_file(sock, client_id, data_payload, payload_size)
    elif request_code == CODE_REQUESTS['Valid CRC']:
        handle_valid_crc_request(sock, client_id, data_payload)
    elif request_code == CODE_REQUESTS['Invalid CRC 1']:
        handle_first_invalid_crc_req(client_id, data_payload)
    elif request_code == CODE_REQUESTS['Invalid CRC 2']:
        handle_second_invalid_crc_req()
    else:
        error_response(sock)
    # Update Last request time for a client.
    db.update_time_for_new_request(client_id)

def handle_file(sock, client_id, data_payload, payload_size):
    ### Parse Data
    file_size = payload_size - FILE_REQUEST_HEADER_METADATA 
    payload_request = struct.unpack(f'<16s I 255s {file_size}s', data_payload)
    file_content = payload_request[3]
    file_name = payload_request[2]
    ### Decrypt File & Calc CRC
    file_content = decrypt_file(client_id, file_content)

    db.insert_new_file_to_the_table(client_id, file_name, file_content)
    save_file_in_server_folder(file_content.decode(), file_name)
    cksum = zlib.crc32(file_content)
    ### Send CRC
    sock.sendall(struct.pack('<B H L', SERVER_VERSION, CODE_RESPONSE['FileRec'], FILE_RECEIVED_PAYLOAD_RESPONE_SIZE))
    sock.sendall(struct.pack('<16s I 255s I', client_id, file_size, file_name, cksum))

def handle_registration(sock, data_payload, client_id):
    ### Parse Data
    payload_request = struct.unpack('<255s', data_payload)
    name = decode_str_hex(payload_request[0])
    ### Check if user already registered, If so send Registeration Failed response (2021)
    if db.id_exists_in_the_table(client_id):
        sock.sendall(struct.pack('<B H L', SERVER_VERSION, CODE_RESPONSE['Registration Failed'], EMPTY_PAYLOAD))
        return
    gen_uuid = uuid.uuid4()
    ### Avoid rare duplicates
    while (db.id_exists_in_the_table(gen_uuid)):
        gen_uuid = uuid.uuid4()
    db.insert_new_client_to_the_table(gen_uuid, name)
    ### Send Sucess registration respone
    sock.sendall(struct.pack('<B H L', SERVER_VERSION, CODE_RESPONSE['Registration was successful'], SUCCESS_REGISTRATION_PAYLOAD_RESPONE_SIZE ))
    sock.sendall(struct.pack('<16s', gen_uuid.bytes))


def encrypt_key(pub_key, aes):
    rsa_pub = RSA.import_key(pub_key)
    cipher = PKCS1_OAEP.new(rsa_pub)
    ciphertext = cipher.encrypt(aes)
    return ciphertext

def decrypt_file(client_id, file_content):
    aes_key = db.get_aes_key(client_id)
    iv = bytearray([0] * AES.block_size)
    chiper = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_content = unpad(chiper.decrypt(file_content), AES.block_size)
    return decrypted_content

def gen_aes_key_and_store_in_db(client_id):
    aes_key = get_random_bytes(16)
    db.update_aes_key_for_client(client_id, aes_key)

def send_public_key(sock, client_id,  data_payload):
    ### Parse Data
    data_struct = struct.unpack('<255s 160s', data_payload)
    public_key = data_struct[1]
    ### Update public key in DB
    db.update_public_key_for_client(client_id, public_key)
    ### Generate AES key and store it in DB
    gen_aes_key_and_store_in_db(client_id)
    ### Encrypt AES key
    aes_key = db.get_aes_key(client_id)
    encrypted_aes = encrypt_key(public_key, aes_key)
    ### Send AES key response
    sock.sendall(struct.pack('<B H L', SERVER_VERSION, CODE_RESPONSE['Public key'], SEND_PUBLIC_KEY_PAYLOAD_SIZE))
    sock.sendall(struct.pack('<16s 128s', client_id, encrypted_aes))

### Basic Request Header decoding and parsing.
def decode_request(data_header):
    header_request = struct.unpack('<16s B H I', data_header)
    client_id = header_request[0]
    srv_version = header_request[1]
    request_code = header_request[2]
    payload_size = header_request[3]
    return client_id, srv_version, request_code, payload_size

def handle_valid_crc_request(sock, client_id, data_payload):
    payload_request = struct.unpack(f'<16s 255s', data_payload)
    file_name = payload_request[1]
    file_name = decode_str_hex(file_name)
    db.update_crc_status(client_id, file_name)
    ### Send Msg Rec response
    sock.sendall(struct.pack('<B H L', SERVER_VERSION, CODE_RESPONSE['MSG Rec'], EMPTY_PAYLOAD))


def handle_first_invalid_crc_req(client_id, data_payload):
    payload_request = struct.unpack(f'<16s 255s', data_payload)
    file_name = payload_request[1]
    file_name = decode_str_hex(file_name)
    db.update_crc_status(client_id, file_name, valid=0)


def handle_second_invalid_crc_req():
    print("invalid CRC Number 2, Client wont be sending again!")

def error_response(sock):
    sock.sendall(struct.pack('<B H L', SERVER_VERSION, CODE_RESPONSE['Registration Error'], EMPTY_PAYLOAD))

def save_file_in_server_folder(file_content, file_name):
    file_name = decode_str_hex(file_name)
    path = os.path.join('ClientFiles', file_name)
    fd = open(path, 'w')
    fd.write(file_content)


def decode_str_hex(str):
    return str.split(b'\x00')[0].decode()