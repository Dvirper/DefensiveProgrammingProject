import datetime
import sqlite3
import uuid
import os
sql_create_clients_table = """ CREATE TABLE IF NOT EXISTS clients( 
                                ID varchar(16) PRIMARY KEY, 
                                Name varchar(255) , 
                                LastSeen DATETIME ,
                                PublicKey varchar(160),
                                AESkey varchar(16)
                                ); """
sql_create_files_table = """ CREATE TABLE IF NOT EXISTS files( 
                                ID varchar(16), 
                                fileName varchar(255) PRIMARY KEY, 
                                pathName varchar(255) , 
                                cksumValid varchar(1)
                                ); """

def add_null_terminator(str):
    return str + '\0'

class DataBase:
    def __init__(self):
        try:
            self.files_ram_dict = dict()
            ### open folder if doesnt exist
            print("Loading Database...")
            self.connection = sqlite3.connect('server.db')
            self.cursor = self.connection.cursor()
            self.create_data_base()
            sqlite3.register_adapter(uuid.UUID, lambda u: u.bytes)
            os.mkdir('ClientFiles')
        except sqlite3.Error as e:
            print(e)
        except FileExistsError:
            pass

    def create_table(self, create_table_sql):
        try:
            self.cursor.execute(create_table_sql)
            print(self.cursor.fetchall())
        except sqlite3.Error as e:
            print(e)

    def create_data_base(self):
        if self.connection is not None:
            self.create_table(sql_create_clients_table)  # create clients table
            self.create_table(sql_create_files_table)  # create messages table
            self.connection.commit()
        else:
            print("Error! cannot create the database connection.")

    def id_exists_in_the_table(self, id):
        self.cursor.execute("SELECT * FROM clients WHERE ID=?", (id,))
        data=self.cursor.fetchall()
        return True if data else False

    def insert_new_client_to_the_table(self, client_id, name):
        now = datetime.datetime.now()
        name = name + '\0'
        self.cursor.execute("INSERT INTO clients VALUES (?, ?, ?, ?, ?)", (client_id, name, now, None, None))
        self.connection.commit()

    def update_time_for_new_request(self, client_id):
        now = datetime.datetime.now()
        self.cursor.execute("UPDATE clients SET LastSeen=? WHERE ID=?", (now, client_id))
        self.connection.commit()

    def update_public_key_for_client(self, client_id, public_key):
        self.cursor.execute("UPDATE clients SET PublicKey=? WHERE ID=?", (public_key, client_id))
        self.connection.commit()

    def update_aes_key_for_client(self, client_id, aes_key):
        self.cursor.execute("UPDATE clients SET AESKey=? WHERE ID=?", (aes_key, client_id))
        self.connection.commit()

    def insert_new_files_to_the_table(self, client_id, file_name, file_path, valid_cksum):
        self.cursor.execute("INSERT INTO files VALUES (?, ?, ?, ?)",
        (client_id, file_name, file_path, valid_cksum))
        self.connection.commit()

    def __del__(self):
        self.cursor.close()
        self.connection.close()

    def get_aes_key(self, client_id):
        self.cursor.execute(" SELECT AESKey FROM clients WHERE ID=? ", (client_id,))
        result = self.cursor.fetchall()
        if not result:
            print("Error, This User is not registered! Please check if me.info exists on client but db is empty")
            exit()
        return result[0][0]

    def insert_new_file_to_the_table(self, client_id, file_name, file_content):
        file_name = file_name.split(b'\x00')[0].decode()
        self.update_ram_files_table(file_name, file_content)
        path_name = os.path.join('ClientFiles', file_name)

        file_name = add_null_terminator(file_name)
        path_name = add_null_terminator(path_name)
        self.cursor.execute("INSERT or REPLACE INTO files VALUES (?, ?, ?, ?)", (client_id, file_name, path_name, 0))
        self.connection.commit()

    def update_crc_status(self, client_id, file_name, valid=1):
        file_name = add_null_terminator(file_name)
        self.cursor.execute("UPDATE files SET cksumValid=? WHERE ID=? and fileName=?", (valid, client_id, file_name))
        self.connection.commit()
    
    def update_ram_files_table(self, file_name ,file_content):
        if file_name in self.files_ram_dict:
            self.files_ram_dict[file_name] = file_content
        else:
            self.files_ram_dict[file_name] = file_content
            
db = DataBase()

