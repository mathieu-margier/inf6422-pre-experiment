# Fonctions pour la db
import sqlite3


def add_user(c, name, private_key, public_key, signing_key, verifying_key):
    query = "insert into users (FirstName,Public_key,Private_key,Verifying_key,Signing_key) values (?, ?, ?, ?, ?)"
    c.execute(query, (name, public_key, private_key, verifying_key, signing_key))

def add_message(c, number, sender, link, capsule, is_encrypted):
    query = "insert into message (Number, Sender, Link, IsMessage, Capsule, IsEncrypted) values (?, ?, ?, ?, ?, ?)"
    c.execute(query, (number, sender, link, True, capsule, is_encrypted))

def add_file(c, number, sender, link, key, capsule):
    # TODO Handle not encrypted files
    query = "insert into message (Number, Sender, Link, IsMessage, LinkKey, Capsule, IsEncrypted) values (?, ?, ?, ?, ?, ?, ?)"
    c.execute(query, (number, sender, link, False, key, capsule, True))

def add_reenc_key(c, message_number, receiver, reenc_key):
    query = "insert into proxy (MessageNumber, Receiver, ReencKey) values (?, ?, ?)"
    c.execute(query, (message_number, receiver, reenc_key))

def show_table(c, table):
    query = """select * from """ + table
    c.execute(query)
    print(c.fetchall())


def show_element(c, table, colomn, condition):
    query = """select * from """ + table + """ where """ + colomn + """=\'""" + condition +"""\' """
    c.execute(query)
    return c.fetchone()

def get_proxy_line(c, message_number, receiver):
    query = "select * from proxy where MessageNumber = ? and Receiver = ?"
    c.execute(query, (message_number, receiver))
    return c.fetchone()

def get_content(c, username):
    query = "select Number, Sender, Link, Capsule, IsEncrypted from message where Number IN (select MessageNumber from proxy where Receiver = ?) AND message.IsMessage = True"
    c.execute(query, (username,))
    return c.fetchall()

def get_file(c, username):
    query = "select Number, Sender, Link, LinkKey, Capsule from message where Number IN (select MessageNumber from proxy where Receiver = ?) AND message.IsMessage = False"
    c.execute(query, (username,))
    return c.fetchall()

def get_content_unencrypted(c):
    query = "select * from message where IsEncrypted is FALSE "
    c.execute(query,)
    return c.fetchall()

def get_own_content(c, username):
    query = "select Number, Sender, Link, Capsule, IsEncrypted from message where Sender = ? AND message.IsMessage = True"
    c.execute(query, (username,))
    return c.fetchall()

    ##INITIALISATION DES TABLES


def initialisation_data_base(c):
    ## Dropping Tables
    c.execute("""DROP TABLE IF EXISTS users""")
    c.execute("""DROP TABLE IF EXISTS message""")
    c.execute("""DROP TABLE IF EXISTS proxy""")

    ## Creating Tables
    c.execute("""CREATE TABLE users (
        FirstName varchar(255) NOT NULL,
        Public_key varchar (255) NOT NULL,
        Private_key varchar (255) NOT NULL,
        Verifying_key varchar (255) NOT NULL,
        Signing_key varchar (255) NOT NULL)""")

    c.execute("""CREATE TABLE message (
        Number int NOT NULL,
        Sender varchar(255) NOT NULL,
        Link varchar (255) NOT NULL,
        IsMessage boolean NOT NULL,
        LinkKey varchar (255),
        Capsule varchar (255) NOT NULL,
        IsEncrypted boolean NOT NULL)""")

    c.execute("""CREATE TABLE proxy (
        MessageNumber int NOT NULL,
        Receiver varchar(255) NOT NULL,
        ReencKey varchar (255) NOT NULL )""")
