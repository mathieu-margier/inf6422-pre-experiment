# Fonctions pour la db
import sqlite3


def add_user(c, name, private_key, public_key, signing_key, verifying_key):
    query = "insert into users (FirstName,Public_key,Private_key,Verifying_key,Signing_key) values (?, ?, ?, ?, ?)"
    c.execute(query, (name, public_key, private_key, verifying_key, signing_key))

def add_message(c, number, sender, link, is_message, capsule, is_encrypted):
    query = "insert into message (Number, Sender, Link, IsMessage, Capsule, IsEncrypted) values (?, ?, ?, ?, ?, ?)"
    c.execute(query, (number, sender, link, is_message, capsule, is_encrypted))

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
    query = "select * from message where Number IN (select MessageNumber from proxy where Receiver = ?)"
    c.execute(query, (username,))
    return c.fetchall()

def get_content_unencrypted(c):
    query = "select * from message where IsEncrypted is FALSE "
    c.execute(query,)
    return c.fetchall()

def get_own_content(c, username):
    query = "select * from message where Sender = ?"
    c.execute(query, (username,))
    return c.fetchall()

    ##INITIALISATION DES TABLES


def initialisation_data_base(c):
    ## Dropping Tables
    try :
        c.execute("""DROP TABLE users""")
        c.execute("""DROP TABLE message""")
        c.execute("""DROP TABLE proxy""")
    except sqlite3.OperationalError:
        pass

    ## Creating Tables
    c.execute("""CREATE TABLE users (
        FirstName varchar(255),
        Public_key varchar (255),
        Private_key varchar (255),
        Verifying_key varchar (255),
        Signing_key varchar (255))""")

    c.execute("""CREATE TABLE message (
        Number int,
        Sender varchar(255),
        Link varchar (255),
        IsMessage boolean,
        Capsule varchar (255),
        IsEncrypted boolean)""")

    c.execute("""CREATE TABLE proxy (
        MessageNumber int,
        Receiver varchar(255),
        ReencKey varchar (255))""")




