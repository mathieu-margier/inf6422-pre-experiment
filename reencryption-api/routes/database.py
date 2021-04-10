# Fonctions pour la db
def add_user(c, name, private_key, public_key, signing_key, verifying_key):
    query = "insert into users (FirstName,Public_key,Private_key,Verifying_key,Signing_key) values (?, ?, ?, ?, ?)"
    c.execute(query, (name, public_key, private_key, verifying_key, signing_key))

def add_message(c, number, sender, link, is_message, capsule):
    query = "insert into message (Number, Sender, Link, IsMessage, Capsule) values (?, ?, ?, ?, ?)"
    c.execute(query, (number, sender, link, is_message, capsule))

def add_reenc_key(c, message_number, receiver, reenc_key):
    query = "insert into proxy (MessageNumber, Receiver, ReencKey) values (?, ?, ?)"
    c.execute(query, (message_number, receiver, reenc_key))

def show_table(c, table):
    query = """select * from """ + table
    c.execute(query)
    print(c.fetchall())


def show_element(c, table, colomn, condition):
    query = """select * from """ + table + """ where """ + colomn + """=\'""" + condition +"""\' """
    print(query)
    c.execute(query)
    return c.fetchone()

    ##INITIALISATION DES TABLES


def initialisation_data_base(c):
    ## Dropping Tables
    c.execute("""DROP TABLE users""")
    c.execute("""DROP TABLE message""")
    c.execute("""DROP TABLE proxy""")

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
        Capsule varchar (255))""")

    c.execute("""CREATE TABLE proxy (
        MessageNumber int,
        Receiver varchar(255),
        ReencKey varchar (255))""")


def message_recieved(c, person):
    args = (person,)
    query = """select * from message where Reciever = ? and IsMessage = True"""
    c.execute(query, args)
    print(c.fetchall())


def message_sent(c, person):
    args = (person,)
    query = """select * from message where Sender = ? and IsMessage = True"""
    c.execute(query, args)
    print(c.fetchall())



