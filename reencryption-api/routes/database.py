# Fonctions pour la db
def add_user(c, name, private_key, public_key, signing_key, verifying_key):
    query = "insert into users (FirstName,Public_key,Private_key,Verifying_key,Signing_key) values (?, ?, ?, ?, ?)"
    c.execute(query, (name, public_key, private_key, verifying_key, signing_key))

def add_message(c, number, sender, link, capsule):
    query = "insert into message (Number, Sender, Link, IsMessage, Capsule) values (?, ?, ?, ?, ?)"
    c.execute(query, (number, sender, link, True, capsule))

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
    query = "select Number, Sender, Link, Capsule from message where Number IN (select MessageNumber from proxy where Receiver = ?)"
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
        Capsule varchar (255) NOT NULL)""")

    c.execute("""CREATE TABLE proxy (
        MessageNumber int NOT NULL,
        Receiver varchar(255) NOT NULL,
        ReencKey varchar (255) NOT NULL )""")


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
