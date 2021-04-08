import sqlite3

conn = sqlite3.connect('social_network.db')

c = conn.cursor()


## METHODES

def add_user(name, private_key, public_key):
    args = (name, private_key, public_key)
    query = """insert into users (FirstName,Public_key,Private_key) values (?,?,?)"""
    c.execute(query, args)


def add_message(sender, reciever, link, is_message):
    args = (sender, reciever, link, is_message)
    query = """insert into message values (?,?,?,?)"""
    c.execute(query, args)


def show_table(table):
    query = """select * from """ + table
    c.execute(query)
    print(c.fetchall())


def show_element(table, colomn, condition):
    query = """select * from """ + table + """ where """ + colomn + """=\'""" + condition + """\' """
    c.execute(query)
    print(c.fetchall())


def message_recieved(person):
    args = (person,)
    query = """select * from message where Reciever = ? and IsMessage = True"""
    c.execute(query, args)
    print(c.fetchall())


def message_sent(person):
    args = (person,)
    query = """select * from message where Sender = ? and IsMessage = True"""
    c.execute(query, args)
    print(c.fetchall())

    # INITIALISATION DES TABLES


def initialisation_data_base():
    ## Dropping Tables
    c.execute("""DROP TABLE users""")
    c.execute("""DROP TABLE message""")

    # Creating Tables
    c.execute("""CREATE TABLE users (
        FirstName varchar(255),
        Public_key varchar (255),
        Private_key varchar (255))""")

    c.execute("""CREATE TABLE message (
        Sender varchar(255),
        Reciever varchar (255),
        Link varchar (255),
        IsMessage boolean)""")


c.close()
