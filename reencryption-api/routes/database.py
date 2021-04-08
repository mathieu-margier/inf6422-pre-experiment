# Fonctions pour la db
def add_user(c, name, private_key, public_key):
    query = "insert into users (FirstName,Public_key,Private_key) values (?, ?, ?)"
    c.execute(query, (name, public_key, private_key))


def add_message(c, sender, reciever, link, is_message):
    query = """insert into message values (\'""" + sender + """\',\'""" + reciever + """\',\'""" + link + """\',""" + str(
        is_message) + """) """
    c.execute(query)


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

    ## Creating Tables
    c.execute("""CREATE TABLE users (
        FirstName varchar(255),
        Public_key varchar (255),
        Private_key varchar (255))""")

    c.execute("""CREATE TABLE message (
        Sender varchar(255),
        Reciever varchar (255),
        Link varchar (255),
        IsMessage boolean)""")


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



