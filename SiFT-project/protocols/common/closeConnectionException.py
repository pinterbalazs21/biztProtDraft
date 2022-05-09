'''
Use instead of manually closing connection
Server/Client on upper levels should catch it and close the connections,
while middle level should always throw it further
'''


class CloseConnectionException(Exception):
    pass
