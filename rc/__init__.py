'''
Some general purpose stuff
'''

__version__ = '0.1.1'


class UserException(Exception):
    '''
    Exceptions for known user errors
    '''

    def __init__(self, message):
        super(UserException, self).__init__(message)
        self.user_msg = message
