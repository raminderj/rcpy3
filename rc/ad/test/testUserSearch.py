'''
Created on May 15, 2019

@author: Aaron Kitzmiller <aaron_kitzmiller@harvard.edu>
@copyright: 2019 The Presidents and Fellows of Harvard College. All rights reserved.
@license: GPL v2.0
'''
import os
import unittest
from datetime import datetime

from rc import ad
from rc.ad import user
from rc.filetimes import filetime_to_dt

BINDDN = os.environ.get('BINDDN')
BINDPW = os.environ.get('BINDPW')
if not BINDDN or not BINDPW:
    raise Exception('Must set BINDDN and BINDPW environment variables.')

GOODPW = '2ii2c2Bpi$2co'

NEWUSER = {
    'cn': 'Howdy Doody2',
    'mail': 'ajk@gmail.com',
    'username': 'howdydoody',
    'title': 'BMOC',
    'department': 'love',
    'telephoneNumber': '617-610-8897',
    'expirationDate': datetime(2020, 1, 1),
}


class Test(unittest.TestCase):

    def setUp(self):
        c = ad.Connection(BINDDN, BINDPW)
        for dn in ['CN=%s,OU=_new_accounts,%s' % (NEWUSER['cn'], user.USER_DOMAIN)]:
            try:
                c.delete(dn)
            except Exception:
                pass

    def tearDown(self):
        pass

    def testUserSearch(self):
        c = ad.Connection(BINDDN, BINDPW)
        result = c.search(sAMAccountName=NEWUSER['username'])
        print(result)
        self.assertTrue(len(result) == 0, 'Test user already exists!')
        dn = user.addNewAccount(c, **NEWUSER)
        self.assertTrue(dn == 'CN=%s,%s' % (NEWUSER['cn'], user.NEW_ACCOUNT_OU), 'Returned dn was incorrect: %s' % dn)

        result = c.search(sAMAccountName=NEWUSER['username'])
        self.assertTrue(len(result) == 1, 'Wrong number of results returned %d' % len(result))
        self.assertTrue(result[0][0] == 'CN=%s,%s' % (NEWUSER['cn'], user.NEW_ACCOUNT_OU), 'Wrong dn returned: %s\nShould be %s' % (result[0][0], 'CN=%s,%s' % (NEWUSER['cn'], user.NEW_ACCOUNT_OU)))

        # Check the attrs
        attrs = result[0][1]
        for k in ['mail', 'cn', 'title', 'department', 'telephoneNumber']:
            self.assertTrue(attrs[k][0] == NEWUSER[k], '%s from AD, %s, does not match expected value %s' % (k, attrs[k], NEWUSER[k]))

        # Check the expiration date
        self.assertTrue(attrs['accountExpires'][0] == '132223104000000000', 'Incorrect account expiration: %s' % attrs['accountExpires'][0])

        # Check that password must be reset
        self.assertTrue(attrs['pwdLastSet'][0] == '0', 'Incorrect pwdLastSet value: %s' % attrs['pwdLastSet'][0])

        # Remove the user when done
        user.deleteUser(c, dn)

        result = c.search(sAMAccountName=NEWUSER['username'])
        self.assertTrue(len(result) == 0, 'User was not deleted!')


if __name__ == "__main__":
    unittest.main()
