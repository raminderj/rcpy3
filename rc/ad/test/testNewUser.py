'''
Tests for the creation of new users

@author: Aaron Kitzmiller
@copyright: 2019 The Presidents and Fellows of Harvard College. All rights reserved.
@license: GPL v2.0
@contact: aaron_kitzmiller@harvard.edu
'''
import os
import unittest
from datetime import datetime
import copy

from rc import ad
from rc.ad import user
from rc.filetimes import filetime_to_dt

BINDDN = os.environ.get('BINDDN')
BINDPW = os.environ.get('BINDPW')
if not BINDDN or not BINDPW:
    raise Exception('Must set BINDDN and BINDPW environment variables.')

GOODPW = '2ii2c2Bpi$2co'

NEWUSERCLEANCN = 'Howdy Doody2'
NEWUSER = {
    'cn': 'Howdy [Doody]2',
    'mail': 'ajk@gmail.com',
    'username': 'howdydoody',
    'title': 'BMOC',
    'department': 'love',
    'telephoneNumber': '617-610-8897',
    'expirationDate': datetime(2020, 1, 1),
}

EXISTINGUSER = {
    'username': 'akitzmiller'
}

TESTGROUP = {
    'name': 'pearson_lab',
    'distinguishedName': 'CN=pearson_lab,OU=EPS,OU=Domain Groups,DC=rc,DC=domain',
}

NEWLABGROUP = 'doody_lab'
NEWLABGROUPDN = 'CN=%s,OU=EPS,OU=Domain Groups,DC=rc,DC=domain' % NEWLABGROUP
NEWLABGROUPGID = '999999'

NEWLABGROUP_ATTRS = [
    ('name',                [NEWLABGROUP.encode('utf-8')]),
    ('distinguishedName',   [NEWLABGROUPDN.encode('utf-8')]),
    ('sAMAccountName',      [NEWLABGROUP.encode('utf-8')]),
    ('cn',                  [NEWLABGROUP.encode('utf-8')]),
    ('gidNumber',           [NEWLABGROUPGID.encode('utf-8')]),
    ('msSFU30Name',         [NEWLABGROUP.encode('utf-8')]),
    ('msSFU30NisDomain',    [b'rc']),
    ('objectCategory',      [b'CN=Group,CN=Schema,CN=Configuration,DC=rc,DC=domain']),
    ('objectClass',         [b'top', b'group']),
]

NONLABGROUP = 'stuff'
NONLABGROUPDN = 'CN=%s,OU=EPS,OU=Domain Groups,DC=rc,DC=domain' % NONLABGROUP
NONLABGROUPGID = '999998'
NONLABGROUP_ATTRS = [
    ('name',                [NONLABGROUP.encode('utf-8')]),
    ('distinguishedName',   [NONLABGROUPDN.encode('utf-8')]),
    ('sAMAccountName',      [NONLABGROUP.encode('utf-8')]),
    ('cn',                  [NONLABGROUP.encode('utf-8')]),
    ('gidNumber',           [NONLABGROUPGID.encode('utf-8')]),
    ('msSFU30Name',         [NONLABGROUP.encode('utf-8')]),
    ('msSFU30NisDomain',    [b'rc']),
    ('objectCategory',      [b'CN=Group,CN=Schema,CN=Configuration,DC=rc,DC=domain']),
    ('objectClass',         [b'top', b'group']),
]

NEWPI = {
    'cn': 'Dr Doody',
    'mail': 'ajk2@gmail.com',
    'username': 'drdoody',
    'title': 'Big Dealio',
    'department': 'love',
    'telephoneNumber': '617-610-8898',
}


class Test(unittest.TestCase):

    def setUp(self):
        c = ad.Connection(BINDDN, BINDPW)
        for dn in ['CN=%s,OU=EPS,%s' % (NEWUSERCLEANCN, user.USER_DOMAIN), 'CN=%s,%s' % (NEWUSERCLEANCN, user.NEW_ACCOUNT_OU), 'CN=%s,%s' % (NEWPI['cn'], user.NEW_ACCOUNT_OU), NEWLABGROUPDN, NONLABGROUPDN]:
            try:
                c.delete(dn)
            except Exception:
                pass

    def tearDown(self):
        pass

    def testAddUser(self):
        '''
        Create and remove a new user
        '''

        c = ad.Connection(BINDDN, BINDPW)
        result = c.search(sAMAccountName=NEWUSER['username'])
        self.assertTrue(len(result) == 0, 'Test user already exists!')
        dn = user.addNewAccount(c, **NEWUSER)
        self.assertTrue(dn == 'CN=%s,%s' % (NEWUSERCLEANCN, user.NEW_ACCOUNT_OU), 'Returned dn was incorrect: %s' % dn)

        result = c.search(sAMAccountName=NEWUSER['username'])
        self.assertTrue(len(result) == 1, 'Wrong number of results returned %d' % len(result))
        self.assertTrue(result[0][0] == 'CN=%s,%s' % (NEWUSERCLEANCN, user.NEW_ACCOUNT_OU), 'Wrong dn returned: %s\nShould be %s' % (result[0][0], 'CN=%s,%s' % (NEWUSERCLEANCN, user.NEW_ACCOUNT_OU)))

        # Check the attrs
        attrs = result[0][1]
        for k in ['mail', 'title', 'department', 'telephoneNumber']:
            self.assertTrue(attrs[k][0] == NEWUSER[k], '%s from AD, %s, does not match expected value %s' % (k, attrs[k], NEWUSER[k]))
        self.assertTrue(attrs['cn'][0] == NEWUSERCLEANCN, 'Incorrect cn: %s, should be %s' % (attrs['cn'][0], NEWUSERCLEANCN))

        # Check the expiration date
        self.assertTrue(attrs['accountExpires'][0] == '132223104000000000', 'Incorrect account expiration: %s' % attrs['accountExpires'][0])

        # Check that password must be reset
        self.assertTrue(attrs['pwdLastSet'][0] == '0', 'Incorrect pwdLastSet value: %s' % attrs['pwdLastSet'][0])

        # Remove the user when done
        user.deleteUser(c, dn)

        result = c.search(sAMAccountName=NEWUSER['username'])
        self.assertTrue(len(result) == 0, 'User was not deleted!')

    def testAddUserToGroup(self):
        '''
        Add an existing user to a group.  Remove them from a group.
        '''
        c = ad.Connection(BINDDN, BINDPW)

        # Make sure the user isn't in the group to begin with
        user.removeFromGroup(c, EXISTINGUSER['username'], TESTGROUP['name'])
        result = c.search(sAMAccountName=EXISTINGUSER['username'])
        self.assertTrue(TESTGROUP['distinguishedName'] not in result[0][1]['memberOf'], 'Cannot seem to remove the group!?!?')

        user.addToGroup(c, EXISTINGUSER['username'], TESTGROUP['name'])

        result = c.search(sAMAccountName=EXISTINGUSER['username'])
        self.assertTrue(TESTGROUP['distinguishedName'] in result[0][1]['memberOf'], 'User %s should be a member of group %s, but is not.' % (EXISTINGUSER['username'], TESTGROUP['name']))
        user.removeFromGroup(c, EXISTINGUSER['username'], TESTGROUP['name'])

    def testEnableNewUser(self):
        '''
        Enable user from _new_accounts
        '''
        c = ad.Connection(BINDDN, BINDPW)
        userdn = user.addNewAccount(c, **NEWUSER)
        result = c.search(distinguishedName=userdn)
        self.assertTrue(result[0][0] == userdn, 'Retrieved wrong user')
        self.assertTrue(result[0][1]['userAccountControl'][0] == '514', 'Initial account control incorrect')
        self.assertTrue(user.NEW_ACCOUNT_OU in result[0][0], 'User not in new account OU?!?!?')

        # Got to set a password before you can enable
        c.setPassword(userdn, GOODPW)

        newou = 'OU=EPS,%s' % user.USER_DOMAIN
        user.enableNewUser(c, userdn, newou)
        result = c.search(sAMAccountName=NEWUSER['username'])
        self.assertTrue(result[0][1]['userAccountControl'][0] == '512', 'User did not get enabled')
        newdn = 'CN=%s,%s' % (NEWUSERCLEANCN, newou)
        self.assertTrue(result[0][0] == newdn, 'User dn is %s, but should be %s' % (result[0][0], newdn))

        try:
            c2 = ad.Connection(newdn, 'wrongpassword')
            self.asserTrue(False, 'Was able to connect with incorrect password')
        except Exception:
            pass

        c2 = ad.Connection(newdn, GOODPW)
        self.assertTrue(c2 is not None, 'What the?')

        user.deleteUser(c, newdn)

    def testSetExpirationDate(self):
        '''
        Set a user's expiration date.
        '''
        c = ad.Connection(BINDDN, BINDPW)

        # Create new user with specified expiration date
        LOCALUSER = copy.deepcopy(NEWUSER)
        userdn = user.addNewAccount(c, **LOCALUSER)
        user.setPrimaryGroup(c, userdn)
        result = c.search(distinguishedName=userdn)
        expdate = result[0][1]['accountExpires'][0]
        self.assertTrue(expdate == '132223104000000000', 'Incorrect expdate %s' % expdate)

        # Unexpire it
        user.setExpirationDate(c, userdn, expdate=None)
        result = c.search(distinguishedName=userdn)
        expdate = result[0][1]['accountExpires'][0]
        expdatetime = filetime_to_dt(int(expdate))
        self.assertTrue(expdatetime.year == 1601, 'Incorrect expiration date year %s' % str(expdatetime.year))

        user.deleteUser(c, userdn)

        # Set to never expire by not setting expiration date when adding
        del LOCALUSER['expirationDate']
        userdn = user.addNewAccount(c, **LOCALUSER)
        user.setPrimaryGroup(c, userdn)
        result = c.search(distinguishedName=userdn)
        expdate = result[0][1]['accountExpires'][0]
        expdatetime = filetime_to_dt(int(expdate))
        self.assertTrue(expdatetime.year == 1601, 'Incorrect expiration date year %s' % str(expdatetime.year))
        user.deleteUser(c, userdn)

    def testNoPasswordReset(self):
        '''
        Create user that does not need a password reset.
        '''
        c = ad.Connection(BINDDN, BINDPW)

        # Create new user with specified expiration date
        LOCALUSER = copy.deepcopy(NEWUSER)
        LOCALUSER['requirePasswordReset'] = False

        userdn = user.addNewAccount(c, **LOCALUSER)
        result = c.search(distinguishedName=userdn)
        pwdlastset = result[0][1]['pwdLastSet'][0]
        self.assertTrue(pwdlastset != '0', 'Incorrect pwdlastset %s' % str(pwdlastset))

    def testSetPrimaryGroup(self):
        '''
        Set a user's primary group.
        '''
        c = ad.Connection(BINDDN, BINDPW)

        # Create a new user and set his primary group to the default
        userdn = user.addNewAccount(c, **NEWUSER)
        user.setPrimaryGroup(c, userdn)
        result = c.search(distinguishedName=userdn)
        self.assertTrue(result[0][1]['gidNumber'][0] == user.DEFAULT_PRIMARY_GROUP_ID, 'User gidNumber should be %s, but it is %s' % (user.DEFAULT_PRIMARY_GROUP_ID, result[0][1]['gidNumber'][0]))

        # Add groups
        c.add(NEWLABGROUPDN, NEWLABGROUP_ATTRS)
        result = c.search(distinguishedName=NEWLABGROUPDN, domain=ad.GROUP_DOMAIN, objectclass='Group')
        self.assertTrue(result[0][0] == NEWLABGROUPDN, 'Error retrieving new lab group %s' % NEWLABGROUPDN)

        # Add the PI and set to the lab group PI
        pidn = user.addNewAccount(c, **NEWPI)
        result = c.search(distinguishedName=pidn)
        self.assertTrue(result[0][0] == pidn, 'Error retrieving new pi.')

        c.addUsersToGroups(pidn, NEWLABGROUPDN)
        c.setAttributes(NEWLABGROUPDN, managedBy=pidn)
        result = c.search(distinguishedName=pidn)

        # Set the primary group using the specified groupdn and gidnumber
        user.setPrimaryGroup(c, userdn, groupdn=NEWLABGROUPDN, gid=NEWLABGROUPGID)
        result = c.search(distinguishedName=userdn)
        self.assertTrue(result[0][1]['gidNumber'][0] == NEWLABGROUPGID, 'gidNumber should be %s, but it is %s' % (NEWLABGROUPGID, result[0][1]['gidNumber'][0]))
        self.assertTrue(result[0][1]['memberOf'][0] == NEWLABGROUPDN, 'Lab group membership is not correct: %s' % ','.join(result[0][1]['memberOf']))

        # Delete user and set primaryGroup via PI with multiple groups
        c.delete(userdn)
        userdn = user.addNewAccount(c, **NEWUSER)

        c.add(NONLABGROUPDN, NONLABGROUP_ATTRS)
        result = c.search(distinguishedName=NONLABGROUPDN, domain=ad.GROUP_DOMAIN, objectclass='Group')
        self.assertTrue(result[0][0] == NONLABGROUPDN, 'Error retrieving new lab group %s' % NONLABGROUPDN)
        c.setAttributes(NONLABGROUPDN, managedBy=pidn)
        result = c.search(distinguishedName=pidn)
        self.assertTrue(len(result[0][1]['managedObjects']) == 2, 'PI is not managing the right objects: %s' % ','.join(result[0][1]['managedObjects']))

        user.setPrimaryGroup(c, userdn, pidn)
        result = c.search(distinguishedName=userdn)
        self.assertTrue(result[0][1]['gidNumber'][0] == NEWLABGROUPGID, 'gidNumber should be %s, but it is %s' % (NEWLABGROUPGID, result[0][1]['gidNumber'][0]))
        self.assertTrue(result[0][1]['memberOf'][0] == NEWLABGROUPDN, 'Lab group membership is not correct: %s' % ','.join(result[0][1]['memberOf']))

        c.delete(userdn)
        c.delete(pidn)
        c.delete(NEWLABGROUPDN)
        c.delete(NONLABGROUPDN)


if __name__ == "__main__":
    unittest.main()
