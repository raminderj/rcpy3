'''
Test connection to AD and some searches of users and groups

@author: Aaron Kitzmiller
@copyright: 2019 The Presidents and Fellows of Harvard College. All rights reserved.
@license: GPL v2.0
@contact: aaron_kitzmiller@harvard.edu
'''
import os
from rc import ad
import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest


# binddn and pw
BINDDN          = os.environ.get('BINDDN')
BINDPW          = os.environ.get('BINDPW')
if not BINDDN or not BINDPW:
    raise Exception('Must set BINDDN and BINDPW environment variables.')

# Non existent server for bad connecitons
BADSERVER       = 'ldaps://junk.rc.fas.harvard.edu:3269'

# Normal query server
GOODSERVER      = 'ldaps://dc02.rc.domain:3269'

# Server for modifications
MODSERVER       = 'ldaps://dc02.rc.domain:636'

# User that will not be found
BADUSERDN       = 'CN=nobody,OU=Informatics,OU=RC,OU=Domain Users,DC=rc,DC=domain'

# User that will be found
GOODUSERDN      = 'CN=akitzmiller,OU=Informatics,OU=RC,OU=Domain Users,DC=rc,DC=domain'
GOODUSERNAME    = 'akitzmiller'

NOTADOMAIN      = 'DC=junk,DC=thing'

GOODGROUPDN     = 'CN=rc_admin,OU=RC,OU=Domain Groups,DC=rc,DC=domain'
GOODGID         = '40273'
BADGID          = '9'

DESCRIPTION     = 'Senior Research Computing Associate'
MODDESCRIPTION  = 'stuff'
PHONE           = '339-368-0656'
MODPHONE        = 'junk'

ADDGROUPDN      = 'CN=aspuru-guzik_lab,OU=CCB,OU=Domain Groups,DC=rc,DC=domain'

# Group that is larger than PAGESIZE
LARGEGROUPDN    = 'CN=cluster_users,OU=SEER,OU=Domain Groups,DC=rc,DC=domain'


class Test(unittest.TestCase):

    def setUp(self):
        self.rcdcs = os.environ.get('RCDCS')
        if 'RCDCS' in os.environ:
            del os.environ['RCDCS']

    def tearDown(self):
        if self.rcdcs is not None:
            os.environ['RCDCS'] = self.rcdcs
        else:
            if 'RCDCS' in os.environ:
                del os.environ['RCDCS']

    @unittest.skipUnless(os.path.exists('/etc/ldap.conf'), 'Cannot test /etc/ldap.conf reading if you do not have one.')
    def testLdapConf(self):
        '''
        Test connecting via ldap.conf
        '''
        self.assertTrue(ad.Connection(BINDDN, BINDPW) is not None, 'Connection failed.')

    def testServerParameter(self):
        '''
        Pass in a parameter
        '''
        try:
            ad.Connection(BINDDN, BINDPW, BADSERVER)
            self.assertTrue(False, 'Connection was created with a bad server')
        except Exception:
            pass

        self.assertTrue(ad.Connection(BINDDN, BINDPW, GOODSERVER) is not None, 'Connection failed.')

    def testServerEnv(self):
        '''
        Server list from environment.  First one will fail, but second should connect
        '''
        os.environ['RCDCS'] = ','.join([BADSERVER, GOODSERVER])
        c = ad.Connection(BINDDN, BINDPW)
        self.assertTrue(c is not None, 'Connection failed')
        self.assertTrue(GOODSERVER in c.server, 'Server is %s' % c.server)

    def testUserSearch(self):
        '''
        Test search for users (ie default objectClass and search domain)
        '''
        c = ad.Connection(BINDDN, BINDPW, GOODSERVER)
        userdata = c.search(distinguishedName=GOODUSERDN)
        self.assertTrue(len(userdata) == 1, 'Incorrect number of users returned: %d' % len(userdata))
        self.assertTrue(userdata[0][0] == GOODUSERDN, 'Incorrect DN returned from search: %s' % userdata[0][0])

        userdata = c.search(distinguishedName=BADUSERDN)
        self.assertTrue(len(userdata) == 0, 'User data returned for bad user!')

        try:
            userdata = c.search(distinguishedName=GOODUSERDN, domain=NOTADOMAIN)
            self.assertTrue(False, 'Result was returned for bad domain')
        except Exception:
            pass

        userdata = c.search(sAMAccountName=GOODUSERNAME)
        self.assertTrue(len(userdata) == 1, 'Wrong number of results returned: %d' % len(userdata))
        self.assertTrue(userdata[0][0] == GOODUSERDN, 'Wrong user returned: %s' % userdata[0][0])
        self.assertTrue(userdata[0][1]['sAMAccountName'][0] == bytes(GOODUSERNAME.encode('utf-8')), 'Wrong username returned: %s' % userdata[0][1]['sAMAccountName'])

    def testGroupSearch(self):
        '''
        Use the search functionality to find a group
        '''
        c = ad.Connection(BINDDN, BINDPW, GOODSERVER)
        groupdata = c.search(domain=ad.GROUP_DOMAIN, objectclass='Group', gidNumber=GOODGID)
        self.assertTrue(len(groupdata) == 1, 'Wrong number of group search results: %d' % len(groupdata))
        self.assertTrue(groupdata[0][0] == GOODGROUPDN, 'Incorrect group dn returned: %s' % groupdata[0][0])

        groupdata = c.search(domain=ad.GROUP_DOMAIN, objectclass='Group', gidNumber=BADGID)
        self.assertTrue(len(groupdata) == 0, 'Wrong number of group search results: %d' % len(groupdata))

    def testAddToGroup(self):
        '''
        Test adding and removing a user from a group
        '''
        c = ad.Connection(BINDDN, BINDPW, MODSERVER)
        [user] = c.search(distinguishedName=GOODUSERDN)
        self.assertTrue(user[0] == GOODUSERDN, 'User search failed')
        for g in user[1]['memberOf']:
            print(g)
        self.assertTrue(bytes(ADDGROUPDN.encode('utf-8')) not in user[1]['memberOf'], 'Group %s found in group list\n' % ADDGROUPDN)

        # Add user to group
        c.addUsersToGroups(GOODUSERDN, ADDGROUPDN)
        [user] = c.search(distinguishedName=GOODUSERDN)
        self.assertTrue(user[0] == GOODUSERDN, 'User search failed')
        self.assertTrue(bytes(ADDGROUPDN.encode('utf-8')) in user[1]['memberOf'], 'Group %s found in group list\n' % ADDGROUPDN)

        # Remove user from group
        c.removeUsersFromGroups(GOODUSERDN, ADDGROUPDN)
        [user] = c.search(distinguishedName=GOODUSERDN)
        self.assertTrue(user[0] == GOODUSERDN, 'User search failed')
        self.assertTrue(bytes(ADDGROUPDN.encode('utf-8')) not in user[1]['memberOf'], 'Group %s found in group list\n' % ADDGROUPDN)

    def testLargeGroupSearch(self):
        '''
        Get users for a group that is larger than page size
        '''

        c = ad.Connection(BINDDN, BINDPW, GOODSERVER)
        users = c.search(memberOf=LARGEGROUPDN)
        self.assertTrue(len(users) > ad.PAGESIZE, 'Group %s has %d members, but should have more than %d' % (LARGEGROUPDN, len(users), ad.PAGESIZE))
        for user in users:
            self.assertTrue(bytes(LARGEGROUPDN.encode('utf-8')) in user[1]['memberOf'], 'User %s is was erroneously returned in search of %s' % (user[0], LARGEGROUPDN))


if __name__ == "__main__":
    unittest.main()
