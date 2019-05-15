'''
Test the creation of home directories.

This test requires a local home directory setup that will allow homes to be created without interfering with
actual local users.

The following commands should make things work:

export DEFAULT_HOME_ROOT=/tmp/testmkhomedir
export NCF_HOME_ROOT=/tmp/testncfhomedir

as root:
groupadd -g 9999 testmkhomedir
mkdir /tmp/testmkhomedir/home99
useradd -d /tmp/testmkhomedir/home99/howdydoody -g 9999 howdydoody


@author: Aaron Kitzmiller
@copyright: 2019 The Presidents and Fellows of Harvard College. All rights reserved.
@license: GPL v2.0
@contact: aaron_kitzmiller@harvard.edu
'''
import os
import shutil
import subprocess

from rc import ad
from rc.ad import user
import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest


BINDDN = os.environ.get('BINDDN')
BINDPW = os.environ.get('BINDPW')


NEWUSER = {
    'cn': 'Howdy Doody',
    'mail': 'ajk@gmail.com',
    'username': 'howdydoody',
    'title': 'BMOC',
    'department': 'love',
    'telephoneNumber': '617-610-8897'
}

# NEWUSER uidnumber for the current system
NEWUSERUID = '502'

# A primary group gid that exists on the test system
NEWUSER_GROUP = {
    'name': 'testmkhomedir',
    'gid': 9999
}


GOODPW = '2ii2c2Bpi$2co'

# A primary group that will not support cluster use by itself (ie a lab)
USELESS_GROUP_DN = 'CN=oconnell_lab,OU=CSB,OU=Domain Groups,DC=rc,DC=domain'
USELESS_GID = '34731'


TEMP_HOME = '/tmp/test'

GOOD_HOME = 'home99'
GOOD_SKEL = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'skel')


# logger = logging.getLogger('rc.user')
# logger.addHandler(logging.StreamHandler(sys.stderr))
# logger.setLevel(logging.DEBUG)

if not os.environ.get('DEFAULT_HOME_ROOT'):
    raise Exception('You must set DEFAULT_HOME_ROOT during testing to avoid writing to real home directories. The value cannot be a directory with contents as it is completely removed during testing.')

if not os.environ.get('NCF_HOME_ROOT'):
    raise Exception('You must set NCF_HOME_ROOT during testing to avoid writing to real home directories. The value cannot be a directory with contents as it is completely removed during testing.')

user.NCF_SKELDIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'skel')
user.DEFAULT_SKELDIR = GOOD_SKEL


@unittest.skipUnless(
    os.system('grep "%s:x:%d" < /etc/group > /dev/null' % (NEWUSER_GROUP['name'], NEWUSER_GROUP['gid'])) == 0,
    'Cannot test homedir creation unless the test group (%s:%s) exists.' % (NEWUSER_GROUP['name'], NEWUSER_GROUP['gid'])
)
class Test(unittest.TestCase):

    def createAllTheHomes(self):
        '''
        Creates all possible homes so that a new creation will fail
        '''
        self.dirs = []
        for i in range(user.HOME_DIR_RANGE):
            path = os.path.join(user.DEFAULT_HOME_ROOT, 'home%02d' % i, NEWUSER['username'])
            self.dirs.append(path)
            os.makedirs(path)

    def removeAllTheHomes(self):
        '''
        Removes everything created by createAllTheHomes
        '''
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)

    def setUp(self):
        self.assertTrue(os.system('grep "%s:x:%d" < /etc/group > /dev/null' % (NEWUSER_GROUP['name'], NEWUSER_GROUP['gid'])) == 0, 'Test group does not exist')
        c = ad.Connection(BINDDN, BINDPW)
        c.removeUsersFromGroups('CN=%s,%s' % (NEWUSER['cn'], user.NEW_ACCOUNT_OU), USELESS_GROUP_DN)
        for dn in ['CN=%s,%s' % (NEWUSER['cn'], user.NEW_ACCOUNT_OU)]:
            try:
                c.delete(dn)
            except Exception:
                pass

        if user.DEFAULT_HOME_ROOT is None or user.DEFAULT_HOME_ROOT == '':
            raise Exception('If you unset user.DEFAULT_HOME_ROOT and run this test, you will remove your entire file system.')

        os.system('sudo rm -rf %s > /dev/null' % user.DEFAULT_HOME_ROOT)
        os.system('sudo rm -rf %s > /dev/null' % user.NCF_HOME_ROOT)
        shutil.rmtree(TEMP_HOME, ignore_errors=True)

    def tearDown(self):
        c = ad.Connection(BINDDN, BINDPW)
        for dn in ['CN=%s,%s' % (NEWUSER['cn'], user.NEW_ACCOUNT_OU)]:
            try:
                c.delete(dn)
            except Exception:
                pass

        if user.DEFAULT_HOME_ROOT is None or user.DEFAULT_HOME_ROOT == '':
            raise Exception('If you unset user.DEFAULT_HOME_ROOT and run this test, you will remove your entire file system.')

        os.system('sudo rm -rf %s > /dev/null' % user.DEFAULT_HOME_ROOT)
        os.system('sudo rm -rf %s > /dev/null' % user.NCF_HOME_ROOT)
        shutil.rmtree(TEMP_HOME, ignore_errors=True)

    def testNcfUser(self):
        '''
        Ensure that an NCF user gets created with a correct home directory
        '''

        # Create the user
        c = ad.Connection(BINDDN, BINDPW)
        userdn = user.addNewAccount(c, **NEWUSER)
        self.assertTrue(userdn == 'CN=%s,%s' % (NEWUSER['cn'], user.NEW_ACCOUNT_OU), 'Returned dn was incorrect: %s' % userdn)

        # Initially the default
        result = c.search(distinguishedName=userdn)
        self.assertTrue(result[0][1]['unixHomeDirectory'][0] == user.DEFAULT_UNIX_HOME, 'Incorrect default home dir set: %s' % result[0][1]['unixHomeDirectory'][0])

        user.setPrimaryGroup(c, userdn, groupdn=USELESS_GROUP_DN, gid=USELESS_GID)

        # Don't create the home dir since user is not in cluster users or ncf users
        try:
            user.makeHomedir(c, userdn)
            self.assertTrue(False, 'No exception was thrown though no cluster user group was set.')
        except Exception as e:
            self.assertTrue('Cannot create a home directory for user that is not in one of the cluster user groups' in str(e), 'Error message is incorrect: %s' % str(e))

        # Add the user to the group
        user.addToGroup(c, userdn, user.NCF_USER_GROUP_DN)

        # make the homedir
        user.makeHomedir(c, userdn)

        home = os.path.join(user.NCF_HOME_ROOT, NEWUSER['username'])
        self.assertTrue(os.path.exists(home), 'Home dir not created %s' % home)

    def testPresetHomedir(self):
        '''
        Test for handling old account tool logic in which the home directory is set by the account tool.
        '''
        c = ad.Connection(BINDDN, BINDPW)
        userdn = user.addNewAccount(c, **NEWUSER)
        self.assertTrue(userdn == 'CN=%s,%s' % (NEWUSER['cn'], user.NEW_ACCOUNT_OU), 'Returned dn was incorrect: %s' % userdn)

        result = c.search(distinguishedName=userdn)
        self.assertTrue(result[0][1]['unixHomeDirectory'][0] == user.DEFAULT_UNIX_HOME, 'Incorrect default home dir set: %s' % result[0][1]['unixHomeDirectory'][0])

        # Set unixHomeDirectory to an appropriate value
        home = os.path.join(user.DEFAULT_HOME_ROOT, GOOD_HOME, NEWUSER['username'])
        c.setAttributes(userdn, unixHomeDirectory=home)
        # Set a primary group
        user.setPrimaryGroup(c, userdn, groupdn=USELESS_GROUP_DN, gid=USELESS_GID)
        # Make sure he's in a cluster user group
        user.addToGroup(c, userdn, user.CLUSTER_USERS_GROUP_DNS[0])

        user.makeHomedir(c, userdn)

        # Check that it has the contents of skel and the rsa key
        cmd = "sudo su - %s -c 'cd && ls -l .ssh/id_rsa'" % NEWUSER['username']
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        print(stdout)
        self.assertTrue(p.returncode == 0, 'Attempt to ls public key failed %s' % stderr)
        self.assertTrue(stdout.decode('utf-8').split()[0] == '-rw-------', 'Incorrect result from ls: %s' % stdout.decode('utf-8').split()[0])

    def testMkHomedir(self):
        '''
        Create home directories
        '''
        c = ad.Connection(BINDDN, BINDPW)
        dn = user.addNewAccount(c, **NEWUSER)
        self.assertTrue(dn == 'CN=%s,%s' % (NEWUSER['cn'], user.NEW_ACCOUNT_OU), 'Returned dn was incorrect: %s' % dn)

        result = c.search(distinguishedName=dn)
        self.assertTrue(result[0][1]['unixHomeDirectory'][0] == user.DEFAULT_UNIX_HOME, 'Incorrect default home dir set: %s' % result[0][1]['unixHomeDirectory'][0])
        # Fail because primary group is not set
        try:
            user.makeHomedir(c, dn)
            self.assertTrue(False, 'No exception was thrown though primary group was not set.')
        except Exception as e:
            self.assertTrue('has no primary group set' in str(e), 'Error message is incorrect: %s' % str(e))

        user.setPrimaryGroup(c, dn, groupdn=USELESS_GROUP_DN, gid=USELESS_GID)

        # Don't create the home dir since user is not in cluster users or ncf users
        try:
            user.makeHomedir(c, dn)
            self.assertTrue(False, 'No exception was thrown though no cluster user group was set.')
        except Exception as e:
            self.assertTrue('Cannot create a home directory for user that is not in one of the cluster user groups' in str(e), 'Error message is incorrect: %s' % str(e))

        user.addToGroup(c, dn, user.CLUSTER_USERS_GROUP_DNS[0])

        # Fail to create the directory because it already exists
        self.createAllTheHomes()

        try:
            user.makeHomedir(c, dn)
            self.assertTrue(False, 'No exception was thrown, though dir was already made.')
        except Exception as e:
            self.assertTrue('already exists' in str(e), 'Incorrect error message: %s' % str(e))

        # Make sure it is still the old default after the error
        result = c.search(distinguishedName=dn)
        self.assertTrue(result[0][1]['unixHomeDirectory'][0] == user.DEFAULT_UNIX_HOME, 'Incorrect default home dir set: %s' % result[0][1]['unixHomeDirectory'][0])

        self.removeAllTheHomes()

        # Fail becuase you can't create a dir there
        try:
            user.makeHomedir(c, dn, '/proc/junk/stuff')
            self.assertTrue(False, 'No exception was thrown, though you cannot write to the dir')
        except Exception as e:
            self.assertTrue('No such file or directory' in str(e), 'Incorrect error message: %s' % str(e))

        # Make sure it is still the old default after the error
        result = c.search(distinguishedName=dn)
        self.assertTrue(result[0][1]['unixHomeDirectory'][0] == user.DEFAULT_UNIX_HOME, 'Incorrect default home dir set: %s' % result[0][1]['unixHomeDirectory'][0])

        # Fail because the skel dir doesn't exist
        try:
            user.makeHomedir(c, dn, home=TEMP_HOME, skeldir='/this/doesnot/exist')
            self.assertTrue(False, 'No exception thrown, though the skeldir does not exist.')
        except Exception as e:
            self.assertTrue('No such file or directory' in str(e), 'Incorrect error message: %s' % str(e))

        # Make sure it is still the old default after the error
        result = c.search(distinguishedName=dn)
        self.assertTrue(result[0][1]['unixHomeDirectory'][0] == user.DEFAULT_UNIX_HOME, 'Incorrect default home dir set: %s' % result[0][1]['unixHomeDirectory'][0])

        goodhome = os.path.join(user.DEFAULT_HOME_ROOT, GOOD_HOME, NEWUSER['username'])
        # Set to a usable primary group
        c.removeUsersFromGroups(dn, USELESS_GROUP_DN)
        user.setPrimaryGroup(c, dn, groupdn=USELESS_GROUP_DN, gid=NEWUSER_GROUP['gid'])

        # Set the uidnumber for the user
        c.setAttributes(dn, uidNumber=NEWUSERUID)

        # Make a home dir for real
        user.makeHomedir(c, dn, home=goodhome, skeldir=GOOD_SKEL)

        # Check that it has the contents of skel and the rsa key
        cmd = 'sudo su - %s -c "ls -l ~/.ssh/id_rsa"' % NEWUSER['username']
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        self.assertTrue(p.returncode == 0, 'Attempt to ls public key failed %s' % stderr)
        self.assertTrue(stdout.decode('utf-8').split()[0] == '-rw-------', 'Incorrect result from ls: %s' % stdout.decode('utf-8').split()[0])

        cmd = 'sudo su - %s -c "cat .bashrc"' % NEWUSER['username']
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        self.assertTrue(p.returncode == 0, 'Attempt to ls public key failed %s' % stderr)
        self.assertTrue('new-modules' not in stdout.decode('utf-8'), 'new-modules is in the stdout! : %s' % stdout.decode('utf-8'))


if __name__ == "__main__":
    unittest.main()
