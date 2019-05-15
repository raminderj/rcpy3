'''
rc.ad.user

Set of functions for setting up and manipulating users in AD

@author: Aaron Kitzmiller
@copyright: 2016 The Presidents and Fellows of Harvard College. All rights reserved.
@license: GPL v2.0
@contact: aaron_kitzmiller@harvard.edu
'''

import os
import re
import shutil
import traceback
import errno
import subprocess
import logging
import unicodedata
import ldap.filter

from random import randrange

from rc import UserException, ad

# Standard domains
NEW_ACCOUNT_OU              = os.environ.get('NEW_ACCOUNT_OU',      'OU=_new_accounts,OU=Domain Users,DC=rc,DC=domain')
APPROVED_ACCOUNT_OU         = os.environ.get('APPROVED_ACCOUNT_OU', 'OU=_approved_accounts,OU=Domain Users,DC=rc,DC=domain')
GLOBAL_DOMAIN               = os.environ.get('GLOBAL_DOMAIN',       'DC=rc,DC=domain')
GROUP_DOMAIN                = os.environ.get('GROUP_DOMAIN',        'OU=Domain Groups,DC=rc,DC=domain')
DISABLED_GROUP_DOMAIN       = os.environ.get('DISABLED_GROUP_DOMAIN', 'OU=Archived Objects,DC=rc,DC=domain')
USER_DOMAIN                 = os.environ.get('USER_DOMAIN',         'OU=Domain Users,DC=rc,DC=domain')
GROUP_OBJECT_CATEGORY       = os.environ.get('GROUP_OBJECT_CATEGORY', 'CN=Group,CN=Schema,CN=Configuration,DC=rc,DC=domain')

# Default DN and gid for new users
DEFAULT_PRIMARY_GROUP_DN    = os.environ.get('DEFAULT_PRIMARY_GROUP_DN', 'CN=non_cluster_users,OU=Affiliation Groups,OU=Domain Groups,DC=rc,DC=domain')
DEFAULT_PRIMARY_GROUP_ID    = os.environ.get('DEFAULT_PRIMARY_GROUP_ID', '403124')

# Default nis domain for cluster users
DEFAULT_NIS_DOMAIN          = os.environ.get('DEFAULT_NIS_DOMAIN', 'rc')

# Default login shell.  All new users get this.
DEFAULT_LOGIN_SHELL         = os.environ.get('DEFAULT_LOGIN_SHELL', '/bin/bash')

# Default unix home.  All new users get this.
DEFAULT_UNIX_HOME           = os.environ.get('DEFAULT_UNIX_HOME', '/dev/null')

# Required attributes for all new accounts
REQUIREDATTRS               = ['cn', 'username', 'mail', 'department', 'telephoneNumber', 'title']

# Cluster users groups
CLUSTER_USERS_GROUP_DNS     = ['CN=cluster_users_2,OU=SEER,OU=Domain Groups,DC=rc,DC=domain', 'CN=cluster_users,OU=SEER,OU=Domain Groups,DC=rc,DC=domain']

# Default mode for home directories
DEFAULT_HOMEDIR_MODE        = 0o700

# Default skeleton dir
DEFAULT_SKELDIR             = os.environ.get('DEFAULT_SKELDIR', '/etc/skel')

# Root of home directories
DEFAULT_HOME_ROOT           = os.environ.get('DEFAULT_HOME_ROOT', '/n')

# Shared scratch dir
DEFAULT_SHARED_SCRATCH      = os.environ.get('DEFAULT_SHARED_SCRATCH', '/n/scratchlfs')

# Range of home directores- 00-HOME_DIR_RANGE
HOME_DIR_RANGE              = int(os.environ.get('HOME_DIR_RANGE', 14))

# Group membership indicates an NCF user
NCF_USER_GROUP_DN           = os.environ.get('NCF_USER_GROUP_DN', 'CN=ncf_users,OU=NCF,OU=Domain Groups,DC=rc,DC=domain')

# Root of NCF home directories
NCF_HOME_ROOT               = os.environ.get('NCF_HOME_ROOT', '/users')

# Skeleton dir for NCF accounts
NCF_SKELDIR                 = os.environ.get('NCF_SKELDIR', '/users/default-profile')

# DN for hepl group
HEPL_DN = 'CN=hepl,OU=Physics,OU=Domain Groups,DC=rc,DC=domain'
HEPL_GID = 20030

# DN for hetg group
HETG_DN = 'CN=hetg,OU=Physics,OU=Domain Groups,DC=rc,DC=domain'
HETG_GID = 34737


logger = logging.getLogger('rc.user')


def cleanADName(name):
    '''
    strips and normalizes first name, last name, cn, etc. so that they can be used in a DN (and other places)
    '''
    name = name.strip().replace('[', '').replace(']', '')  # Needed for HarvardKey nicknames
    return unicodedata.normalize('NFKD', name).encode('ascii', 'ignore').decode('utf-8')


def addNewAccount(conn, **kwargs):
    '''
    Add a new account to AD.  keyword args must include cn, username, mail, department
    A list of groups (by sAMAAccountName), title, unix home, etc. may also be included.
    Returns the DN of the new account
    '''

    # Check required fields
    for key in REQUIREDATTRS:
        if key not in kwargs or kwargs[key] is None or kwargs[key].strip() == '':
            raise UserException('Required field %s missing.  New accounts must have %s.' % (key, ','.join(REQUIREDATTRS)))

    # Pop the requireds.  Everything else will be added as is
    # cn, first name and last name (see below) are popped, stripped, unicoded, then normalized.
    cn          = cleanADName(kwargs.pop('cn'))
    username    = cleanADName(kwargs.pop('username'))  # python ldap doesn't like unicode here
    mail        = cleanADName(kwargs.pop('mail'))
    department  = ldap.filter.filter_format('%s', [str(kwargs.pop('department').strip())])
    phone       = cleanADName(kwargs.pop('telephoneNumber'))
    title       = str(kwargs.pop('title').strip())

    # Get first name, last name.  There may only be a first name.
    names = re.split(r'\s+', cn, 1)
    firstname = lastname = ''
    if len(names) > 1:
        firstname = names[0]
        lastname = names[1]
    else:
        lastname = names[0]

    # If givenName and sn are defined, use those:
    if 'givenName' in kwargs:
        firstname = cleanADName(kwargs.pop('givenName'))
    if 'sn' in kwargs:
        lastname = cleanADName(kwargs.pop('sn'))

    # Does the email address exist in the system?
    result = conn.search(mail=mail)
    if len(result) > 0:
        raise UserException('Email %s already exists in the system for user %s.' % (mail, result[0][0]))

    # Does the username exist in the system?
    result = conn.search(sAMAccountName=username)
    if len(result) > 0:
        raise UserException('Username %s already exists in the system for user %s' % (username, result[0][0]))

    # Non alphanumerics in username is a no-no
    if re.search(r'[^A-Za-z0-9]', username) is not None:
        raise UserException('Username may only contain A-Za-z0-9')

    # No numbers in names for some reason?
#    if re.search(r'\d',cn) is not None:
#        raise UserException('cn (common name) cannot contain numbers')

    OU = NEW_ACCOUNT_OU
    if 'ou' in kwargs.keys():
        OU = kwargs.pop('ou').strip()

    # The dn of our new entry/object
    dn = 'CN=%s,%s' % (cn, OU)

    # Set displayname
    displayname = ' '.join(names)

    # Set the uidnumber
    uidnumber = str(getNextUid(conn) + 1)

    upn = '%s@%s' % (username, ad.DOMAIN_STRING)

    dept = department[:63]

    attrs = [
        ('objectclass', [b'top', b'person', b'organizationalperson', b'user']),
        ('userPrincipalName', [upn.encode('utf-8')]),
        ('uid', [username.encode('utf-8')]),
        ('uidNumber', [uidnumber.encode('utf-8')]),
        ('distinguishedName', [dn.encode('utf-8')]),
        ('sAMAccountName', [username.encode('utf-8')]),
        ('displayName', [displayname.encode('utf-8')]),
        ('mail', [mail.encode('utf-8')]),
        ('telephoneNumber', [phone.encode('utf-8')]),
        ('title', [title.encode('utf-8')]),
        ('description', [title.encode('utf-8')]),
        ('department', [dept.encode('utf-8')]),
        ('loginShell', [DEFAULT_LOGIN_SHELL.encode('utf-8')]),
        ('unixHomeDirectory', [DEFAULT_UNIX_HOME.encode('utf-8')]),
        ('msSFU30NisDomain', [b'<none>']),
        ('msSFU30Name', [username.encode('utf-8')]),
        ('ou', [OU.encode('utf-8')]),
        ('userAccountControl', [b'514']),
        ('pwdLastSet', [b'-1']),
    ]

    if firstname != '':
        givenName = ldap.filter.filter_format('%s', [firstname])
        attrs.append(('givenName', [givenName.encode('utf-8')]))

    if lastname != '':
        sn = ldap.filter.filter_format('%s', [lastname])
        attrs.append(('sn', [sn.encode('utf-8')]))

    # Add all remaining attributes as is
    # If one of the kwargs is 'password', set it.
    # Also hang on to the expiration date
    password = None
    expirationdate = None
    requirepasswordreset = True

    for k, v in kwargs.items():
        if not isinstance(v, list):
            if isinstance(v, str):
                v = v.encode('utf-8')
            v = [v]
        if k == 'password':
            password = ldap.filter.filter_format('%s', [v[0]])
        elif k == 'expirationDate':
            expirationdate = v[0]
        elif k == 'requirePasswordReset':
            if not v[0]:
                requirepasswordreset = False
        else:
            attrs.append((k, v))

    # Add the user
    try:
        conn.add(dn, attrs)
    except Exception as e:
        logger.exception(e)
        if 'desc' in e and 'Already exists' in e['desc']:
            raise Exception('User %s %s with email %s already exists' % (cn, username, mail))
        else:
            raise

    # If there are any failures at this point, remove the account if possible
    try:
        # Set password
        if password is not None:
            conn.setPassword(dn, password)

        # Set expiration date
        if expirationdate is not None:
            setExpirationDate(conn, dn, expirationdate)

        # Require password reset
        if requirepasswordreset:
            requirePasswordReset(conn, dn)

    except Exception as e:
        logger.error('Account removed due to error after creating account for %s: %s\n%s' % (dn, str(e), traceback.format_exc()))
        conn.delete(dn)
        raise e

    return dn


def usernameToDn(conn, username):
    '''
    Get the Distinguished Name associated with a username
    '''
    result = conn.search(sAMAccountName=username)
    if len(result) == 0:
        raise UserException('Unable to find user with username %s' % username)
    if len(result) > 1:
        raise UserException('Multiple accounts with username %s' % username)
    return result[0][0]


def groupnameToDn(conn, groupname):
    '''
    Get the Distinguished Name (CN=schrag_lab,OU=EPS,OU=Domain Groups,DC=rc,DC=domain)
    for a group name (e.g. schrag_lab)
    '''
    result = conn.search(domain=ad.GROUP_DOMAIN, objectclass='Group', sAMAccountName=groupname)
    if len(result) == 0:
        result = conn.search(domain=ad.AFFILIATIONS_DOMAIN, objectclass='Group', sAMAccountName=groupname)
    if len(result) == 0:
        result = conn.search(domain=ad.GROUP_DOMAIN, objectclass='Group', cn=groupname)
    if len(result) == 0:
        result = conn.search(domain=ad.GROUP_DOMAIN, objectclass='Group', name=groupname)
    if len(result) == 0:
        raise UserException('Unable to find group with name %s' % groupname)
    if len(result) > 1:
        raise UserException('Multiple groups with name %s' % groupname)

    return result[0][0]


def addToInstrumentGroup(conn, user, group):
    '''
    This is because the instrument groups are not under Domain Groups
    '''
    groupdn = group
    if not groupdn.upper().startswith('CN='):
        result = conn.search(domain=ad.INSTRUMENT_DOMAIN, objectclass='Group', sAMAccountName=group)
        if len(result) == 0:
            raise UserException('Unable to find group with name %s' % group)

        groupdn = result[0][0].decode('utf-8')

    addToGroup(conn, user, groupdn)


def addToGroup(conn, user, group):
    '''
    Add to an AD group.  User or group can either be in the form of a DN or a username (sAMAccountName).
    For the latter case, Domain Users is assumed.
    '''
    userdn = user
    if not userdn.upper().startswith('CN='):
        userdn = usernameToDn(conn, user)

    groupdn = group
    if not groupdn.upper().startswith('CN='):
        groupdn = groupnameToDn(conn, group)

    conn.addUsersToGroups(userdn, groupdn)


def removeFromGroup(conn, user, group):
    '''
    Remove a user from a group.  User or group can be either a DN or a username (sAMAccountName)
    '''
    userdn = user
    if not userdn.upper().startswith('CN='):
        userdn = usernameToDn(conn, user)

    groupdn = group
    if not groupdn.upper().startswith('CN='):
        groupdn = groupnameToDn(conn, group)

    conn.removeUsersFromGroups(userdn, groupdn)


def getManagedGroups(conn, user):
    '''
    Get the groups this user manages. user may be DN or username.
    Array of dn,attrs is returned for each group
    '''
    groupdata = []
    result = []
    if user.upper().startswith('CN='):
        result = conn.search(distinguishedName=user)
    else:
        result = conn.search(sAMAccountName=user)

    if len(result) == 0:
        raise UserException('Unable to find user %s' % user)
    if len(result) > 1:
        raise UserException('Multiple users retrieved when searching with %s' % user)

    if 'managedObjects' in result[0][1]:
        for groupdn in result[0][1]['managedObjects']:
            groupdata = groupdata + conn.search(domain=ad.GROUP_DOMAIN, objectclass='Group', distinguishedName=groupdn.decode('utf-8'))

    return groupdata


def getPiLabGroups(conn, pi):
    '''
    Returns the lab group(s) of the PI, if any.
    A list of groupdn,gid,sAMAccountName tuples is returned if there are matches, None if not.
    If there is only one group that the Pi manages, that is returned.  Otherwise, it must have _lab in the name.
    This handles some legacy _users groups.
    '''
    groups = getManagedGroups(conn, pi)

    if len(groups) == 1:
        return [(groups[0][0], groups[0][1]['gidNumber'][0].decode('utf-8'), groups[0][1]['cn'][0].decode('utf-8'))]
    elif len(groups) > 1:
        result = []
        for group in groups:
            if '_lab' in group[1]['cn'][0].decode('utf-8').lower():
                if 'gidNumber' not in group[1]:
                    raise Exception('Group %s does not have a gidNumber' % group[1]['cn'][0].decode('utf-8'))
                result.append((group[0], group[1]['gidNumber'][0].decode('utf-8'), group[1]['cn'][0].decode('utf-8')))
        return result
    else:
        return None


def setPrimaryGroup(conn, user, pi=None, groupdn=None, gid=None):
    '''
    For the given cluster user, set the primary group.  nis domain (msSFU30NisDomain) is also set to DEFAULT_NIS_DOMAIN

    If groupdn and gid are set, those will be used directly.

    If pi is set, then we search for a managedObject associated with the PI.
    If multiple managedObjects are found, the one with _lab in it will be used.

    If neither pi nor groupdn/gid are set, the DEFAULT_PRIMARY_GROUP_DN and
    DEFAULT_PRIMARY_GROUP_GID will be used.
    '''

    pgroupdn  = ''
    pgroupgid = ''

    userdn = user
    if not userdn.upper().startswith('CN='):
        userdn = usernameToDn(conn, user)

    # If they are explicit, use them
    if groupdn is not None and gid is not None:
        pgroupdn = groupdn
        pgroupgid = str(gid)

    # If the PI is defined, get her managedObjects.
    # If there is only 1, use it.
    # If there are multiple, pick the one that says _lab
    # If there are multiple _labs, give up
    elif pi is not None:
        pidn = pi
        if not pidn.upper().startswith('CN='):
            pidn = usernameToDn(conn, pi)

        pidata = conn.search(distinguishedName=pidn)
        if pidata is None or len(pidata) == 0 or len(pidata[0]) == 0:
            raise Exception('Unable to locate PI %s' % pidn)

        # Special processing for hepl
        if 'memberOf' in pidata[0][1] and HEPL_DN in pidata[0][1]['memberOf']:
            pgroupdn = HEPL_DN
            pgroupgid = HEPL_GID
        # Special processing for hetg
        elif 'memberOf' in pidata[0][1] and HETG_DN in pidata[0][1]['memberOf']:
            pgroupdn = HETG_DN
            pgroupgid = HETG_GID
        else:
            pigroups = getPiLabGroups(conn, pidn)
            if pigroups is None:
                raise UserException('PI %s does not manage any groups.' % pi)
            if len(pigroups) > 1:
                raise UserException('PI %s manages multiple labs and I cannot figure out which one you want. Run setPrimaryGroup with the desired groupdn and gid.' % pi)
            pgroupdn = pigroups[0][0]
            pgroupgid = pigroups[0][1]

    else:
        pgroupdn  = DEFAULT_PRIMARY_GROUP_DN
        pgroupgid = DEFAULT_PRIMARY_GROUP_ID


# Not sure what this Claire Reardon stuff is about
#         if user_dn == 'cn=%s,%s' % ('Claire Reardon', NEW_ACCOUNT_OU):
#             gidNumber = '402738'
#             group_dn = 'CN=external_users,OU=External,OU=Domain Groups,DC=rc,DC=domain'

    conn.setAttributes(userdn, msSFU30NisDomain=[DEFAULT_NIS_DOMAIN.encode('utf-8')], gidNumber=[pgroupgid.encode('utf-8')])
    conn.addUsersToGroups(userdn, pgroupdn)

    return (pgroupgid, pgroupdn)


def makeHomedir(conn, user, home=None, skeldir=None):
    '''
    Pick out an appropriate home directory and make it.  Has to be run from sa01.
    Can be either a username or a DN.

    Exceptions are thrown if
      - the specified user doesn't exist
      - the home directory that is selected already exists, an
      - the user has no uidNumber or gidNumber attribute
      - the user does not exist on the current system or has no group name
      - the user is not part of one of the cluster user groups (CLUSTER_USERS_GROUP_DNS)
      - any of the shell commands (copy the skel dir, chown the new home, create the ssh key) fails

    If any of the home directory setup steps fails, any partial directory creation is cleaned up and the
    old home value (i.e. /dev/null) is restored to the AD attribute
    '''

    # Find the user
    userdn = user
    if not userdn.upper().startswith('CN='):
        userdn = usernameToDn(conn, user)
    userdata = conn.search(distinguishedName=userdn)
    if len(userdata) < 1:
        raise UserException('User %s does not exist in the system' % user)

    username = userdata[0][1]['sAMAccountName'][0].decode('utf-8')

    # Make sure she has a uidNumber and gidNumber
    if 'uidNumber' not in userdata[0][1] or len(userdata[0][1]['uidNumber']) == 0:
        raise UserException('User %s has no uid set.' % userdn)
    uid = int(userdata[0][1]['uidNumber'][0].decode('utf-8'))

    if 'gidNumber' not in userdata[0][1] or len(userdata[0][1]['gidNumber']) == 0:
        raise UserException('User %s has no primary group set.' % userdn)
    gid = int(userdata[0][1]['gidNumber'][0].decode('utf-8'))

    # Get the group name from the username.  Needed later for chowning.
    groupname = getUnixUserPrimaryGroup(username)

    oldhome = userdata[0][1]['unixHomeDirectory'][0].decode('utf-8')

    # If home and skeldir are not explicitly set, either 1) use the homedir set in the attribute (if it's not /dev/null (DEFAULT_UNIX_HOME)
    # or 2) generate a new one
    if home is None and skeldir is None:

        if oldhome != DEFAULT_UNIX_HOME:
            # Must have been set by another process.  We'll let it stand.
            home = oldhome
        else:
            home = generateHomedirPath(username, [m.decode('utf-8') for m in userdata[0][1]['memberOf']])

        # If it's an NCF user
        if NCF_USER_GROUP_DN in [m.decode('utf-8') for m in userdata[0][1]['memberOf']]:
            skeldir = NCF_SKELDIR
        else:
            skeldir = DEFAULT_SKELDIR

    # Set the new home directory
    setHomedirAttribute(conn, userdn, home)

    # Flag used by the exception handler to determine if the newly create dir should be removed.
    removehome = False

    # Create the home directory
    try:
        # Bail if it already exists
        if os.path.exists(home):
            raise Exception('Home directory %s already exists.' % home)

        removehome = True

        initHomedir(home, username, groupname, skeldir)

        # Setup the ssh key
        setupSshKey(username, home)

    except Exception as e:
        # If directory creation fails, set back to the old one.
        conn.setAttributes(userdn, unixHomeDirectory=[oldhome.encode('utf-8')])
        if removehome and os.path.exists(home):
            shutil.rmtree(home, ignore_errors=True)

        raise e


def generateHomedirPath(username, groups):
    '''
    Create a homedir path with a combination of the username and the listing of groups
    from the 'memberOf' list.

    If the user is part of a cluster user group, then DEFAULT_HOME_ROOT will be used along with
    the random homedir between home00-homeHOME_DIR_RANGE and the username

    If the user is an NCF user, the NCF_HOME_ROOT will be used.

    If the user is not NCF or in a cluster user group, an Exception will be thrown.
    '''
    isclusteruser = False
    for cudn in CLUSTER_USERS_GROUP_DNS:
        if cudn in groups:
            isclusteruser = True

    # If it's an NCF user
    if NCF_USER_GROUP_DN in groups:
        return generateNcfHomedirPath(username)
    elif isclusteruser:
        return generateOdysseyHomedirPath(username)
    else:
        raise UserException('Cannot create a home directory for user that is not in one of the cluster user groups such as %s' % ' or '.join(CLUSTER_USERS_GROUP_DNS))


def generateNcfHomedirPath(username):
    '''
    Make an Ncf Homedir
    '''
    return os.path.join(NCF_HOME_ROOT, username)


def generateOdysseyHomedirPath(username):
    '''
    Make an Odyssey homedir path
    '''
    return os.path.join(DEFAULT_HOME_ROOT, 'home%02d' % randrange(HOME_DIR_RANGE), username)


def getUnixUserPrimaryGroup(username):
    '''
    For a username get the primary group name.

    The 'id' Linux command is currently used.
    '''
    # Refresh the cache to make sure all is right

    cmd = 'sss_cache -U'
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    cmd = 'id -gn %s' % username
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if p.returncode != 0:
        raise Exception('Failed to get the users groupname %s' % stderr)
    groupname = stdout.decode('utf-8').strip()
    return groupname


def getUnixUserPrimaryGid(username):
    '''
    For a username get the primary group name.

    The 'id' Linux command is currently used.
    '''
    cmd = 'id -g %s' % username
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if p.returncode != 0:
        raise Exception('Failed to get the users gid %s' % stderr)
    gid = stdout.strip()
    return gid


def setHomedirAttribute(conn, user, home):
    '''
    Set the home dir attribute for the user
    '''
    # Find the user
    userdn = user
    if not userdn.upper().startswith('CN='):
        userdn = usernameToDn(conn, user)
    conn.setAttributes(userdn, unixHomeDirectory=[home.encode('utf-8')])


def initHomedir(home, username, groupname, skeldir=None):
    '''
    Creates an initial home directory, copies skeleton if defined and makes a .ssh dir.

    Chowns the dir to the specified username:groupname
    '''

    if os.system('id %s > /dev/null' % username) != 0:
        raise Exception('User %s does not exist' % username)

    if skeldir:
        shutil.copytree(skeldir, home)
    else:
        os.makedirs(home)

    os.chmod(home, DEFAULT_HOMEDIR_MODE)

    # Create the .ssh dir
    os.makedirs(os.path.join(home, '.ssh'), 0o700)
    logger.debug('Made %s' % os.path.join(home, '.ssh'))

    # Chown the contents to the user
    # This is run as a sudo command only for the sake of testing
    cmd = 'sudo chown -R %s:%s %s' % (username, groupname, home)
    logger.debug('Running cmd %s' % cmd)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    logger.debug('Cmd returns %d. %s' % (p.returncode, stderr))

    if p.returncode != 0:
        raise UserException('chown of homedir failed: %s\n%s' % (' '.join(cmd), stderr))


def setupSshKey(username, home):
    '''
    Create an ssh key for a user using ssh-keygen.

    Also appends key to authorized_keys
    '''

    # Create public key
    cmd = "sudo su - %s -c \"ssh-keygen -qN '' -t rsa -f %s\"" % (username, os.path.join(home, '.ssh', 'id_rsa'))
    logger.debug('Running cmd %s' % cmd)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    logger.debug('Cmd returns %d. %s' % (p.returncode, stderr))

    if p.returncode != 0:
        raise UserException('Creation of public key failed: %s\n%s' % (' '.join(cmd), stderr))

    # Add key to authorized keys
    cmd = 'sudo su - %s -c "cat %s >> %s"' % (username, os.path.join(home, '.ssh', 'id_rsa.pub'), os.path.join(home, '.ssh', 'authorized_keys'))
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    if p.returncode != 0:
        raise UserException('Copying public key to authorized_keys failed: %s\n%s' % (' '.join(cmd), stderr))


def enableUser(conn, user):
    '''
    Enable a previously disabled user by setting userAccountControl to 512.
    User must be a DN or username.
    '''
    userdn = user
    if not user.upper().startswith('CN='):
        userdn = usernameToDn(conn, user)

    conn.setAttributes(userdn, userAccountControl=[b'512'])


def enableNewUser(conn, userdn, ou):
    '''
    Activate a user that is in the _new_accounts OU by moving to the specified OU and
    calling enableUser
    '''
    if not userdn.upper().startswith('CN=') or NEW_ACCOUNT_OU.upper() not in userdn.upper():
        raise UserException('Cannot enable %s.  Must specify a distinguished name that starts with CN= and includes the NEW_ACCOUNT_OU' % userdn)

    enableUser(conn, userdn)
    conn.move(userdn, ou)


def setExpirationDate(conn, user, expdate=None):
    '''
    Set the expiration date of a user using a python datetime.  If date is set to None, then it is set to
    never expire
    '''
    userdn = user
    if not userdn.upper().startswith('CN='):
        userdn = usernameToDn(conn, user)

    conn.setExpirationDate(userdn, expdate)


def deleteUser(conn, user):
    '''
    Remove a user from AD.
    '''
    userdn = user
    if not userdn.upper().startswith('CN='):
        userdn = usernameToDn(conn, userdn)
    conn.delete(userdn)


def moveUser(conn, userdn, newou):
    '''
    Move a user from one OU to another.  User must be a full DN.
    '''
    pass


def requirePasswordReset(conn, user):
    '''
    Require password reset.  User may be a username (assuming Domain Users) or a full DN.
    '''
    userdn = user
    if not userdn.upper().startswith('CN='):
        userdn = usernameToDn(conn, user)

    conn.requirePasswordReset(userdn)


def getNextUid(conn):
    return conn.getMaxUid()


def getNextGid(conn):
    return conn.getMaxGid()


def searchUser(conn, user, includeDisabled=False):
    '''
    Search for a user
    '''
    userdn = user
    if not userdn.upper().startswith('CN='):
        userdn = usernameToDn(conn, user)

    # Include only non-disabled users unless flagged
    result = []
    for u in conn.search(userdn):

        useracctctl = 514
        try:
            useracctctl = int(u[1]['userAccountControl'][0])
        except Exception:
            pass

        if useracctctl & 2 == 0 or includeDisabled:
            result.append(u)

    return result


def makeLabDirs(username, dirname=None):
    '''
    Create the lab directories for the given PI username.

    By default the directory name is the PI users primary group
    '''
    dirs = {}
    groupname = getUnixUserPrimaryGroup(username)
    if dirname is None:
        dirname = groupname

    dirs['shared_scratch'] = os.path.join(DEFAULT_SHARED_SCRATCH, dirname)

    for key, path in dirs.items():
        try:
            os.makedirs(path)

            # Chown the contents to the user
            # This is run as a sudo command only for the sake of testing
            cmd = 'sudo chown -R %s:%s %s; chmod 2770 %s' % (username, groupname, path, path)
            logger.debug('Running cmd %s' % cmd)
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            logger.debug('Cmd returns %d. %s' % (p.returncode, stderr))

            if p.returncode != 0:
                raise UserException('chown of homedir failed: %s\n%s' % (' '.join(cmd), stderr))

        except OSError as exc:
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                # If it already exists, skip it
                pass
            else:
                raise


def makePiLabGroupName(conn, piusername):
    '''
    Uses the pi username to get PI data and construct the lab group name
    '''
    # Get the pidn for the managedBy attribute
    pidata = searchUser(conn, piusername)
    if pidata is None:
        raise Exception('Cannot find account for PI %s' % piusername)

    # Lab name is lower case last name_lab or can be passed as a parameter
    # Gotta convert to unicode, then normalize
    lastname = pidata[0][1]['sn'][0].decode('utf-8')
    lastname = re.sub(r'[ \-,]+', '_', lastname)
    labname = '%s_lab' % unicodedata.normalize('NFKD', lastname.lower()).encode('ascii', 'ignore')

    return labname


def createLabGroup(conn, **kwargs):
    '''
    Create a lab group from the given parameters.  For example.

    createLabGroup(
        piusername='aizenberg',
        department='CCB',
        description='Joanna Aizenberg - SEAS Faculty',
    )

    Uses piusername to create the group cn and set the managedBy attribute

    gidNumber is optional.  If not provided, one will be generated.
    '''

    errors = []
    for required in ['piusername', 'department']:
        if required not in kwargs or kwargs[required] is None or kwargs[required].strip() == '':
            errors.append('parameter %s is required to create a lab group.' % required)
    if len(errors) > 0:
        raise Exception('Cannot create lab group: %s' % ' '.join(errors))

    piusername = kwargs['piusername'].strip()
    pidn = usernameToDn(conn, piusername)

    department = str(kwargs['department'].strip())
    description = kwargs.get('description', '').encode('utf8')

    if 'groupdn' in kwargs and kwargs['groupdn'] is not None and kwargs['groupdn'].strip() != '':
        groupdn = kwargs['groupdn'].strip()
        cn = groupdn.split(',')[0].strip()
        labname = cn[3:]  # Remove CN=
        # If the group already exists, use that gidnumber

    else:
        labname = makePiLabGroupName(conn, piusername)

        # DN is group dn + department code + labname
        OU = ','.join(['OU=%s' % department, GROUP_DOMAIN])
        if 'ou' in kwargs and kwargs['ou'] is not None and kwargs['ou'].strip() != '':
            OU = kwargs['ou'].strip()

        # The dn of our new entry/object
        groupdn = str('CN=%s,%s' % (labname, OU))

        # If this exists, or the "DISABLED" version exists, fail
        gs = conn.search(domain=GROUP_DOMAIN, sAMAccountName=labname)
        if gs:
            raise Exception('Lab group %s already exists' % labname)
        gs = conn.search(domain=DISABLED_GROUP_DOMAIN, sAMAccountName='DISABLED-%s' % labname)
        if gs:
            raise Exception('Lab group DISABLED=%s already exists' % labname)

    # Get a gidnumber
    gidnumber = str(getNextGid(conn) + 1)

    attrs = [
        ('objectclass', [b'top', b'group']),
        ('distinguishedName', [groupdn.encode('utf-8')]),
        ('sAMAccountName', [labname.encode('utf-8')]),
        ('description', [description.encode('utf-8')]),
        ('msSFU30NisDomain', [b'rc']),
        ('msSFU30Name', [labname.encode('utf-8')]),
        ('managedBy', [pidn.encode('utf-8')]),
        ('gidNumber', [gidnumber.encode('utf-8')]),
    ]
    conn.add(groupdn, attrs)
    return (groupdn, gidnumber)


def hasGroups(conn, dn, groups):
    '''
    Returns true if the user has all of the groups in the groups list.
    Groups may be one or more common names or distinguishedNames.
    '''
    if isinstance(groups, str):
        groups = [groups]

    userdn = dn
    user = []
    if not dn.lower().startswith('cn='):
        user = conn.search(sAMAccountName=userdn)
    else:
        user = conn.search(distinguishedName=userdn)

    if not user or len(user[0]) == 0 or 'memberOf' not in user[0][1]:
        return False

    memberGroupsCns = [g.split(',')[0].replace('CN=', '') for g in user[0][1]['memberOf']]
    for group in groups:
        if group.startswith('CN=') and group not in user[0][1]['memberOf']:
            return False
        elif not group.startswith('CN=') and group not in memberGroupsCns:
            return False
        else:
            continue

    return True
