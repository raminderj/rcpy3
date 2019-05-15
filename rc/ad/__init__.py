import ldap
import os
import sys
import re
import traceback
import ldap.controls
import ldap.filter
import logging

from rc import UserException
from rc.filetimes import dt_to_filetime, utc

ldap.set_option(ldap.OPT_REFERRALS, 0)
# allow a self-signed cert, for now
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
# ldap.set_option(ldap.OPT_X_TLS_NEVER)


DOMAIN_STRING       = 'rc.domain'
USER_DOMAIN         = 'OU=Domain Users,DC=rc,DC=domain'
GLOBAL_DOMAIN       = 'DC=rc,DC=domain'
GROUP_DOMAIN        = 'OU=Domain Groups,DC=rc,DC=domain'
GID_SEARCH_DOMAINS  = [GROUP_DOMAIN, 'OU=Domain Groups,DC=rc,DC=domain']
INSTRUMENT_DOMAIN   = 'OU=Lab_Instruments,OU=Domain Groups,OU=CGR,DC=rc,DC=domain'
AFFILIATIONS_DOMAIN = 'OU=Affiliations,DC=rc,DC=domain'

DEFAULTLDAPPORT = '636'

# Size of pages for paged queries
PAGESIZE = 100

level = logging.INFO
if os.environ.get('AD_DEBUG') is not None:
    level = logging.DEBUG
logging.basicConfig(level=level)
logger = logging.getLogger('portal')

portre = re.compile(r':\d+$')


def readLdapConf(conffile='/etc/ldap.conf'):
    '''
    Returns a dict of entries from the ldap.conf file.
    Values are arrays
    '''
    result = {}
    with open(conffile, 'r') as f:
        for line in f:
            line = line.strip()
            if line == '' or line.startswith('#'):
                continue

            # Stuff up to the first whitespace is key, rest is value
            entry = re.split(r'\s+', line, 1)
            if len(entry) == 2:
                if entry[0] not in result:
                    result[entry[0]] = [entry[1]]
                else:
                    result[entry[0]].append(entry[1])
    return result


class Connection(object):
    '''
    A connection to an AD service
    '''

    def __init__(self, binddn=None, bindpw=None, ldapserver=None):
        '''
        If an ldapserver is not explicitly specified,
        first check the environment variable RCDCS.

        If RCDCS is set, the comma-separated list will be split and
        tried in turn.

        If RCDCS is not set, /etc/ldap.conf will be interrogated for
        the uri field.  If found, the space-separated list will be split
        and the servers tried in turn.
        '''
        RCDCS       = os.environ.get('RCDCS')
        if binddn is None:
            binddn = os.environ.get('BINDDN')
        if bindpw is None:
            bindpw = os.environ.get('BINDPW')
        if binddn is None or bindpw is None:
            raise Exception('binddn and bindpw must be set or the BINDDN and BINDPW environment variables must be defined.')

        errormsg = ''
        self.conn = None

        if ldapserver is None:

            if RCDCS is not None:
                '''
                Use the RCDCS environment variable
                '''
                for ldapserver in RCDCS.split(','):
                    if self.conn is None:
                        try:
                            uriparts = ldapserver.split(':')
                            if len(uriparts) < 3:
                                if 'ldaps' in uriparts[0]:
                                    ldapserver = ldapserver + ':' + DEFAULTLDAPPORT
                            c = ldap.initialize(ldapserver, bytes_mode=False)
                            c.simple_bind_s(binddn, bindpw)
                            self.server = ldapserver
                            self.conn = c
                        except Exception as e:
                            logger.debug('Error using RCDCS environment variable: %s' % str(e))
                            errormsg = errormsg + 'Unable to connect to %s: %s\n' % (ldapserver, str(e))

            else:
                '''
                Read from ldap.conf
                '''
                conf = readLdapConf()
                if 'uri' in conf and len(conf['uri']) > 0 and conf['uri'][0] != '':
                    for ldapserver in re.split(r'\s+', conf['uri'][0]):
                        if self.conn is None:
                            try:
                                if re.search(r':\d+$', ldapserver) is None:
                                    ldapserver = '%s:%s' % (ldapserver, '636')

                                c = ldap.initialize(ldapserver, bytes_mode=False)

                                c.simple_bind_s(binddn, bindpw)
                                self.server = ldapserver
                                self.conn = c
                            except Exception as e:
                                logger.debug('Error reading ldap.conf %s:%s' % (str(e), traceback.format_exc()))
                                errormsg = errormsg + 'Unable to connect to %s: %s\n' % (ldapserver, str(e))

        else:
            '''
            Use the server string passed in
            '''
            try:
                c = ldap.initialize(ldapserver, bytes_mode=False)
                c.simple_bind_s(binddn, bindpw)
                self.server = ldapserver
                self.conn = c
            except Exception as e:
                logger.debug('Error connecting with supplied ldap server: %s' % str(e))
                errormsg = 'Unable to connect to %s: %s\n' % (ldapserver, str(e))

        '''
        If ultimately unsuccessful, raise the collected messages
        '''

        if self.conn is None:
            raise Exception(errormsg)

        self.conn.protocol_version = ldap.VERSION3

    def unbind(self):
        if not self.conn:
            return
        self.conn.unbind_s()

    def search(self, domain=USER_DOMAIN, objectclass='person', **kwargs):
        '''
        Search for something in AD.  None is returned for empty results.

        domain defaults to the user domain (Domain Users) and the objectclass
        defaults to 'person'

        Search terms are key-value pairs, e.g.
            search(mail='akitzmiller@g.harvard.edu')

        There can be multiple specified at once, e.g.
            search(givenName='Aaron',sn='Kitzmiller')

        Person search examples:
            # Email address
            search(mail='akitzmiller@g.harvard.edu')

            # First name, last name
            search(givenName='Aaron',sn='Kitzmiller')

            # Username
            search(sAMAccountName='akitzmiller')

            # Or full user principle name
            search(userPrincipalName='akitzmiller@rc.domain')

            # Distinguished name
            search(distinguishedName='CN=Aaron Kitzmiller,OU=Informatics,OU=RC,DC=rc,DC=domain')

        Group search examples:
            # Get Group by gid
            search(domain=ad.GROUP_DOMAIN,objectclass='Group',gidNumber=10206)
        '''

        filterstr = '(&(objectClass=%s)' % objectclass
        for k, v in kwargs.items():
            filterstr = filterstr + ldap.filter.filter_format('(%s=%s)', [k, str(v)])
        filterstr = filterstr + ')'

        # Setup servercontrol for paging purposes
        lc = ldap.controls.SimplePagedResultsControl(True, size=PAGESIZE, cookie='')
        known_ldap_resp_ctrls = {ldap.controls.SimplePagedResultsControl.controlType: ldap.controls.SimplePagedResultsControl, }

        result = []
        while True:
            msgid = self.conn.search_ext(domain, ldap.SCOPE_SUBTREE, filterstr, None, 0, serverctrls=[lc])
            rtype, rdata, rmsgid, serverctrls = self.conn.result3(msgid, resp_ctrl_classes=known_ldap_resp_ctrls)

            for dn, atts in rdata:
                result.append([dn, atts])

            pctrls = [
                c for c in serverctrls if c.controlType == ldap.controls.SimplePagedResultsControl.controlType
            ]
            if not pctrls:
                print >> sys.stderr, 'Warning: Server ignores RFC 2696 control.'
                break

            # Ok, we did find the page control, yank the cookie from it and
            # insert it into the control for our next search. If however there
            # is no cookie, we are done!
            if pctrls[0].cookie:
                lc.cookie = pctrls[0].cookie
            else:
                break

        return result

    def add(self, dn, attrs):
        '''
        Add the dn to the directory, including attrs
        '''
        self.conn.add_s(dn, attrs)

    def delete(self, dn):
        '''
        Remove the dn from the system
        '''
        try:
            self.conn.delete_s(dn)
        except ldap.NO_SUCH_OBJECT:
            raise UserException('Unable to delete %s.  No such object.' % dn)

    def move(self, dn, ou):
        '''
        Move the dn to ou.
        For example, move CN=John Noos,OU=_new_accounts,OU=RC,OU=Domain Users,DC=rc,DC=domain
        to CN=John Noss,OU=CloudOps,OU=RC,OU=Domain Users,DC=rc,DC=domain
        '''
        elements = dn.split(',')
        if len(elements) < 2:
            raise UserException('%s does not look like a distinguishedName' % dn)
        if not elements[0].upper().startswith('CN='):
            raise UserException('Cannot move %s; It doesn\'t start with a CN' % dn)

        self.conn.rename_s(dn, elements[0], ou)

    def setAttributes(self, dn, **kwargs):
        '''
        Set attributes for a dn.
        Attributes should be in kwargs form.  Value may be a scalar or a list
        '''
        mods = []
        for key, val in kwargs.items():
            if not isinstance(val, list):
                val = [str(val)]
            mods.append((ldap.MOD_REPLACE, key, val))

        self.conn.modify_s(dn, mods)

    def setPassword(self, dn, passwd):

        if not re.match(r'^\".*\"$', passwd):
            passwd = "\"" + passwd + "\""

        password_value = passwd.encode("utf-16-le")

        mod_attrs = [(ldap.MOD_REPLACE, "unicodePwd", [password_value])]

        try:
            self.conn.modify_s(dn, mod_attrs)
        except ldap.UNWILLING_TO_PERFORM:
            raise Exception('Password cannot be set.')

    def setExpirationDate(self, dn, expdate):
        '''
        Set the account expiration to the given date.  expdate should be a datetime.
        '''
        if expdate is None:
            expdate = str(0)
        else:
            expdate = str(dt_to_filetime(expdate.replace(tzinfo=utc)))

        self.setAttributes(dn, accountExpires=str(expdate))

    def requirePasswordReset(self, dn):
        '''
        Ensure that a password must be reset
        '''
        self.setAttributes(dn, pwdLastSet='0')

    def addUsersToGroups(self, userdns, groupdns):
        '''
        Add the given user(s) to the group(s). If they are already in the group, nothing happens.

        userdns and groupdns may be individual string values
        '''
        if isinstance(userdns, str):
            userdns = [userdns]
        if isinstance(groupdns, str):
            groupdns = [groupdns]

        for userdn in userdns:
            for groupdn in groupdns:
                try:
                    self.conn.modify_s(groupdn, [(ldap.MOD_ADD, 'member', userdn.encode('utf-8'))])
                except ldap.ALREADY_EXISTS:
                    pass

    def removeUsersFromGroups(self, userdns, groupdns):
        '''
        Remove the given user(s) from the group(s)

        userdns and groupdns may be individual string values

        If the user is not part of the group, no error is reported.
        '''
        if isinstance(userdns, str):
            userdns = [userdns]
        if isinstance(groupdns, str):
            groupdns = [groupdns]

        for userdn in userdns:
            for groupdn in groupdns:
                try:
                    self.conn.modify_s(groupdn, [(ldap.MOD_DELETE, 'member', userdn.encode('utf-8'))])
                except ldap.UNWILLING_TO_PERFORM:
                    # No error if the user was not originally part of the group
                    pass

    def getMaxUid(self):
        filter = '(&(objectClass=person)(uidNumber>=20000))'
        uids = []
        results = self.conn.search_ext_s(GLOBAL_DOMAIN, ldap.SCOPE_SUBTREE, filter, ['uidNumber'])
        for result in results:
            if 'uidNumber' in result[1]:
                num = int(result[1]['uidNumber'][0])
                if num not in uids:
                        uids.append(num)

        sorteduids = sorted(uids)
        maxuid = 20000
        oldmaxuid = 20000
        for uid in sorteduids:
            oldmaxuid = maxuid
            maxuid = uid
            if maxuid > 20002:
                if maxuid - oldmaxuid > 1:
                    newuid = oldmaxuid + 1
                    while newuid < maxuid:
                        searchresult = self.search(domain=GLOBAL_DOMAIN, uidNumber=str(newuid))
                        if len(searchresult) == 0 or searchresult[0][0] is None:
                            return newuid - 1
                        newuid += 1
        return maxuid

    def getMaxGid(self):
        '''
        Return the current highest gid
        '''
        filter = '(&(gidNumber=*))'
        gids = []
        maxgid = 0
        for domain in GID_SEARCH_DOMAINS:
            results = self.conn.search_ext_s(domain, ldap.SCOPE_SUBTREE, filter, ['gidNumber'])
            for result in results:
                if 'gidNumber' in result[1]:
                    gid = int(result[1]['gidNumber'][0])
                    if gid not in gids:
                        gids.append(gid)
        sortedgids = sorted(gids)
        maxgid = 0
        oldmaxgid = 0
        for gid in sortedgids:
            oldmaxgid = maxgid
            maxgid = gid
            if maxgid > 5000:
                if maxgid - oldmaxgid > 1:
                    newgid = oldmaxgid + 1
                    while newgid < maxgid:
                        searchresult = self.search(domain=GLOBAL_DOMAIN, gidNumber=str(newgid))
                        if len(searchresult) == 0 or searchresult[0][0] is None:
                            return newgid - 1
                        newgid += 1
        return maxgid
