#!/usr/bin/env python
"""
__author__ = "Emanuel Zelic"
__version__ = "1.01"
__email__ = "emanuel@plus.hr"
__status__ = "Development"
"""
# TODO: Napisi configtest funkcionalnost

import smtplib
import subprocess
import shlex
import ConfigParser
import logging
import time
import yaml

import commands
import dns.resolver as resolver

try:
    from email.MIMEText import MIMEText
except:
    from email.mime.text import MIMEText


class Server(object):
    # account
    LIST_SUSPENDED = 'whmapi1 listsuspended'
    LIST_RESELLERS = 'whmapi1 listresellers'
    LIST_ACCOUNTS = 'whmapi1 listaccts'
    LIST_ACC_DOMAINS = 'uapi --user=USER DomainInfo list_domains'
    LIST_DOMAIN_DATA = 'whmapi1 domainuserdata domain=DOMAIN'

    # bandwidth
    GET_BW_DATA = 'whmapi1 showbw'
    SET_BW_DATA = 'whmapi1 limitbw'

    # e-mail
    GET_USER_MAILS = 'whmapi1 list_pops_for user=USER'
    GET_MAIL_DISK_USAGE = 'uapi --user=USERNAME Email get_disk_usage user=USER domain=DOMAIN'

    #LVE
    LVEINFO = 'lveinfo -j --show-all --user=USER --period=PERIOD'
    LVECHART = 'lvechart --user=USER --period=PERIOD --show-all --format=png --output=USER-7d.png'


    def __init__(self):
        # configuration parameters
        self.server_conf = self._read_config(self.__class__.__name__)
        self.logfile = self.server_conf.get('Server', 'logfile')
        self.report_mail = self.server_conf.get('Server', 'reportMail')

        # runtime variables
        self.hostname = commands.getoutput('hostname')
        self.logger = self.set_logger(self.logfile, mode='a')


    @staticmethod
    def _read_config(conf):
        configfile = 'includes/' + conf + '.conf'
        config = ConfigParser.ConfigParser()
        config.readfp(open(configfile))

        return config

    @staticmethod
    def set_logger(logname, formatter='%(asctime)s - %(levelname)s - %(message)s', mode='a'):
        """
        Sets file handler for log file
        :return: log file handler
        """
        logger = logging.getLogger(logname)
        logger.setLevel(logging.INFO)

        fh = logging.FileHandler(logname, mode=mode)
        formatter = logging.Formatter(formatter)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        return logger

    def resolve(self, domain, dns_type):
        """
        Get DNS resolving results depending on the dns_type

        Arguments:
            domain: domain to query
            dns_type: type of DNS entry to query

        Results:
            There are three possible queries and result formats
            A: query data is returned
            list(tuple): list of tuples for every MX record and its resolving IP address
            list(tuple): list of tuples for every NS record and its resolving IP address
            False: No record found
        """
        try:
            answ = resolver.query(domain, dns_type)
        except:
            return False

        records = []
        for rdata in answ:
            if dns_type == 'A':
                records.append(str(rdata))
            elif dns_type == 'MX':
                if rdata:
                    mx_record = str(rdata).split()[1].strip('.')
                    a_record_mx = self.resolve(mx_record, 'A')
                    if a_record_mx:
                        records.append((mx_record, a_record_mx))
            elif dns_type == 'NS':
                if rdata:
                    ns_record = str(rdata).strip('.')
                    a_record_ns = self.resolve(ns_record, 'A')
                    if a_record_ns:
                        records.append((ns_record, a_record_ns[0]))
            elif dns_type == 'TXT':
                if rdata:
                    records.append(str(rdata))

        if len(records) > 0:
            return records
        else:
            return False

    def get_suspended_user_data(self):
        """
        populates suspended_user_data dictionary with suspended user data

        Returns:
            dict: {users: {details}}
        """
        try:
            data = yaml.load(self.exec_cpanel_api_command(Server.LIST_SUSPENDED))
        except:
            print ("Error loading yaml data from %s command output (Is dry run set to 1?)" % Server.LIST_SUSPENDED)
            data = ''

        suspended_users_data = {}

        if isinstance(data, dict):
            for account in data['data']['account']:
                owner = account['owner']
                user = account['user']
                reason = account['reason']
                suspendtime = account['time']
                try:
                    unixtime = float(account['unixtime'])
                except:
                    unixtime = 0
                period = round((time.time() - unixtime) / 3600 / 24, 0)

                suspended_users_data.setdefault(user, {'owner': owner})
                suspended_users_data[user]['reason'] = reason
                suspended_users_data[user]['suspendtime'] = suspendtime
                suspended_users_data[user]['unixtime'] = unixtime
                suspended_users_data[user]['suspendperiod'] = period

            return suspended_users_data
        else:
            return 0

    def get_resellers(self):
        """
        Method for getting a list of reseller packages on the server

        Returns:
            list: List of resellers
        """

        data = yaml.load(self.exec_cpanel_api_command(Server.LIST_RESELLERS))

        if data:
            return data['data']['reseller']
        else:
            return False

    def get_acc_details(self, search='', searchtype='owner'):
        """
        Get a dictionary of account properties for every account on the server matching
        the optional search word and searchtype
        If no search and searchtype parameters are provided, all accounts are returned

        Arguments (optional):
            search: PCRE to filter the results
            searchtype: information to query (domain, owner, user, IP, package)

        Returns:
            dict: {user: acc_details}

        """

        cmd = Server.LIST_ACCOUNTS + ' search=%s searchtype=%s' % (search, searchtype)
        data = yaml.load(self.exec_cpanel_api_command(cmd))

        if 'data' in data.keys():
            return data['data']['acct']
        else:
            return False

    def get_owners_user_details(self, search='', searchtype='owner'):
        """
        Get a dictionary of account properties for every account on the server matching
        the optional search word and searchtype, sorted in order {owner: {user: data}}
        If no search and searchtype parameters are provided, all accounts are returned

        Arguments (optional):
            search: PCRE to filter the results
            searchtype: information to query (domain, owner, user, IP, package)

        Returns:
            dict: dictionary with keys 'main_domain', 'addon_domains', 'parked_domains', 'sub_domains'
        """

        data = self.get_acc_details(search, searchtype)

        owners_users = {}

        for acc_details in data:
            owner = acc_details['owner']
            user = acc_details['user']

            owners_users.setdefault(owner, {})[user] = acc_details

        return owners_users

    def get_account_domains(self, user):
        """
        Argument:
            user: cPanel username

        Returns:
            dict: dictionary with keys 'main_domain', 'addon_domains', 'parked_domains', 'sub_domains'
        """

        cmd = Server.LIST_ACC_DOMAINS.replace('USER', user)
        data = yaml.load(self.exec_cpanel_api_command(cmd))

        if data:
            return data['result']['data']
        else:
            return False

    def get_account_domain_list(self, subdomains=False, owners_users_data=False):
        """
        Returns a list of user domains (sub domains excluded)

        note: try to use only when you don't call get.owners_user-details() method inside  your script, so you avoid
            calling this method twice
            (this is now fixed with 'owners_users_data' argument definition)
        :return:
            dict: {users_keys: [domain_list]}
        """

        users_domains = {}
        domain_types = ['addon_domains', 'parked_domains']
        if subdomains:
            domain_types.append('sub_domains')

        if not owners_users_data:
            owners_users_data = self.get_owners_user_details()

        for owner in owners_users_data.keys():
            for user in owners_users_data[owner].keys():
                user_domains = self.get_account_domains(user)
                domain_list = [user_domains['main_domain']]
                for domain_type in domain_types:
                    domain_list.extend(user_domains[domain_type])

                users_domains[user] = domain_list

        return users_domains

    def get_domain_data(self, domain):
        """
        Returns data for any domain configured on the server
        :param domain:
        :return
        """
        cmd = Server.LIST_DOMAIN_DATA.replace('DOMAIN', domain)
        data = yaml.load(self.exec_cpanel_api_command(cmd))

        if data:
            return data['data']['userdata']
        else:
            return False

    def get_bw_data(self, searchtype='user', search=''):
        """
        Return Bandwith data. If not searchtype and search parameters are provided, it returns all the data
        :param searchtype:
        :param search:
        :param month:
        :param year:
        :param showres:
        :return:
        """
        # cmd = Server.GET_BW_DATA + ' search={0} + searchtype={1}'.format(search,  searchtype)
        cmd = Server.GET_BW_DATA + ' search=%s searchtype=%s' % (search, searchtype)
        data = yaml.load(self.exec_cpanel_api_command(cmd))

        if len(data['data']['acct']) > 0:

            return data['data']['acct']
        else:
            return False

    def set_bw_limit(self, user, bw_value):
        # cmd = Server.SET_BW_DATA + ' user={0} bwlimit={1}'.format(user, bw_value)
        cmd = Server.SET_BW_DATA + ' user=%s bwlimit=%s' % (user, bw_value)
        data = yaml.load(self.exec_cpanel_api_command(cmd))

        return data['metadata']['reason']

    def exec_cpanel_api_command(self, command):
        """
        Executes cPanel API call (whmapi1, whmapi2, cpapi2, uapi)

        Arguments:
            command: cPanel api command

        Returns:
            stdoutdata: output of Popen.communicate() method,
            0: if error occurs, or command is not allowed
            1: if test run is enabled
        """

        allowed = ['whmapi1', 'whmapi2', 'cpapi2', 'uapi', '/scripts/generate_maildirsize', 'lve-read-snapshot',
                   'hostname']
        cmd = shlex.split(command)

        if cmd[0] in allowed:
            print("Executing %s" % command)
            self.logger.info("Executing %s" % command)
            out, err = subprocess.Popen(cmd,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            if out:
                self.logger.info("Command %s executed!" % command)
                return out
            elif err:
                # self.logger.debug('ERROR with command {0}: \n{1}'.format(command, err))
                self.logger.info('ERROR with command %s: \n%s' % (command, err))
                return err
            else:
                return False

        else:
            self.logger.info("SKIPPED %s" % command)

        return False

    def mail_report(self, name,  content='', logfile='', error=''):
        """
        Mmethod accepts string or filename data, and sends a report to the designated mail

        :param name: Name of the Class.__name__ that invoked the mail_report method
        :param content: string
        :param logfile: filename
        :param error: if calling script got an error during execution
        :return:
        """
        if bool(self.server_conf.get('Server', 'send_report_mail')):
            if logfile:
                f = open(logfile, 'rb')
                msg = MIMEText(f.read())
                f.close()
            else:
                print content
                msg = MIMEText(content)
                print msg

            msg['Subject'] = error + name + ' report for server ' + self.hostname
            msg['From'] = 'root@' + self.hostname
            msg['To'] = self.report_mail

            s = smtplib.SMTP('localhost')
            s.sendmail(msg['From'], msg['To'], msg.as_string())

            self.logger.info("Report mail sent to %s!" % msg['To'])




if __name__ == '__main__':
    s = Server()
