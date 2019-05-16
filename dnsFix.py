#!/usr/bin/env python
"""
__author__ = "Emanuel Zelic"
__version__ = "1.00"
__email__ = "emanuel@plus.hr"
__status__ = "Production"
"""

# == Description ==
# This script is intended to fix DNS zone entries for cPanel server domains.
# Script will MX and spf entries (to comply with Gmail new standards)
#
# Existing spf entries will be appended with the value from the config file.
#
# Script also checks MX configuration.
# If the domains has local mail resolving it will change the record from:
# << domain.tld IN MX domain.tld
# << mail IN CNAME domain.tld
# to:
# >> domain.tld IN MX mail.domain.tld
# >> mail IN A  0.0.0.0 (SERVER IP)
# Experience has shown that Gmail doesn't like the first setup and mark mails from those domains as {Spam} (low)

# == IMPORTANT: ==
# To run, check the configuration file inside ./includes/Server.conf, [Server] and [dnsFix] sections.
#
# IP Ranges that are being used for DNS servers across the cluster should be defined in [Server] section,
# value name "ns_ipranges"
# Example:
# ns_ipranges = 178.218.172.160/27, 178.218.165.160/27

from includes.Server import Server

import yaml
import time

try:
    # 'Importing netaddr for python 2.4'
    from netaddr import IP
    from netaddr import CIDR
except:
    # Importing netaddr for python > 2.4
    from netaddr import IPAddress as IP
    from netaddr import IPNetwork as CIDR


class dnsFix(object):
    server = Server()

    DUMP_DNS_ZONE = 'whmapi1 dumpzone domain=DOMAIN.TLD'

    def __init__(self):
        self.start = time.time()
        self.ns_ipranges = [s.strip() for s in dnsFix.server.server_conf.get('Server', 'ns_ipranges').split(',')]
        self.ignoreDomains = [s.strip() for s in
                              dnsFix.server.server_conf.get('dnsFix', 'ignoreDomains').split(',')]
        self.spf_includes = dnsFix.server.server_conf.get('dnsFix', 'spf_include').strip()

        # populate necessary data and create containers
        self.owners_users_data = dnsFix.server.get_owners_user_details()

        self.domain_resolving = {}
        self.dump_zone_fails = []

        self.report_string = []

    def output_and_log(self, text):
        """
        Just print the output steps to shell and prepere the report string.
        :param text:
        :return:
        """
        print text
        self.report_string.append(str(text))

    def get_zone_record(self, domain, line):
        get_zone_record = "whmapi1 getzonerecord domain=%s line=%s" % (domain, line)

        out = yaml.load(dnsFix.server.exec_cpanel_api_command(get_zone_record))['data']['record']
        if out:
            return out[0]
        else:
            return "Error getting zone record: ", domain, line

    def check_MX_record(self, domain, zone_dump, local_ip):
        """
        This method locates the relevant MX lines in the zone dump, so checks and modifications can be made.
        Currently just prints the results when change is needed.

        TODO: so far only check is that domain is using our nameservers!!!
        This method adds check that that the mails are resolving on the domain name
        Need to add additional checks to be sure mails are really delivered locally!
        :param domain:
        :param zone_dump:
        :param local_ip:
        :return:
        """
        fixmx = 0
        fixmail = 0
        mail_record_exists = 0
        for item in zone_dump:
            # fix MX record to point to mail.domain.tld
            if item['type'] == 'MX' and item['name'].strip('.') == item['exchange']:
                line = 'whmapi1 editzonerecord domain=%s line=%s name=%s exchange=%s class=IN ttl=300 type=MX preference=%s' % \
                       (domain, item['Line'], domain+'.', 'mail.'+domain, item['preference'])
                log_msg = 'MX Record (OLD): ', item
                self.output_and_log(log_msg)
                dnsFix.server.exec_cpanel_api_command(line)
                new_mx = self.get_zone_record(domain, item['Line'])
                log_msg = 'MX Record (NEW): ', new_mx
                self.output_and_log(log_msg)
                fixmx = 1
            # fix mail.domain.tld record so it points to server IP
            if item.has_key('name') and item['name'].strip('.') == 'mail.'+domain \
                    and item['type'] == 'CNAME' and item['cname'] == domain:
                line = 'whmapi1 editzonerecord domain=%s line=%s name=%s class=IN ttl=300 type=A address=%s' % \
                       (domain, item['Line'], item['name'], local_ip)
                log_msg = 'MAIL.DOMAIN.TLD Record (OLD): ', item
                self.output_and_log(log_msg)
                dnsFix.server.exec_cpanel_api_command(line)
                nex_mail = self.get_zone_record(domain, item['Line'])
                log_msg = 'MAIL.DOMAIN.TLD Record (NEW): ', nex_mail
                self.output_and_log(log_msg)
                fixmail = 1
                mail_record_exists = 1

            if item.has_key('name') and item['name'].strip('.') == 'mail.'+domain:
                # in case mail.domain.tld is already present and points to an IP address
                mail_record_exists = 1


        if not mail_record_exists:
            # add mail.domain.tld if the record is not present in the zone
            add_mail_record = "whmapi1 addzonerecord domain=%s name=%s class=IN ttl=14400 type=A address=%s" % \
                        (domain, 'mail.'+domain+'.', local_ip)
            self.output_and_log('Domain mail.domain.tld not found, adding now:')
            dnsFix.server.exec_cpanel_api_command(add_mail_record)

        if not fixmx and not fixmail:
            self.output_and_log('Domain is using good MX/mail configuration.')

    def fix_txt_record(self, domain, spf_record):
        line = 'whmapi1 editzonerecord domain=%s line=%s name=%s class=IN ttl=14400 type=TXT txtdata="%s"' \
               % (domain, spf_record['Line'], spf_record['name'], spf_record['txtdata'])
        log_msg = "Applying TXT Fix for domain", domain, 'record', spf_record['name'], 'line', spf_record['Line']
        self.output_and_log(log_msg)
        dnsFix.server.exec_cpanel_api_command(line)
        new_txt = self.get_zone_record(domain, spf_record['Line'])
        log_msg = 'TXT SPF (NEW):',  new_txt['txtdata']
        if new_txt['txtdata'] != spf_record['txtdata']:
            self.output_and_log("ERROR CONFIRMING DOMAIN TXT DATA, CHECK ZONE FILE FOR ERRORS (missing A record!)")
        self.output_and_log(log_msg)

    def check_txt_record(self, domain, zone_dump):
        """
        This method will locate the ALL TXT spf records in the zone dump by changing '?all' to '~all' and adding
        'include:spf.domain.tld' to the record where necessary (use config file to define the spf include domain)

        :param domain:
        :param zone_dump:
        :return:
        """
        for item in zone_dump:
            spffix = 0
            if item.has_key('txtdata') and 'v=spf1' in item['txtdata']:
                log_msg = "TXT SPF (OLD): ", item['txtdata']

                # spf soft fail check
                if '?all' in item['txtdata']:
                    self.output_and_log('Soft fail needed!')
                    item['txtdata'] = item['txtdata'].replace('?all', '~all')
                    spffix = 1
                # include check
                if self.spf_includes not in item['txtdata']:
                    self.output_and_log('SPF include needed!')
                    spf = item['txtdata'].split()
                    spf.insert(-1, self.spf_includes)
                    item['txtdata'] = ' '.join([i.lstrip('+') for i in spf])
                    spffix = 1

                if spffix:
                    self.output_and_log(log_msg)
                    self.fix_txt_record(domain, item)
                else:
                    log_msg = "Domain %s is using correct SPF: %s" % (domain, item)
                    self.output_and_log(log_msg)

    def dump_domain(self, domain):
        """
        Dump DNS zone and reads collects txt records.
        Apply fix if needed
        """
        cmd = dnsFix.DUMP_DNS_ZONE.replace('DOMAIN.TLD', domain)
        try:
            dump_out = dnsFix.server.exec_cpanel_api_command(cmd).replace('\t','')
            zone_dump = yaml.load(dump_out)['data']['zone'][0]['record']
        except yaml.scanner.ScannerError, err:
            self.output_and_log('ERROR: \n' + repr(err))
            print 'ERROR: ', err
            self.dump_zone_fails.append(domain)
            return 0
        except KeyError, err:
            self.output_and_log('ERROR: \n', repr(err))
            self.dump_zone_fails.append(domain)
            return 0

        return zone_dump

    def check_ns_resolve(self, domain):
        """
         This method checks if the domain is resolving to our name server IP ranges
         :param domain:
         :return:
         """
        # if domain is resolving via our name servers and domain is not listed in ignored domains
        if '.'.join(domain.split('.')[-2:]) not in self.ignoreDomains:
            dom_res_ns = self.domain_resolving[domain]['NS']
            if (type(dom_res_ns) != bool) and dom_res_ns:
                if [net for net in self.ns_ipranges for ns in dom_res_ns if IP(ns[1]) in CIDR(net)]:
                    # condition will be true if server NS entry resolves to our Name Server IP ranges
                    return True
            else:
                # domain name server entries not found, or external:
                return False

    def resolve_domain(self, domain):
        """
        Accepts list of domains and populates self.domain_resolving[domain][('A'|'MX'|'NS'}| values
        Data format:
            A: query data is returned
            MX: list(tuple): list of tuples for every MX record and its resolving IP address
            MX: list(tuple): list of tuples for every NS record and its resolving IP address

        :param user_domains:
        :return:
        """
        ns = dnsFix.server.resolve(domain, 'NS')
        a = dnsFix.server.resolve(domain, 'A')
        mx = dnsFix.server.resolve(domain, 'MX')
        txt = dnsFix.server.resolve(domain, 'TXT')
        if ns:
            ns_records = sorted(ns, key=lambda ns_rec: ns_rec[0])
        else:
            ns_records = False

        self.domain_resolving.setdefault(domain, {})['NS'] = ns_records
        self.domain_resolving[domain]['A'] = a
        self.domain_resolving[domain]['MX'] = mx
        self.domain_resolving[domain]['TXT'] = txt

    def prepare_data(self):
        """
        This method prepares the dictionary of users to perform the spf and MX change 'operation'
        List of dict(self.skipped_users) is populated:
         - any domain on the account is not using our name servers
         - domain.tld is not listed in the 'ignored_domains' configuration value
         This resolution is done by self.check_ns_resolve
        :return:
        """
        users_domains = dnsFix.server.get_account_domain_list(owners_users_data=self.owners_users_data)

        for owner in self.owners_users_data.keys():
            log_msg = '\n\nOWNER: %s' % owner
            self.output_and_log(log_msg)
            users = self.owners_users_data[owner].keys()
            users.sort()
            for user in users:
                log_msg = '\nUSER: %s' % user
                self.output_and_log(log_msg)
                user_domains = users_domains[user]
                self.owners_users_data[owner][user]['domains'] = user_domains

                for domain in user_domains:
                    self.resolve_domain(domain)
                    log_msg = 'D: ', domain
                    self.output_and_log(log_msg)
                    log_msg = 'MX Resolve: ', self.domain_resolving[domain]['MX']
                    self.output_and_log(log_msg)

                    mx_resolve = self.domain_resolving[domain]['MX']
                    # domain has MX records, uses our nameserver cluster and mails resolving locally
                    if mx_resolve and self.check_ns_resolve(domain) and \
                                        self.owners_users_data[owner][user]['ip'] in mx_resolve[0][1]:
                        zone_dump = self.dump_domain(domain)

                        if zone_dump:
                            self.check_txt_record(domain, zone_dump)
                            self.check_MX_record(domain, zone_dump, self.owners_users_data[owner][user]['ip'])
                        else:
                            log_msg = "ERROR: Unable to dump zone %s: \n %s" % (domain, zone_dump)
                            self.output_and_log(log_msg)
                    else:
                        reason = "REASON: Domain %s not resolving to our servers or domain ignored." % domain
                        log_msg = "Skipped:", domain, reason
                        self.output_and_log(log_msg)

    def report(self):
        if len(self.dump_zone_fails) > 0:
            log_msg = "\n\nZONES WITH DUMP ERRORS:"
            self.output_and_log(log_msg)
            for domain in self.dump_zone_fails:
                self.output_and_log(domain)

        execution_time = "\nExecution took: %s seconds" % (time.time()-self.start)
        self.report_string.append(execution_time)
        rs = '\n'.join(self.report_string)
        dnsFix.server.mail_report(self.__class__.__name__, content=rs)


if __name__ == '__main__':
    try:
        gmailFix = dnsFix()
        gmailFix.prepare_data()
        gmailFix.report()
    except Exception , err:
        err = 'Error executing script! \n %s' % repr(err)
        dnsFix.server.mail_report('dnsFix.py', content=err, error='ERROR: ')


