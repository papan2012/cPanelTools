#!/usr/bin/env python
"""
__author__ = "Emanuel Zelic"
__version__ = "1.0"
__email__ = "emanuel@plus.hr"
__status__ = "Development"
"""

from includes.Server import Server
import datetime

try:
    # 'Importing netaddr for python 2.4'
    from netaddr import IP
    from netaddr import CIDR
except:
    # Importing netaddr for python > 2.4
    from netaddr import IPAddress as IP
    from netaddr import IPNetwork as CIDR


class SATerminator(object):

    def __init__(self):
        # configuration parameters
        self.ns_ipranges = [s.strip() for s in server.server_conf.get('Server', 'ns_ipranges').split(',')]
        self.ignoreDomains = [s.strip() for s in server.server_conf.get('SATerminator', 'ignoreDomains').split(',')]
        self.period_moved = float(server.server_conf.get('SATerminator', 'term_period_moved'))
        self.period_expired = float(server.server_conf.get('SATerminator', 'term_period_expired'))
        self.terminate_owners = [s.strip() for s in
                                 server.server_conf.get('SATerminator', 'default_owners_to_terminate').split(',')]

        self.logfile = server.server_conf.get(self.__class__.__name__, 'logfile')
        self.logger = server.set_logger(self.logfile, formatter='%(message)s', mode='w')

        # runtime dictionaries
        self.terminate = {'TERMINATE': [], 'TERMINATE_KEEP': [], 'DOUBLECHECK': [], 'SKIP': []}
        self.domains = {}

        # data processing
        self.suspended_users_data = server.get_suspended_user_data()

    def resolve_suspended(self, owners):
        """
        Iterates over suspended accounts, limited to owners list
        Resolves name server records for domains of relevant users
        Users that are not owned by the defined owners are removed from the suspended_user_data dict
        """

        for user in self.suspended_users_data.keys():
            if self.suspended_users_data[user]['owner'] in owners:
                domains = server.get_account_domains(user)
                if domains:
                    user_domains = domains['addon_domains']+domains['parked_domains']
                    user_domains.append(domains['main_domain'])
                    self.suspended_users_data[user]['domains'] = user_domains

                    for domain in user_domains:
                        ns = server.resolve(domain, 'NS')
                        a = server.resolve(domain, 'A')
                        mx = server.resolve(domain, 'MX')
                        if ns:
                            ns_records = sorted(ns, key=lambda ns_rec: ns_rec[0])
                        else:
                            ns_records = False

                        self.domains.setdefault(domain, {})['NS'] = ns_records
                        self.domains[domain]['A'] = a
                        self.domains[domain]['MX'] = mx
            else:
                self.suspended_users_data.pop(user)

    def check_terminate_details(self, user):
        """
        Checks for the conditions for termination.
        Bandwith limit exceedesrs will have their bandwith raised and they will be unsuspended.
        Method returns True if account exceedes defined periods for suspension
        Accounts with defined suspension reason will be compared with moved_period,
        otherwise expired_period is checked.
        :param user:
        :return bool:
        """
        user_details = self.suspended_users_data[user]
        if 'Bandwidth Limit Exceeded' in user_details['reason']:
            # set new bandwith limit for the user
            bw_data = server.get_bw_data('user', user)[0]
            day_of_month = float(datetime.datetime.today().day)
            new_bw_limit = int(float(bw_data['totalbytes'])/1024/1024 * 40/day_of_month)
            response = server.set_bw_limit(user, new_bw_limit)
            self.logger.info('User %s: %s}' % (user, response))
            return False
        elif user_details['reason'] != 'Unknown':
            return user_details['suspendperiod'] > self.period_moved
        else:
            return user_details['suspendperiod'] > self.period_expired

    def compare_resolving(self, user):
        """
        Method is checking if the domain is using any nameservers on our nameservers IP ranges
        If it does, account will be marked for termination with keep dns zone
        """
        ns_ip_resolve = 0
        for domain in self.suspended_users_data[user]['domains']:
            if not ns_ip_resolve and '.'.join(domain.split('.')[-2:]) not in self.ignoreDomains:
                # while no domain is resolving via our name servers and domain is not listed in ignored domains
                dom_res_ns = self.domains[domain]['NS']
                if dom_res_ns:
                    if [net for net in self.ns_ipranges for ns in dom_res_ns if IP(ns[1]) in CIDR(net)]:
                        # condition will be true if server NS entry resolves to Nameserver IP ranges
                        ns_ip_resolve = 1

        terminate = self.check_terminate_details(user)
        if terminate:
            if ns_ip_resolve:
                self.terminate['TERMINATE_KEEP'].append(user)
            else:
                self.terminate['TERMINATE'].append(user)
        else:
            self.terminate['SKIP'].append(user)

    def terminator(self):
        for task in self.terminate.keys():
            if task == 'SKIP':
                for user in self.terminate[task]:
                    self.logger.info("%s %s not terminated, suspended %s days ago"
                                     % (task, user, self.suspended_users_data[user]['suspendperiod']))
            else:
                for user in self.terminate[task]:
                    reason = self.suspended_users_data[user]['reason']
                    if reason:
                        reason = ", Reason: " + reason
                    self.logger.info("%s: %s, suspended %s days ago %s"
                                     % (task, user, self.suspended_users_data[user]['suspendperiod'], reason))
                    for domain in self.suspended_users_data[user]['domains']:
                        self.logger.info("%13s Domain: %s" % (' ', domain))
                        self.logger.info('%13s IP: %s' % (' ', self.domains[domain]['A']))
                        self.logger.info('%13s MX: %s' % (' ', self.domains[domain]['MX']))
                        self.logger.info('%13s NS: %s\n' % (' ', self.domains[domain]['NS']))

                    if task == 'TERMINATE':
                        terminate_command = "whmapi1 removeacct user=" + user
                    if task == 'TERMINATE_KEEP':
                        terminate_command = "whmapi1 removeacct user=" + user + " keepdns=1"

                    if not server.server_conf.getboolean('Server', 'verbose_dry_run'):
                        self.logger.info("%8s Terminating: %s\n" % (' ', terminate_command))
                        server.exec_cpanel_api_command(terminate_command)
                    else:
                        self.logger.info("%8s DRY RUN: Command %s" % (' ', terminate_command))


        server.mail_report(self.__class__.__name__, logfile=self.logfile)

    def run(self):
        self.resolve_suspended(self.terminate_owners)

        for user in self.suspended_users_data.keys():
            self.compare_resolving(user)

        self.terminator()


if __name__ == '__main__':
    server = Server()

    sa_terminator = SATerminator()
    sa_terminator.run()
