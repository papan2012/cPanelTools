#!/usr/bin/env python
"""
__author__ = "Emanuel Zelic"
__version__ = "0.8"
__email__ = "emanuel@plus.hr"
__status__ = "Development"
"""


from includes.Server import Server
import time


class LocRem(Server):
    def __init__(self):
        self.start = time.time()

        # config values
        self.logfile = server.server_conf.get(self.__class__.__name__, 'logfile')
        self.logger = server.set_logger(self.logfile, formatter='%(message)s', mode='w')
        self.localdomains_file = server.server_conf.get('LocRem', 'local')
        self.remotedomains_file = server.server_conf.get('LocRem', 'remote')
        self.ignored_domains = [s.strip(',').strip() for s in
                                str.split(server.server_conf.get(self.__class__.__name__, 'ignoreDomains'))]
        self.ignored_nameservers = [s.strip(',').strip() for s in
                                    str.split(server.server_conf.get(self.__class__.__name__, 'ignoreNameServers'))]

        # account and ownership details
        self.acc_details = dict((item['user'], item) for item in server.get_acc_details())
        self.users_domains = server.get_account_domain_list()
        self.domain_users = dict((domain, user) for user in self.users_domains.keys() for domain in self.users_domains[user])
        self.domain_list = [domain for domain in self.domain_users.keys()]
        self.suspended_users_data = server.get_suspended_user_data()
        self.domain_resolving = {}

        # working dictionaries
        self.fixlocrem = {'local': [], 'remote': [], 'second': [], 'check': [], 'remove': []}

        # data processing
        self.check_loc_rem()

    def checkResolving(self, domain):
        """
        Method returns true if:
            - domain MX records resolve to local vHost IP
            - if no MX records are found, A record is compared to local vHost IP
        Domain resolving is ignored if domain is using ignored nameservers (configuration file)

        :param domain:
        :return:
        """
        domain_local_ip = self.acc_details[self.domain_users[domain]]['ip']

        a_result = server.resolve(domain, 'A')
        mx_result = server.resolve(domain, 'MX')
        ns_result = server.resolve(domain, 'NS')

        self.domain_resolving.setdefault(domain, {'A': a_result})
        self.domain_resolving[domain]['MX'] = mx_result
        self.domain_resolving[domain]['NS'] = ns_result

        if ns_result:
            # domain is using ignored nameservers
            ns_domains = list(set(['.'.join(item[0].split('.')[-2:]) for item in ns_result]))
            for ns_domain in ns_domains:
                if ns_domain in self.ignored_nameservers:
                    self.fixlocrem['check'].append((domain, "Domain is using ignored name servers, check "
                                                            "skipped:\n{0}".format(ns_result)))
                    return False

        if mx_result:
            domain_mx_ips = [mx_entry[1][0] for mx_entry in mx_result]

            if domain_local_ip in domain_mx_ips:
                if len(domain_mx_ips) > 1:
                    self.fixlocrem['check'].append(
                        (domain, "Multiple MX Entries found, one is pointing to this server\n{0}".format(mx_result)))
                    return False
                return True
            else:
                return False
        elif a_result:
            if domain_local_ip in a_result:
                # no MX record found, domain A record is resolving to local vHost IP
                return True
            else:
                return False
        else:
            # domain is not resolving to local vHost IP
            return False

    def check_loc_rem(self):
        """
        Iterates over the domains and initiates checkResolving method
        :param locrem:
        :return:
        """
        localdomains = [line.rstrip() for line in open(self.localdomains_file, 'r')]
        remotedomains = [line.rstrip() for line in open(self.remotedomains_file, 'r')]

        for domain in self.domain_list:
            if '.'.join(domain.split('.')[-2:]) not in self.ignored_domains:
                resolve_result = self.checkResolving(domain)

                if resolve_result and domain in remotedomains:
                    self.fixlocrem['local'].append((domain, "{0:>13} A:{1[A]}\n{0:>13} MX:{1[MX]}\n"
                                                            "{0:>13} NS:{1[NS]}\n".format(' ', self.domain_resolving[domain])))
                elif not resolve_result and domain in localdomains and \
                                domain not in [record[0] for record in self.fixlocrem['check']]:
                    self.fixlocrem['remote'].append((domain, "{0:>13} A:{1[A]}\n{0:>13} MX:{1[MX]}\n"
                                                            "{0:>13} NS:{1[NS]}\n".format(' ', self.domain_resolving[domain])))
                else:
                    self.logger.info("Domain {0} configured OK".format(domain))


    def apply_fix(self, locrem, domain, domain_mx):
        """
        """
        TEST = server.server_conf.getboolean('Server', 'verbose_dry_run')

        user = self.domain_users[domain]

        fixlocrem = "cpapi2 --user={0} Email setmxcheck domain={1} mxcheck={2}".format(user, domain, locrem)
        unsuspend = "whmapi1 unsuspendacct user=" + user
        suspend = "whmapi1 suspendacct user=" + user

        if user not in self.suspended_users_data.keys():
            # user not suspended
            if not TEST:
                server.exec_cpanel_api_command(fixlocrem)
                self.logger.info("Domain {0} was moved to {1} \n{2}".format(domain, locrem, domain_mx))
            else:
                self.logger.info("DRY RUN: Domain {0} would be moved to {1}"
                                 "\n {2}".format(domain, locrem, domain_mx))
        else:
            if not TEST:
                self.logger.debug("User {0} suspended, unsuspending for LocRem fix".format(user))
                server.exec_cpanel_api_command(unsuspend)
                self.logger.info("Domain {0} was moved to {1} \n{2}".format(domain, locrem, domain_mx))
                server.exec_cpanel_api_command(fixlocrem)
                suspend += " reason=" + self.suspended_users_data[user]['reason']
                server.exec_cpanel_api_command(suspend)
                self.logger.debug("User %s suspended" % user)
            else:
                self.logger.info("DRY RUN: User {0} would be unsuspended and "
                                 "domain {1} moved to {2}\n{3}".format(user, domain, locrem, domain_mx))

    def run(self):
        """
        Executes the steps of the script in order.
        Iterates over self.fixlocrem dictionary
        Reports cases where operator will have to check the situation.

        :param self:
        :return:
        """
        length = time.time() - self.start
        for lr_key, domains in self.fixlocrem.iteritems():
            if lr_key == 'check' or lr_key == 'remove':
                for entry in self.fixlocrem[lr_key]:
                    self.logger.info("{0}: {1}\n{2}".format(lr_key.upper(), entry[0], entry[1]))
            else:
                self.logger.info(lr_key.upper())
                for domain in domains:
                    self.apply_fix(lr_key, domain[0], domain[1])

        self.logger.info('Program operation took {0}'.format(length))

        server.mail_report(self.__class__.__name__, logfile=self.logfile)


if __name__ == '__main__':
    server = Server()
    locrem = LocRem()
    locrem.run()
