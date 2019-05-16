#!/usr/bin/env python
"""
__author__ = "Emanuel Zelic"
__version__ = "0.1"
__email__ = "emanuel@plus.hr"
__status__ = "Development"
"""

from includes.Server import Server

class ResolvingReport(object):

    def __init__(self):
        # account and ownership details
        self.owners = server.get_resellers()

        # working dictionaries
        self.domain_data = {}

    def domain_resolve(self, domain):
        """
        Return domain resolving data
        :param domain:
        :return:
        """
        a_result = server.resolve(domain, 'A')
        mx_result = server.resolve(domain, 'MX')
        ns_result = server.resolve(domain, 'NS')

        domain_data = {}
        domain_data.setdefault('resolving', {'A': a_result})
        domain_data['resolving']['MX'] = mx_result
        domain_data['resolving']['NS'] = ns_result

        return domain_data

    def populate_domain_data(self, domain):
        """
        This method will populate relevant domain data for the report
        :param domain:
        :return:
        """
        self.domain_resolve(domain)
        domain_data = server.get_domain_data(domain)['data']['userdata']

        self.domain_data[domain] = self.domain_resolve(domain)

        if domain in self.domain_data.keys():
            try:
                self.domain_data[domain]['documentroot'] = domain_data['documentroot']
                self.domain_data[domain]['ip'] = domain_data['ip']
            except KeyError:
                self.domain_data[domain]['documentroot'] = "No domain data found, admin should check"
                self.domain_data[domain]['ip'] = "No domain data found, admin should check"

    def generate_report(self, owners_users_data):
        """
        This method will handle data population for report generation
        :return:
        """
        domain_types = ['addon_domains', 'parked_domains', 'sub_domains']

        report = ''

        for owner in owners_users_data.keys():
            report += '\n{0} | {1:>8} | {2:>21} | {3:>28}\n'.format('OWNER', 'USER/DOMAIN', 'IP/MX/NS', 'DOCUMENT ROOT')
            report += owner
            users = owners_users_data[owner].keys()
            users.sort()
            for user in users:
                user_domains = server.get_account_domains(user)
                domain = user_domains['main_domain']

                self.populate_domain_data(domain)
                domain_resolving = self.domain_data[domain]['resolving']
                document_root = self.domain_data[domain]['documentroot']
                report += '{0:>17}:  LOCAL IP: {1:34}\n'.format(user, owners_users_data[owner][user]['ip'])
                report += '{0:>13}{1:34} {2:54}\n'.format(' ', domain, document_root)
                report += '{0:>13}IP: {1}\n'.format(' ', domain_resolving['A'])
                report += '{0:>13}MX: {1}\n'.format(' ', domain_resolving['MX'])
                report += '{0:>13}NS: {1}\n\n'.format(' ', domain_resolving['NS'])

                for domain_type in domain_types:
                    for domain in user_domains[domain_type]:
                        self.populate_domain_data(domain)
                        document_root = self.domain_data[domain]['documentroot']
                        report += '{0:>13}{1:34} {2:54}\n'.format(' ', domain, document_root)
                        report += '{0:>13}{1}\n'.format(' ', domain_resolving['A'] )
                        report += '{0:>13}MX: {1}\n'.format(' ', domain_resolving['MX'])
                        report += '{0:>13}NS: {1}\n\n'.format(' ', domain_resolving['NS'])

        server.mail_report(self.__class__.__name__, content=report)

    def generate_report_p24(self, owners_users_data):
        """
        This method will handle data population for report generation
        :return:
        """
        domain_types = ['addon_domains', 'parked_domains', 'sub_domains']

        report = ''

        for owner in owners_users_data.keys():
            report += '\nOWNER, USER/DOMAIN, IP/MX/NS, DOCUMENT ROOT\n'
            report += owner
            users = owners_users_data[owner].keys()
            users.sort()
            for user in users:
                user_domains = server.get_account_domains(user)
                domain = user_domains['main_domain']

                self.populate_domain_data(domain)
                domain_resolving = self.domain_data[domain]['resolving']
                document_root = self.domain_data[domain]['documentroot']
                report += '%17s:  LOCAL IP: %34s\n' % (user, owners_users_data[owner][user]['ip'])
                report += '%13s, %34s %54s\n' % (' ', domain, document_root)
                report += '%13s IP: %s\n' % (' ', domain_resolving['A'])
                report += '%13s MX: %s\n' % (' ', domain_resolving['MX'])
                report += '%13s NS: %s\n\n' % (' ', domain_resolving['NS'])

                for domain_type in domain_types:
                    for domain in user_domains[domain_type]:
                        self.populate_domain_data(domain)
                        document_root = self.domain_data[domain]['documentroot']
                        report += '%13s, %34s %54s\n' % (' ', domain, document_root)
                        report += '%13s IP: %s\n' % (' ', domain_resolving['A'])
                        report += '%13s MX: %s\n' % (' ', domain_resolving['MX'])
                        report += '%13s NS: %s\n\n' % (' ', domain_resolving['NS'])

        server.mail_report(self.__class__.__name__, content=report)

    def define_search_type(self, owner='', user=''):
        #rijesiti ovaj condition kroz naziv varijable argumenta i njegovu vrijednost
        if owner:
            search = owner
            searchtype = 'owner'
        elif user:
            search = user
            searchtype = 'user'
        else:
            search = ''
            searchtype = 'owner'

        owners_users_data = server.get_owners_user_details(search, searchtype)

        # check python version
        # self.generate_report(owners_users_data)
        self.generate_report_p24(owners_users_data)

if __name__ == '__main__':
    server = Server()
    rr = ResolvingReport()
    rr.define_search_type()
