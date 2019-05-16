#!/usr/bin/env python
"""
__author__ = "Emanuel Zelic"
__version__ = "0.1"
__email__ = "emanuel@plus.hr"
__status__ = "Development"

Report mail disk usage over 500MB
"""

from includes.Server import Server
import yaml

srv = Server()
oud = srv.get_owners_user_details()

def mail_report(user):
    repl = {'USERNAME': user, 'USER': '', 'DOMAIN': ''}

    report = {user: []}

    for email in userEmails:
        repl['USER'] = email.split('@')[0]
        repl['DOMAIN'] = email.split('@')[1]

        get_acc_disk_usage = reduce(lambda a, kv: a.replace(*kv), repl.iteritems(), srv.GET_MAIL_DISK_USAGE)

        mail_quota = float(yaml.load(srv.exec_cpanel_api_command(get_acc_disk_usage))['result']['data']['diskused'])
        if mail_quota >= 500:
            report[user].append((email, mail_quota))

    if len(report[user]) > 0:
        print("{0:>8} {1}".format(' ', user))
        for item in report[user]:
            # item = (email, mail_quota)
            print("{0:>13} {1[0]:34} {1[1]}MB".format(' ', item))


for owner in oud.keys():
    print owner
    for user in oud[owner].keys():
        try:
            userEmails = yaml.load(srv.exec_cpanel_api_command(srv.GET_USER_MAILS.replace('USER', user)))['data']['pops']
            cmd = '/scripts/generate_maildirsize --confirm --allaccounts --verbose '+user
            srv.exec_cpanel_api_command(cmd)
            mail_report(user)
        except Exception as error:
            print('No data returned, check the cPanel username you provided for user {0}'.format(user))
            print error
