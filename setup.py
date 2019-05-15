# -*- coding: utf-8 -*-

'''
Created on  5-15-2019

@author: = Aaron Kitzmiller <aaron_kitzmiller@harvard.edu>
@copyright: 2019 The Presidents and Fellows of Harvard College. All rights reserved.
@license: GPL v2.0
'''

from setuptools import setup, find_packages
import re


def getVersion():
    version = '0.0.0'
    with open('rc/__init__.py', 'r') as f:
        contents = f.read().strip()

    m = re.search(r"__version__ = '([\d\.]+)'", contents)
    if m:
        version = m.group(1)
    return version


setup(
    name="rcpy3",
    version=getVersion(),
    author='Aaron Kitzmiller <aaron_kitzmiller@harvard.edu>',
    author_email='aaron_kitzmiller@harvard.edu',
    description='Some general use RC Python code, including user management libraries.  Python 3 version.',
    license='LICENSE.txt',
    url='http://pypi.python.org/pypi/rcpy/',
    packages=find_packages(),
    long_description='Some general use RC Python code, including user management libraries.',
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
    ],
    install_requires=[
        'python-ldap>=3',
        'nose'
    ],
)
