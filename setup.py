import sys
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

if sys.version_info[0] == 3:
    requires = ['dnspython3']
elif sys.version_info[0] == 2:
    requires = ['dnspython']

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(name='clientsubnetoption',
      version='2.1.1',
      maintainer='Brian Hartvigsen',
      maintainer_email='bhartvigsen@opendns.com',
      description='EDNS Client Subnet option support for dnspython',
      url='https://github.com/opendns/dnspython-clientsubnetoption',
      long_description=long_description,
      long_description_content_type='text/markdown',
      license='BSD',
      py_modules=['clientsubnetoption'],
      install_requires=requires,
      classifiers=[
          "Development Status :: 5 - Production/Stable",
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
      ])
