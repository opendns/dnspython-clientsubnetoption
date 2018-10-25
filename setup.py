import sys
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

if sys.version_info[0] == 3:
    requires = ['dnspython3']
elif sys.version_info[0] == 2:
    requires = ['dnspython']

setup(name='clientsubnetoption',
      version='3.0.0a1',
      maintainer='Brian Hartvigsen',
      maintainer_email='bhartvigsen@opendns.com',
      description='EDNS Client Subnet option support for dnspython',
      url='https://github.com/opendns/dnspython-clientsubnetoption',
      license='BSD',
      py_modules=['clientsubnetoption'],
      install_requires=requires,
      classifiers=[
          "Development Status :: 3 - Alpha",
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
      ])
