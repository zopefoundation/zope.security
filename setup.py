##############################################################################
#
# Copyright (c) 2006 Zope Corporation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Setup for zope.security package

$Id$
"""

import os

from setuptools import setup, find_packages, Extension

setup(name='zope.security',
      version='3.3dev',
      url='http://svn.zope.org/zope.security',
      license='ZPL 2.1',
      description='Zope3 Security Architecture',
      author='Zope Corporation and Contributors',
      author_email='zope3-dev@zope.org',
      long_description='The Security framework provides a generic mechanism '
                       'to implement security policies on Python objects.',
      
	  packages=find_packages('src'),
	  package_dir = {'': 'src'},

      ext_modules=[Extension("zope.security._proxy",
                             [os.path.join('src', 'zope', 'security',
                                           "_proxy.c")
                              ], include_dirs=['include']),
                   Extension("zope.security._zope_security_checker",
                             [os.path.join('src', 'zope', 'security',
                                           "_zope_security_checker.c")
                              ]),
                   ],

      namespace_packages=['zope',],
      tests_require = ['zope.testing'],
      install_requires=['pytz',
                        'zope.exceptions',
                        'zope.interface',
                        'zope.proxy',
                        'zope.schema',
                        'zope.thread',
                        'zope.location'
                       ],
      extras_require = {'untrustedpython': ["RestrictedPython"]},
      include_package_data = True,

      zip_safe = False,
      )
