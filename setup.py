#############################################################################
#
# Copyright (c) 2006 Zope Foundation and Contributors.
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
# This package is developed by the Zope Toolkit project, documented here:
# http://docs.zope.org/zopetoolkit
# When developing and releasing this package, please follow the documented
# Zope Toolkit policies as described by this documentation.
##############################################################################
"""Setup for zope.security package
"""
import os
import platform
import sys
from distutils.errors import CCompilerError
from distutils.errors import DistutilsExecError
from distutils.errors import DistutilsPlatformError

from setuptools import Extension
from setuptools import find_packages
from setuptools import setup
from setuptools.command.build_ext import build_ext


class optional_build_ext(build_ext):
    """This class subclasses build_ext and allows
       the building of C extensions to fail.
    """

    def run(self):
        try:
            build_ext.run(self)
        except DistutilsPlatformError as e:
            self._unavailable(e)

    def build_extension(self, ext):
        try:
            build_ext.build_extension(self, ext)
        except (CCompilerError, DistutilsExecError, OSError) as e:
            self._unavailable(e)

    def _unavailable(self, e):
        print('*' * 80)
        print("""WARNING:
        An optional code optimization (C extension) could not be compiled.
        Optimizations for this package will not be available!""")
        print()
        print(e)
        print('*' * 80)


here = os.path.abspath(os.path.dirname(__file__))


def read(*rnames):
    with open(os.path.join(os.path.dirname(__file__), *rnames)) as f:
        return f.read()

# Include directories for C extensions
# Sniff the location of the headers in the package distribution


class ModuleHeaderDir(object):

    def __init__(self, require_spec, where='../..'):
        # By default, assume top-level pkg has the same name as the dist.
        # Also assume that headers are located in the package dir, and
        # are meant to be included as follows:
        #    #include "module/header_name.h"
        self._require_spec = require_spec
        self._where = where

    def __str__(self):
        from pkg_resources import require
        from pkg_resources import resource_filename
        require(self._require_spec)
        path = resource_filename(self._require_spec, self._where)
        return os.path.abspath(path)


include = [ModuleHeaderDir('zope.proxy')]

codeoptimization = [
    Extension(
        "zope.security._proxy",
        [os.path.join('src', 'zope', 'security', "_proxy.c")],
        include_dirs=include,
    ),
    Extension(
        "zope.security._zope_security_checker",
        [os.path.join('src', 'zope', 'security',
                      "_zope_security_checker.c")]
    ),
]


# Jython cannot build the C optimizations, while on PyPy they are
# anti-optimizations (the C extension compatibility layer is known-slow,
# and defeats JIT opportunities).
py3 = sys.version_info[0] >= 3
py_impl = getattr(platform, 'python_implementation', lambda: None)
is_pypy = py_impl() == 'PyPy'
is_jython = 'java' in sys.platform

if is_pypy or is_jython:
    setup_requires = []
    ext_modules = []
else:
    setup_requires = ['zope.proxy >= 4.3.0']
    ext_modules = codeoptimization


TESTS_REQUIRE = [
    'BTrees',
    'zope.component',
    'zope.configuration',
    'zope.location',
    'zope.testing',
    'zope.testrunner',
]


setup(name='zope.security',
      version='5.5',
      author='Zope Foundation and Contributors',
      author_email='zope-dev@zope.org',
      description='Zope Security Framework',
      long_description=(
          read('README.rst')
          + '\n\n' +
          read('CHANGES.rst')
      ),
      keywords="zope security policy principal permission",
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Environment :: Web Environment',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: Zope Public License',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Programming Language :: Python :: 3.11',
          'Programming Language :: Python :: Implementation :: CPython',
          'Programming Language :: Python :: Implementation :: PyPy',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Topic :: Internet :: WWW/HTTP',
          'Framework :: Zope :: 3',
      ],
      url='http://github.com/zopefoundation/zope.security',
      license='ZPL 2.1',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      namespace_packages=['zope'],
      setup_requires=setup_requires,
      cmdclass={
          'build_ext': optional_build_ext,
      },
      ext_modules=ext_modules,
      python_requires='>=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*',
      install_requires=[
          'setuptools',
          'zope.component',
          'zope.i18nmessageid',
          'zope.interface',
          'zope.location',
          'zope.proxy >= 4.3.0',
          'zope.schema >= 4.2.0',
      ],
      tests_require=TESTS_REQUIRE,
      extras_require={
          'pytz': [
              "pytz"
          ],
          'untrustedpython:python_version == "2.7"': [
              'zope.untrustedpython',
          ],
          'untrustedpython:python_version >= "3.3"': [],
          'zcml': [
              'zope.configuration'
          ],
          'test': TESTS_REQUIRE,
          'docs': [
              'Sphinx',
              'repoze.sphinx.autointerface',
              'zope.configuration',
              'zope.testing',
          ],
      },
      include_package_data=True,
      zip_safe=False,
      )
