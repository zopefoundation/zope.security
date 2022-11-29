##############################################################################
#
# Copyright (c) 2001, 2002 Zope Foundation and Contributors.
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
"""Preliminaries to hookup a test suite with the external TestModule.

This is necessary because the test framework interferes with seeing changes in
the running modules via the module namespace.  This enables having some
subject classes, instances, permissions, etc, that don't live in the test
modules, themselves.
"""
from zope.interface import Interface
from zope.schema import Text


class I(Interface):  # noqa: E742 ambiguous class definition 'I'
    def m1():
        """m1"""

    def m2():
        """m2"""


class I2(I):
    def m4():
        """m4"""


class I3(Interface):
    def m3():
        """m3"""


class I4(Interface):
    def m2():
        """m2"""


class S(Interface):
    foo = Text()
    bar = Text()
    baro = Text(readonly=True)


class S2(Interface):
    foo2 = Text()
    bar2 = Text()


template_bracket = """<configure
   xmlns="http://namespaces.zope.org/zope">
   %s
</configure>"""
