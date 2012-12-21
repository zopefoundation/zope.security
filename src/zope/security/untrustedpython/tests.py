##############################################################################
#
# Copyright (c) 2004 Zope Foundation and Contributors.
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
"""Untrusted python tests
"""
import unittest


def test_suite():
    import doctest
    import re
    try:
        import RestrictedPython
        from zope.testing import renormalizing
    except ImportError:
        return unittest.TestSuite()

    checker = renormalizing.RENormalizing([
       (re.compile(r"'ImmutableModule' object"), r'object'),
       ])
    return unittest.TestSuite((
        doctest.DocFileSuite('builtins.txt',
                             'rcompile.txt',
                             'interpreter.txt',
                             checker=checker,
                             ),
        ))
