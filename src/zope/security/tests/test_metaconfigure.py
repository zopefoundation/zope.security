##############################################################################
#
# Copyright (c) 2012 Zope Foundation and Contributors.
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
"""Test ZCML directives
"""
import unittest

class Test(unittest.TestCase):

    def test_dottted_name_w_None(self):
        from zope.security.metaconfigure import dottedName
        self.assertEqual(dottedName(None), 'None')

    def test_dottted_name_w_class(self):
        from zope.security.metaconfigure import dottedName
        self.assertEqual(dottedName(Test),
                         'zope.security.tests.test_metaconfigure.Test')

def test_suite():
    return unittest.TestSuite([
        unittest.makeSuite(Test),
    ])

