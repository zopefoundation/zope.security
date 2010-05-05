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
"""Test proper protection of inherited methods

$Id$
"""
import unittest
from zope.security.checker import selectChecker
from zope.security.permission import Permission
from zope import component
from zope.component.testing import PlacelessSetup

from zope.security.interfaces import IPermission
from zope.security.protectclass import protectName

class Test(PlacelessSetup, unittest.TestCase):

    def testInherited(self):

        class B1(object):
            def g(self): return 'B1.g'

        class B2(object):
            def h(self): return 'B2.h'

        class S(B1, B2):
            pass

        component.provideUtility(Permission('B1', ''), IPermission, 'B1')
        component.provideUtility(Permission('S', ''), IPermission, 'S')
        protectName(B1, 'g', 'B1')
        protectName(S, 'g', 'S')
        protectName(S, 'h', 'S')

        self.assertEqual(selectChecker(B1()).permission_id('g'), 'B1')
        self.assertEqual(selectChecker(B2()).permission_id('h'), None)
        self.assertEqual(selectChecker(S()).permission_id('g'), 'S')
        self.assertEqual(selectChecker(S()).permission_id('h'), 'S')

        self.assertEqual(S().g(), 'B1.g')
        self.assertEqual(S().h(), 'B2.h')


def test_suite():
    return unittest.makeSuite(Test)

if __name__=='__main__':
    unittest.main(defaultTest='test_suite')
