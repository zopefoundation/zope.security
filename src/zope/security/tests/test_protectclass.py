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
"""Test handler for 'protectClass' directive
"""
import unittest


NOTSET = ()

P1 = "extravagant"
P2 = "paltry"

class Test(unittest.TestCase):

    def setUp(self):
        try:
            from zope.component.testing import setUp
        except ImportError:
            pass
        else:
            setUp()

    def tearDown(self):
        from zope.security.tests.modulehookup import TestModule
        TestModule.test_class = None
        try:
            from zope.component.testing import tearDown
        except ImportError:
            pass
        else:
            tearDown()

    def _populateModule(self):
        from zope.interface import implementer
        from zope.component import provideUtility
        from zope.security.permission import Permission
        from zope.security.interfaces import IPermission
        from zope.security.tests.modulehookup import I
        from zope.security.tests.modulehookup import TestModule

        provideUtility(Permission(P1), IPermission, P1)
        provideUtility(Permission(P2), IPermission, P2)

        class B(object):
            def m1(self):
                return "m1"
            def m2(self):
                return "m2"

        @implementer(I)
        class C(B):
            def m3(self):
                return "m3"
            def m4(self):
                return "m4"

        TestModule.test_base = B
        TestModule.test_class = C
        TestModule.test_instance = C()
        self.assertState(TestModule)
        return TestModule

    def assertState(self, module, m1P=NOTSET, m2P=NOTSET, m3P=NOTSET):
        "Verify that class, instance, and methods have expected permissions."
        from zope.security.checker import selectChecker
        checker = selectChecker(module.test_instance)
        self.assertEqual(checker.permission_id('m1'), (m1P or None))
        self.assertEqual(checker.permission_id('m2'), (m2P or None))
        self.assertEqual(checker.permission_id('m3'), (m3P or None))

    def assertSetattrState(self, module, m1P=NOTSET, m2P=NOTSET, m3P=NOTSET):
        "Verify that class, instance, and methods have expected permissions."
        from zope.security.checker import selectChecker
        checker = selectChecker(module.test_instance)
        self.assertEqual(checker.setattr_permission_id('m1'), (m1P or None))
        self.assertEqual(checker.setattr_permission_id('m2'), (m2P or None))
        self.assertEqual(checker.setattr_permission_id('m3'), (m3P or None))

    # "testSimple*" exercises tags that do NOT have children.  This mode
    # inherently sets the instances as well as the class attributes.

    def testSimpleMethodsPlural(self):
        from zope.security.protectclass import protectName
        module = self._populateModule()
        protectName(module.test_class, 'm1', P1)
        protectName(module.test_class, 'm3', P1)
        self.assertState(module, m1P=P1, m3P=P1)

    def testLikeUntoOnly(self):
        from zope.security.protectclass import protectLikeUnto
        from zope.security.protectclass import protectName
        from zope.security.protectclass import protectSetAttribute
        module = self._populateModule()
        protectName(module.test_base, 'm1', P1)
        protectName(module.test_base, 'm2', P1)
        protectSetAttribute(module.test_base, 'm1', P1)
        protectSetAttribute(module.test_base, 'm2', P1)
        protectLikeUnto(module.test_class, module.test_base)
        # m1 and m2 are in the interface, so should be set, and m3 should not:
        self.assertState(module, m1P=P1, m2P=P1)
        self.assertSetattrState(module, m1P=P1, m2P=P1)

    def testSetattr(self):
        from zope.security.protectclass import protectSetAttribute
        module = self._populateModule()
        protectSetAttribute(module.test_class, 'm1', P1)
        protectSetAttribute(module.test_class, 'm3', P1)
        self.assertSetattrState(module, m1P=P1, m3P=P1)

    def testLikeUntoAsDefault(self):
        from zope.security.protectclass import protectLikeUnto
        from zope.security.protectclass import protectName
        from zope.security.protectclass import protectSetAttribute
        module = self._populateModule()
        protectName(module.test_base, 'm1', P1)
        protectName(module.test_base, 'm2', P1)
        protectSetAttribute(module.test_base, 'm1', P1)
        protectSetAttribute(module.test_base, 'm2', P1)
        protectLikeUnto(module.test_class, module.test_base)
        protectName(module.test_class, 'm2', P2)
        protectName(module.test_class, 'm3', P2)
        protectSetAttribute(module.test_class, 'm2', P2)
        protectSetAttribute(module.test_class, 'm3', P2)
        # m1 and m2 are in the interface, so should be set, and m3 should not:
        self.assertState(module, m1P=P1, m2P=P2, m3P=P2)
        self.assertSetattrState(module, m1P=P1, m2P=P2, m3P=P2)

    def testInherited(self):
        from zope.component import provideUtility
        from zope.security.checker import selectChecker
        from zope.security.interfaces import IPermission
        from zope.security.permission import Permission
        from zope.security.protectclass import protectName

        class B1(object):
            def g(self): return 'B1.g'

        class B2(object):
            def h(self): return 'B2.h'

        class S(B1, B2):
            pass

        provideUtility(Permission('B1', ''), IPermission, 'B1')
        provideUtility(Permission('S', ''), IPermission, 'S')
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
    return unittest.TestSuite((
        unittest.makeSuite(Test),
    ))
