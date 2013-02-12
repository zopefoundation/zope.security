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

class Test_dottedName(unittest.TestCase):

    def _callFUT(self, obj):
        from zope.security.metaconfigure import dottedName
        return dottedName(obj)

    def test_dottted_name_w_None(self):
        self.assertEqual(self._callFUT(None), 'None')

    def test_dottted_name_w_class(self):
        self.assertEqual(self._callFUT(Test_dottedName),
                         'zope.security.tests.test_metaconfigure.' +
                         'Test_dottedName')


class Test_protectModule(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def _callFUT(self, module, name, permission):
        from zope.security.metaconfigure import protectModule
        return protectModule(module, name, permission)

    def test_check_wo_existing_module_checker(self):
        from zope.security import tests as module
        from zope.security.checker import _checkers
        perm = object()
        self._callFUT(module, 'name', perm)
        checker = _checkers[module]
        self.assertTrue(checker.get_permissions['name'] is perm)

    def test_check_w_existing_module_checker_zope_Public(self):
        from zope.security import tests as module
        from zope.security.checker import Checker
        from zope.security.checker import CheckerPublic
        from zope.security.checker import _checkers
        before = _checkers[module] = Checker({'other': CheckerPublic})
        self._callFUT(module, 'name', 'zope.Public')
        checker = _checkers[module]
        self.assertTrue(checker is before)
        self.assertTrue(checker.get_permissions['name'] is CheckerPublic)


def test_suite():
    return unittest.TestSuite([
        unittest.makeSuite(Test_dottedName),
        unittest.makeSuite(Test_protectModule),
    ])

