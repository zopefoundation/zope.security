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

from zope.security.interfaces import PUBLIC_PERMISSION_NAME as zope_Public


class Test_protectName(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def _callFUT(self, class_, name, permission):
        from zope.security.protectclass import protectName
        return protectName(class_, name, permission)

    def test_wo_existing_checker_w_zope_Public(self):
        from zope.security.checker import CheckerPublic
        from zope.security.checker import _checkers
        self._callFUT(Foo, 'bar', zope_Public)
        self.assertTrue(_checkers[Foo].get_permissions['bar'] is CheckerPublic)

    def test_w_existing_checker(self):
        from zope.security.checker import Checker
        from zope.security.checker import _checkers
        checker = _checkers[Foo] = Checker({})
        permission = object()
        self._callFUT(Foo, 'bar', permission)
        self.assertTrue(_checkers[Foo] is checker)
        self.assertTrue(checker.get_permissions['bar'] is permission)


class Test_protectSetAttribute(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def _callFUT(self, class_, name, permission):
        from zope.security.protectclass import protectSetAttribute
        return protectSetAttribute(class_, name, permission)

    def test_wo_existing_checker_w_zope_Public(self):
        from zope.security.checker import CheckerPublic
        from zope.security.checker import _checkers
        self._callFUT(Foo, 'bar', zope_Public)
        self.assertTrue(_checkers[Foo].set_permissions['bar'] is CheckerPublic)

    def test_w_existing_checker(self):
        from zope.security.checker import Checker
        from zope.security.checker import _checkers
        checker = _checkers[Foo] = Checker({})
        permission = object()
        self._callFUT(Foo, 'bar', permission)
        self.assertTrue(_checkers[Foo] is checker)
        self.assertTrue(checker.set_permissions['bar'] is permission)


class Test_protectLikeUnto(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def _callFUT(self, class_, like_unto):
        from zope.security.protectclass import protectLikeUnto
        return protectLikeUnto(class_, like_unto)

    def test_wo_existing_like_unto_checker(self):
        from zope.security.checker import _checkers
        self.assertFalse(Foo in _checkers)
        self._callFUT(Bar, Foo)
        self.assertFalse(Foo in _checkers)
        self.assertFalse(Bar in _checkers)

    def test_w_existing_like_unto_checker_wo_existing_checker(self):
        from zope.security.checker import Checker
        from zope.security.checker import CheckerPublic
        from zope.security.checker import _checkers
        from zope.security.checker import defineChecker
        permission = object()
        foo_checker = Checker({'bar': CheckerPublic}, {'bar': permission})
        defineChecker(Foo, foo_checker)
        self._callFUT(Bar, Foo)
        bar_checker = _checkers[Bar]
        self.assertEqual(bar_checker.get_permissions,
                         foo_checker.get_permissions)
        self.assertEqual(bar_checker.set_permissions,
                         foo_checker.set_permissions)

    def test_w_existing_like_unto_checker_w_existing_checker(self):
        from zope.security.checker import Checker
        from zope.security.checker import CheckerPublic
        from zope.security.checker import _checkers
        from zope.security.checker import defineChecker
        permission1, permission2 = object(), object()
        foo_checker = Checker({'bar': CheckerPublic}, {'bar': permission2})
        defineChecker(Foo, foo_checker)
        bar_checker = Checker({'bar': permission1, 'baz': CheckerPublic}, {})
        defineChecker(Bar, bar_checker)
        self._callFUT(Bar, Foo)
        bar_checker = _checkers[Bar]
        self.assertEqual(bar_checker.get_permissions,
                         {'bar': CheckerPublic, 'baz': CheckerPublic})
        self.assertEqual(bar_checker.set_permissions,
                         foo_checker.set_permissions)


class Foo:
    bar = 'Bar'


class Bar(Foo):
    baz = 'Baz'


def test_suite():
    return unittest.TestSuite((
        unittest.defaultTestLoader.loadTestsFromTestCase(Test_protectName),
        unittest.defaultTestLoader.loadTestsFromTestCase(
            Test_protectSetAttribute),
        unittest.defaultTestLoader.loadTestsFromTestCase(Test_protectLikeUnto),
    ))
