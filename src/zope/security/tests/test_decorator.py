##############################################################################
#
# Copyright (c) 2003 Zope Foundation and Contributors.
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
"""Test zope.security.decorator
"""
import unittest

from zope.security.tests import QuietWatchingChecker


class DecoratedSecurityCheckerDescriptorTests(QuietWatchingChecker,
                                              unittest.TestCase):

    def setUp(self):
        super().setUp()
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        super().tearDown()
        from zope.security.checker import _clear
        _clear()

    def _getTargetClass(self):
        from zope.security.decorator import DecoratedSecurityCheckerDescriptor
        return DecoratedSecurityCheckerDescriptor

    def _makeOne(self):
        return self._getTargetClass()()

    def test_neither_wrapper_nor_object_has_checker(self):
        from zope.proxy import ProxyBase

        from zope.security.checker import NoProxy
        from zope.security.checker import defineChecker

        class Foo:
            a = 'a'
        defineChecker(Foo, NoProxy)
        foo = Foo()

        class Wrapper(ProxyBase):
            b = 'b'
            __Security_checker__ = self._makeOne()
        defineChecker(Wrapper, NoProxy)
        wrapper = Wrapper(foo)
        self.assertRaises(AttributeError,
                          getattr, wrapper, '__Security_checker__')

    def test_both_wrapper_and_object_have_checkers_not_security_proxied(self):
        from zope.proxy import ProxyBase

        from zope.security.checker import CombinedChecker
        from zope.security.checker import NamesChecker
        from zope.security.checker import defineChecker
        from zope.security.interfaces import ForbiddenAttribute

        class Foo:
            a = 'a'
        fooChecker = NamesChecker(['a'])  # a is public
        defineChecker(Foo, fooChecker)
        foo = Foo()
        fooChecker.check(foo, 'a')  # no raise
        self.assertRaises(ForbiddenAttribute,
                          fooChecker.check, foo, 'b')

        class Wrapper(ProxyBase):
            b = 'b'
            __Security_checker__ = self._makeOne()
        wrapperChecker = NamesChecker(['b'])  # b is public
        defineChecker(Wrapper, wrapperChecker)
        wrapper = Wrapper(foo)
        self.assertRaises(ForbiddenAttribute,
                          wrapperChecker.check, foo, 'a')
        wrapperChecker.check(foo, 'b')  # no raise

        checker = wrapper.__Security_checker__
        self.assertIsInstance(checker, CombinedChecker)
        checker.check(wrapper, 'a')  # no raise
        checker.check(wrapper, 'b')  # no raise

    def test_only_wrapper_has_checker(self):
        from zope.proxy import ProxyBase

        from zope.security.checker import NamesChecker
        from zope.security.checker import NoProxy
        from zope.security.checker import defineChecker

        class Foo:
            a = 'a'
        foo = Foo()
        defineChecker(Foo, NoProxy)

        class Wrapper(ProxyBase):
            b = 'b'
            __Security_checker__ = self._makeOne()
        wrapperChecker = NamesChecker(['b'])  # b is public
        defineChecker(Wrapper, wrapperChecker)
        wrapper = Wrapper(foo)
        self.assertIs(wrapper.__Security_checker__, wrapperChecker)

    def test_only_object_has_checker(self):
        from zope.proxy import ProxyBase

        from zope.security.checker import NamesChecker
        from zope.security.checker import NoProxy
        from zope.security.checker import defineChecker

        class Foo:
            a = 'a'
        fooChecker = NamesChecker(['a'])  # a is public
        defineChecker(Foo, fooChecker)
        foo = Foo()

        class Wrapper(ProxyBase):
            b = 'b'
            __Security_checker__ = self._makeOne()
        defineChecker(Wrapper, NoProxy)
        wrapper = Wrapper(foo)
        self.assertIs(wrapper.__Security_checker__, fooChecker)

    def test_both_wrapper_and_object_have_checkers_security_proxied(self):
        from zope.proxy import ProxyBase

        from zope.security.checker import CombinedChecker
        from zope.security.checker import NamesChecker
        from zope.security.checker import defineChecker
        from zope.security.proxy import ProxyFactory

        class Foo:
            a = 'a'
        fooChecker = NamesChecker(['a'])  # a is public
        defineChecker(Foo, fooChecker)
        foo = Foo()
        f_sec = ProxyFactory(foo)

        class Wrapper(ProxyBase):
            b = 'b'
            __Security_checker__ = self._makeOne()
        wrapperChecker = NamesChecker(['b'])  # b is public
        defineChecker(Wrapper, wrapperChecker)
        w_sec = Wrapper(f_sec)

        checker = w_sec.__Security_checker__
        self.assertIsInstance(checker, CombinedChecker)
        checker.check(w_sec, 'a')  # no raise
        checker.check(w_sec, 'b')  # no raise

    def test_cannot_overwrite(self):
        from zope.proxy import ProxyBase

        from zope.security.checker import NoProxy
        from zope.security.checker import defineChecker

        class Foo:
            a = 'a'
        defineChecker(Foo, NoProxy)
        foo = Foo()

        class Wrapper(ProxyBase):
            b = 'b'
            __Security_checker__ = self._makeOne()
        wrapper = Wrapper(foo)

        def _try():
            wrapper.__Security_checker__ = None

        self.assertRaises(TypeError, _try)


def test_suite():
    return unittest.defaultTestLoader.loadTestsFromName(__name__)
