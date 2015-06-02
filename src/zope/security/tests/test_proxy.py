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
"""Security proxy tests
"""
import unittest
import sys

from zope.security._compat import PYTHON2, PYPY, PURE_PYTHON

def _skip_if_not_Py2(testfunc):
    from functools import update_wrapper
    if not PYTHON2:
        def dummy(self):
            pass
        update_wrapper(dummy, testfunc)
        return dummy
    return testfunc

def _skip_if_Py2(testfunc):
    from functools import update_wrapper
    if PYTHON2:
        def dummy(self):
            pass
        update_wrapper(dummy, testfunc)
        return dummy
    return testfunc

def _skip_if_pypy250(testfunc):
    from functools import update_wrapper
    if PYPY and sys.pypy_version_info[:3] == (2,5,0):
        def dummy(self):
            pass
        update_wrapper(dummy, testfunc)
        return dummy
    return testfunc

class ProxyTestBase(object):

    def _makeOne(self, object, checker):
        return self._getTargetClass()(object, checker)

    def test_ctor_w_checker_None(self):
        self.assertRaises(ValueError, self._makeOne, object(), None)

    def test___getattr___w_checker_ok(self):
        class Foo(object):
            bar = 'Bar'
        target = Foo()
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy.bar, 'Bar')
        self.assertEqual(checker._checked, 'bar')
        self.assertEqual(checker._proxied, 'Bar')

    def test___getattr___w_checker_unauthorized(self):
        from zope.security.interfaces import Unauthorized
        class Foo(object):
            bar = 'Bar'
        target = Foo()
        checker = DummyChecker(Unauthorized)
        proxy = self._makeOne(target, checker)
        self.assertRaises(Unauthorized, getattr, proxy, 'bar')
        self.assertEqual(checker._checked, 'bar')

    def test___getattr___w_checker_forbidden_attribute(self):
        from zope.security.interfaces import ForbiddenAttribute
        class Foo(object):
            bar = 'Bar'
        target = Foo()
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, getattr, proxy, 'bar')
        self.assertEqual(checker._checked, 'bar')

    def test___setattr___w_checker_ok(self):
        class Foo(object):
            bar = 'Bar'
        target = Foo()
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        proxy.bar = 'Baz'
        self.assertEqual(target.bar, 'Baz')
        self.assertEqual(checker._checked, 'bar')
        self.assertEqual(checker._proxied, None)

    def test___setattr___w_checker_unauthorized(self):
        from zope.security.interfaces import Unauthorized
        class Foo(object):
            bar = 'Bar'
        target = Foo()
        checker = DummyChecker(Unauthorized)
        proxy = self._makeOne(target, checker)
        self.assertRaises(Unauthorized, setattr, proxy, 'bar', 'Baz')
        self.assertEqual(checker._checked, 'bar')

    def test___setattr___w_checker_forbidden_attribute(self):
        from zope.security.interfaces import ForbiddenAttribute
        class Foo(object):
            bar = 'Bar'
        target = Foo()
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, setattr, proxy, 'bar', 'Baz')
        self.assertEqual(checker._checked, 'bar')

    def test___delattr___w_checker_ok(self):
        class Foo(object):
            bar = None
        target = Foo()
        target.bar = 'Bar'
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        del proxy.bar
        self.assertEqual(target.bar, None)
        self.assertEqual(checker._checked, 'bar')
        self.assertEqual(checker._proxied, None)

    def test___delattr___w_checker_unauthorized(self):
        from zope.security.interfaces import Unauthorized
        class Foo(object):
            pass
        target = Foo()
        target.bar = 'Bar'
        checker = DummyChecker(Unauthorized)
        proxy = self._makeOne(target, checker)
        self.assertRaises(Unauthorized, delattr, proxy, 'bar')
        self.assertEqual(target.bar, 'Bar')
        self.assertEqual(checker._checked, 'bar')

    def test___delattr___w_checker_forbidden_attribute(self):
        from zope.security.interfaces import ForbiddenAttribute
        class Foo(object):
            pass
        target = Foo()
        target.bar = 'Bar'
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, delattr, proxy, 'bar')
        self.assertEqual(target.bar, 'Bar')
        self.assertEqual(checker._checked, 'bar')

    def test___str___checker_allows_str(self):
        target = object()
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(str(proxy), str(target))

    def test___str___checker_forbids_str(self):
        from zope.security.interfaces import ForbiddenAttribute
        from zope.security._compat import _BUILTINS
        from zope.security.proxy import _fmt_address
        target = object()
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        address = _fmt_address(target)
        self.assertEqual(str(proxy),
                         '<security proxied %s.object '
                             'instance at %s>' % (_BUILTINS, address))

    def test___repr___checker_allows_str(self):
        target = object()
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(repr(proxy), repr(target))

    def test___repr___checker_forbids_str(self):
        from zope.security.interfaces import ForbiddenAttribute
        from zope.security._compat import _BUILTINS
        from zope.security.proxy import _fmt_address
        target = object()
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        address = _fmt_address(target)
        self.assertEqual(repr(proxy),
                         '<security proxied %s.object '
                             'instance at %s>' % (_BUILTINS, address))

    @_skip_if_not_Py2
    def test___cmp___w_self(self):
        target = object()
        checker = object() # checker not consulted
        proxy = self._makeOne(target, checker)
        self.assertEqual(cmp(proxy, proxy), 0)

    @_skip_if_not_Py2
    def test___cmp___w_target(self):
        target = object()
        checker = object() # checker not consulted
        proxy = self._makeOne(target, checker)
        self.assertEqual(cmp(proxy, target), 0)

    @_skip_if_not_Py2
    def test___cmp___w_other(self):
        target = object()
        other = object()
        checker = object() # checker not consulted
        proxy = self._makeOne(target, checker)
        self.assertNotEqual(cmp(proxy, other), 0)

    @_skip_if_not_Py2
    def test___cmp___w_other_proxy(self):
        target = object()
        other = object()
        checker = object() # checker not consulted
        proxy = self._makeOne(target, checker)
        o_proxy = self._makeOne(target, checker)
        self.assertEqual(cmp(proxy, o_proxy), 0)

    def test___hash___w_self(self):
        target = object()
        checker = object() # checker not consulted
        proxy = self._makeOne(target, checker)
        self.assertEqual(hash(proxy), hash(target))

    def test___call___w_checker_ok(self):
        class Foo(object):
            def __call__(self):
                return 'Bar'
        target = Foo()
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy(), 'Bar')
        self.assertEqual(checker._checked, '__call__')
        self.assertEqual(checker._proxied, 'Bar')

    def test___call___w_checker_unauthorized(self):
        from zope.security.interfaces import Unauthorized
        class Foo(object):
            def __call__(self):
                return 'Bar'
        target = Foo()
        checker = DummyChecker(Unauthorized, ['__name__', '__str__'])
        proxy = self._makeOne(target, checker)
        self.assertRaises(Unauthorized, proxy)
        self.assertEqual(checker._checked, '__call__')

    def test___call___w_checker_forbidden_attribute(self):
        from zope.security.interfaces import ForbiddenAttribute
        class Foo(object):
            def __call__(self):
                return 'Bar'
        target = Foo()
        checker = DummyChecker(ForbiddenAttribute, ['__str__'])
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, proxy)
        self.assertEqual(checker._checked, '__call__')

    def test___int___w_checker_allows(self):
        target = 3.0
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(int(proxy), int(target))
        self.assertEqual(checker._checked, '__int__')

    def test___int___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3.0
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, int, proxy)
        self.assertEqual(checker._checked, '__int__')

    def test___float___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(float(proxy), float(target))
        self.assertEqual(checker._checked, '__float__')

    def test___float___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, float, proxy)
        self.assertEqual(checker._checked, '__float__')

    @_skip_if_not_Py2
    def test___long___w_checker_allows(self):
        target = 3.0
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(long(proxy), long(target))
        self.assertEqual(checker._checked, '__long__')

    @_skip_if_not_Py2
    def test___long___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, long, proxy)
        self.assertEqual(checker._checked, '__long__')

    @_skip_if_not_Py2
    def test___oct___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(oct(proxy), oct(target))
        self.assertEqual(checker._checked, '__oct__')

    @_skip_if_not_Py2
    def test___oct___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, oct, proxy)
        self.assertEqual(checker._checked, '__oct__')

    @_skip_if_not_Py2
    def test___hex___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(hex(proxy), hex(target))
        self.assertEqual(checker._checked, '__hex__')

    @_skip_if_not_Py2
    def test___hex___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, hex, proxy)
        self.assertEqual(checker._checked, '__hex__')

    def test___add___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy + 2, target + 2)
        self.assertEqual(checker._checked, '__add__')

    def test___add___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy + 2)
        self.assertEqual(checker._checked, '__add__')

    def test___sub___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy - 2, target - 2)
        self.assertEqual(checker._checked, '__sub__')

    def test___sub___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy - 2)
        self.assertEqual(checker._checked, '__sub__')

    def test___mul___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy * 2, target * 2)
        self.assertEqual(checker._checked, '__mul__')

    def test___mul___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy * 2)
        self.assertEqual(checker._checked, '__mul__')

    @_skip_if_not_Py2
    def test___div___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy / 2, target / 2)
        self.assertEqual(checker._checked, '__div__')

    @_skip_if_not_Py2
    def test___div___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy / 2)
        self.assertEqual(checker._checked, '__div__')

    @_skip_if_Py2
    def test___truediv___w_checker_allows(self):
        target = 3.0
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy / 2, target / 2)
        self.assertEqual(checker._checked, '__truediv__')

    @_skip_if_Py2
    def test___truediv___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3.0
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy / 2)
        self.assertEqual(checker._checked, '__truediv__')

    def test___floordiv___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy // 2, target // 2)
        self.assertEqual(checker._checked, '__floordiv__')

    def test___floordiv___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy // 2)
        self.assertEqual(checker._checked, '__floordiv__')

    def test___mod___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy % 2, target % 2)
        self.assertEqual(checker._checked, '__mod__')

    def test___mod___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy % 2)
        self.assertEqual(checker._checked, '__mod__')

    def test___divmod___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(divmod(proxy, 2), divmod(target, 2))
        self.assertEqual(checker._checked, '__divmod__')

    def test___divmod___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: divmod(proxy, 2))
        self.assertEqual(checker._checked, '__divmod__')

    def test___pow___w_x_proxied_allowed(self):
        x, y, z = 3, 4, 7
        checker = DummyChecker()
        proxy = self._makeOne(x, checker)
        self.assertEqual(pow(proxy, y, z), pow(x, y, z))
        self.assertEqual(checker._checked, '__pow__')

    def test___pow___w_x_proxied_forbidden(self):
        from zope.security.interfaces import ForbiddenAttribute
        x, y, z = 3, 4, 7
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(y, checker)
        self.assertRaises(ForbiddenAttribute, lambda: pow(proxy, y, z))
        self.assertEqual(checker._checked, '__pow__')

    def test___pow___w_y_proxied_allowed(self):
        x, y = 3, 4
        checker = DummyChecker()
        proxy = self._makeOne(y, checker)
        self.assertEqual(pow(x, proxy), pow(x, y))
        self.assertEqual(checker._checked, '__rpow__')

    def test___pow___w_y_proxied_forbidden(self):
        from zope.security.interfaces import ForbiddenAttribute
        x, y = 3, 4
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(y, checker)
        self.assertRaises(ForbiddenAttribute, lambda: pow(x, proxy))
        self.assertEqual(checker._checked, '__rpow__')

    def test___pow___w_z_proxied_allowed(self):
        x, y, z = 3, 4, 7
        checker = DummyChecker()
        proxy = self._makeOne(z, checker)
        self.assertEqual(pow(x, y, proxy), pow(x, y, z))
        self.assertEqual(checker._checked, '__3pow__')

    def test___pow___w_z_proxied_forbidden(self):
        from zope.security.interfaces import ForbiddenAttribute
        x, y, z = 3, 4, 7
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(z, checker)
        self.assertRaises(ForbiddenAttribute, lambda: pow(x, y, proxy))
        self.assertEqual(checker._checked, '__3pow__')

    def test___neg___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(-proxy, -target)
        self.assertEqual(checker._checked, '__neg__')

    def test___neg___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: -proxy)
        self.assertEqual(checker._checked, '__neg__')

    def test___pos___w_checker_allows(self):
        target = -3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(+proxy, +target)
        self.assertEqual(checker._checked, '__pos__')

    def test___pos___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = -3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: +proxy)
        self.assertEqual(checker._checked, '__pos__')

    def test___abs___w_checker_allows(self):
        target = -3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(abs(proxy), abs(target))
        self.assertEqual(checker._checked, '__abs__')

    def test___abs___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = -3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, abs, proxy)
        self.assertEqual(checker._checked, '__abs__')

    def test___bool___(self):
        target = 12
        checker = object()
        proxy = self._makeOne(target, checker)
        self.assertEqual(bool(proxy), bool(target))

    def test___invert___w_checker_allows(self):
        target = 47
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(~proxy, ~target)
        self.assertEqual(checker._checked, '__invert__')

    def test___invert___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 47
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: ~proxy)
        self.assertEqual(checker._checked, '__invert__')

    def test___lshift___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy << 2, target << 2)
        self.assertEqual(checker._checked, '__lshift__')

    def test___lshift___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy << 2)
        self.assertEqual(checker._checked, '__lshift__')

    def test___rshift___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy >> 2, target >> 2)
        self.assertEqual(checker._checked, '__rshift__')

    def test___rshift___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy >> 2)
        self.assertEqual(checker._checked, '__rshift__')

    def test___and___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy & 2, target & 2)
        self.assertEqual(checker._checked, '__and__')

    def test___and___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy & 2)
        self.assertEqual(checker._checked, '__and__')

    def test___xor___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy ^ 2, target ^ 2)
        self.assertEqual(checker._checked, '__xor__')

    def test___xor___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy ^ 2)
        self.assertEqual(checker._checked, '__xor__')

    def test___or___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy | 2, target | 2)
        self.assertEqual(checker._checked, '__or__')

    def test___or___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy | 2)
        self.assertEqual(checker._checked, '__or__')

    @_skip_if_not_Py2
    def test___coerce___w_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(coerce(proxy, 4.0), coerce(target, 4.0))
        self.assertEqual(checker._checked, '__coerce__')

    @_skip_if_not_Py2
    def test___coerce___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, coerce, proxy, 4.0)
        self.assertEqual(checker._checked, '__coerce__')

    def test___iadd___not_inplace_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy += 3
        self.assertFalse(proxy is before)
        self.assertEqual(proxy, 6)
        self.assertEqual(checker._checked, '__iadd__')

    def test___iadd___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __iadd__(self, rhs):
                self.value += rhs
                return self
        target = Foo(3)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy += 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 6)
        self.assertEqual(checker._checked, '__iadd__')

    def test___iadd___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy += 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__iadd__')

    def test___isub___not_inplace_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy -= 3
        self.assertFalse(proxy is before)
        self.assertEqual(proxy, 0)
        self.assertEqual(checker._checked, '__isub__')

    def test___isub___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __isub__(self, rhs):
                self.value -= rhs
                return self
        target = Foo(3)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy -= 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 0)
        self.assertEqual(checker._checked, '__isub__')

    def test___isub___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy -= 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__isub__')

    def test___imul___not_inplace_checker_allows(self):
        target = 3
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy *= 3
        self.assertFalse(proxy is before)
        self.assertEqual(proxy, 9)
        self.assertEqual(checker._checked, '__imul__')

    def test___imul___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __imul__(self, rhs):
                self.value *= rhs
                return self
        target = Foo(3)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy *= 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 9)
        self.assertEqual(checker._checked, '__imul__')

    def test___imul___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 3
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy *= 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__imul__')

    @_skip_if_not_Py2
    def test___idiv___not_inplace_checker_allows(self):
        target = 6
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy /= 3
        self.assertFalse(proxy is before)
        self.assertEqual(proxy, 2)
        self.assertEqual(checker._checked, '__idiv__')

    @_skip_if_not_Py2
    def test___idiv___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __idiv__(self, rhs):
                self.value /= rhs
                return self
        target = Foo(6)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy /= 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 2)
        self.assertEqual(checker._checked, '__idiv__')

    @_skip_if_not_Py2
    def test___idiv___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 6
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy /= 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__idiv__')

    @_skip_if_Py2
    def test___itruediv___not_inplace_checker_allows(self):
        target = 6
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy /= 3
        self.assertFalse(proxy is before)
        self.assertEqual(proxy, 2)
        self.assertEqual(checker._checked, '__itruediv__')

    @_skip_if_Py2
    def test___itruediv___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __itruediv__(self, rhs):
                self.value /= rhs
                return self
        target = Foo(6)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy /= 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 2)
        self.assertEqual(checker._checked, '__itruediv__')

    @_skip_if_Py2
    def test___itruediv___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 6
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy /= 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__itruediv__')

    def test___ifloordiv___not_inplace_checker_allows(self):
        target = 6
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy //= 3
        self.assertFalse(proxy is before)
        self.assertEqual(proxy, 2)
        self.assertEqual(checker._checked, '__ifloordiv__')

    def test___ifloordiv___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __ifloordiv__(self, rhs):
                self.value //= rhs
                return self
        target = Foo(6)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy //= 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 2)
        self.assertEqual(checker._checked, '__ifloordiv__')

    def test___ifloordiv___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 6
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy //= 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__ifloordiv__')

    def test___imod___not_inplace_checker_allows(self):
        target = 6
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy %= 3
        self.assertFalse(proxy is before)
        self.assertEqual(proxy, 0)
        self.assertEqual(checker._checked, '__imod__')

    def test___imod___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __imod__(self, rhs):
                self.value %= rhs
                return self
        target = Foo(6)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy %= 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 0)
        self.assertEqual(checker._checked, '__imod__')

    def test___imod___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 6
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy %= 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__imod__')

    def test___ipow___not_inplace_checker_allows(self):
        target = 2
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy **= 3
        self.assertFalse(proxy is before)
        self.assertEqual(proxy, 8)
        self.assertEqual(checker._checked, '__ipow__')

    def test___ipow___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __ipow__(self, rhs):
                self.value **= rhs
                return self
        target = Foo(2)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy **= 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 8)
        self.assertEqual(checker._checked, '__ipow__')

    def test___ipow___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 2
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy **= 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__ipow__')

    def test___ilshift___not_inplace_checker_allows(self):
        target = 2
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy <<= 3
        self.assertFalse(proxy is before)
        self.assertEqual(proxy, 16)
        self.assertEqual(checker._checked, '__ilshift__')

    def test___ilshift___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __ilshift__(self, rhs):
                self.value <<= rhs
                return self
        target = Foo(2)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy <<= 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 16)
        self.assertEqual(checker._checked, '__ilshift__')

    def test___ilshift___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 2
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy <<= 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__ilshift__')

    def test___irshift___not_inplace_checker_allows(self):
        target = 16
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy >>= 3
        self.assertFalse(proxy is before)
        self.assertEqual(proxy, 2)
        self.assertEqual(checker._checked, '__irshift__')

    def test___irshift___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __irshift__(self, rhs):
                self.value >>= rhs
                return self
        target = Foo(16)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy >>= 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 2)
        self.assertEqual(checker._checked, '__irshift__')

    def test___irshift___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 16
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy >>= 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__irshift__')

    def test___iand___not_inplace_checker_allows(self):
        target = 7
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy &= 3
        self.assertFalse(proxy is before)
        self.assertEqual(proxy, 3)
        self.assertEqual(checker._checked, '__iand__')

    def test___iand___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __iand__(self, rhs):
                self.value &= rhs
                return self
        target = Foo(7)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy &= 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 3)
        self.assertEqual(checker._checked, '__iand__')

    def test___iand___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 7
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy &= 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__iand__')

    def test___ixor___not_inplace_checker_allows(self):
        target = 7
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy ^= 3
        self.assertFalse(proxy is before)
        self.assertEqual(checker._checked, '__ixor__')
        self.assertEqual(proxy, 4)

    def test___ixor___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __ixor__(self, rhs):
                self.value ^= rhs
                return self
        target = Foo(7)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy ^= 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 4)
        self.assertEqual(checker._checked, '__ixor__')

    def test___ixor___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 7
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy ^= 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__ixor__')

    def test___ior___not_inplace_checker_allows(self):
        target = 6
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy |= 3
        self.assertFalse(proxy is before)
        self.assertEqual(proxy, 7)
        self.assertEqual(checker._checked, '__ior__')

    def test___ior___inplace_checker_allows(self):
        class Foo(object):
            def __init__(self, value):
                self.value = value
            def __ior__(self, rhs):
                self.value |= rhs
                return self
        target = Foo(6)
        checker = DummyChecker()
        proxy = before = self._makeOne(target, checker)
        proxy |= 3
        self.assertTrue(proxy is before)
        self.assertEqual(target.value, 7)
        self.assertEqual(checker._checked, '__ior__')

    def test___ior___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = 6
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        try:
            proxy |= 3
        except ForbiddenAttribute:
            pass
        else:
            self.fail()
        self.assertEqual(checker._checked, '__ior__')

    def test___len___w_checker_allows(self):
        target = [0, 1, 2]
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(len(proxy), len(target))
        self.assertEqual(checker._checked, '__len__')

    def test___len___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = [0, 1, 2]
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, len, proxy)
        self.assertEqual(checker._checked, '__len__')

    def test___contains___hit_w_checker_allows(self):
        target = [0, 1, 2]
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertTrue(1 in proxy)
        self.assertEqual(checker._checked, '__contains__')

    def test___contains___miss_w_checker_allows(self):
        target = [0, 1, 2]
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertFalse(4 in proxy)
        self.assertEqual(checker._checked, '__contains__')

    def test___contains___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = [0, 1, 2]
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: 0 in proxy)
        self.assertEqual(checker._checked, '__contains__')

    def test___getitem___sequence_hit_w_checker_allows(self):
        target = [0, 1, 2]
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy[1], 1)
        self.assertEqual(checker._checked, '__getitem__')

    def test___getitem___sequence_miss_w_checker_allows(self):
        target = [0, 1, 2]
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertRaises(IndexError, lambda: proxy[4])
        self.assertEqual(checker._checked, '__getitem__')

    def test___getitem___sequence_w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = [0, 1, 2]
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy[0])
        self.assertEqual(checker._checked, '__getitem__')

    def test___setitem___sequence_hit_w_checker_allows(self):
        target = [0, 1, 2]
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        proxy[1] = 7
        self.assertEqual(target[1], 7)
        self.assertEqual(checker._checked, '__setitem__')

    def test___setitem___sequence_miss_w_checker_allows(self):
        target = [0, 1, 2]
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        def _try():
            proxy[4] = 7
        self.assertRaises(IndexError, _try)
        self.assertEqual(checker._checked, '__setitem__')

    def test___setitem___sequence_w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = [0, 1, 2]
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        def _try():
            proxy[4] = 7
        self.assertRaises(ForbiddenAttribute, _try)
        self.assertEqual(checker._checked, '__setitem__')

    @_skip_if_not_Py2
    def test___getslice___w_checker_allows(self):
        target = [0, 1, 2]
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy[1:3], [1, 2])
        self.assertEqual(checker._checked, '__getslice__')

    @_skip_if_not_Py2
    def test___getslice___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = [0, 1, 2]
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy[0:2])
        self.assertEqual(checker._checked, '__getslice__')

    @_skip_if_not_Py2
    def test___setslice___w_checker_allows(self):
        target = [0, 1, 2]
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        proxy[1:3] = [3, 4]
        self.assertEqual(target, [0, 3, 4])
        self.assertEqual(checker._checked, '__setslice__')

    @_skip_if_not_Py2
    def test___setslice___w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = [0, 1, 2]
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        def _try():
            proxy[1:3] = [3, 4]
        self.assertRaises(ForbiddenAttribute, _try)
        self.assertEqual(checker._checked, '__setslice__')

    def test___getitem___mapping_hit_w_checker_allows(self):
        target = {'a': 0, 'b': 1, 'c': 2}
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertEqual(proxy['b'], 1)
        self.assertEqual(checker._checked, '__getitem__')

    def test___getitem___mapping_miss_w_checker_allows(self):
        target = {'a': 0, 'b': 1, 'c': 2}
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        self.assertRaises(KeyError, lambda: proxy['d'])
        self.assertEqual(checker._checked, '__getitem__')

    def test___getitem___mapping_w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = {'a': 0, 'b': 1, 'c': 2}
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        self.assertRaises(ForbiddenAttribute, lambda: proxy['b'])
        self.assertEqual(checker._checked, '__getitem__')

    def test___setitem___mapping_hit_w_checker_allows(self):
        target = {'a': 0, 'b': 1, 'c': 2}
        checker = DummyChecker()
        proxy = self._makeOne(target, checker)
        proxy['a'] = 7
        self.assertEqual(target['a'], 7)
        self.assertEqual(checker._checked, '__setitem__')

    def test___setitem___mapping_w_checker_forbids(self):
        from zope.security.interfaces import ForbiddenAttribute
        target = {'a': 0, 'b': 1, 'c': 2}
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(target, checker)
        def _try():
            proxy['a'] = 7
        self.assertRaises(ForbiddenAttribute, _try)
        self.assertEqual(checker._checked, '__setitem__')

    binops = [
        "x+y", "x-y", "x*y", "x/y", "divmod(x, y)", "x**y", "x//y",
        "x<<y", "x>>y", "x&y", "x|y", "x^y",
        ]

    def test_binops(self):
        from zope.security.proxy import removeSecurityProxy
        checker = DummyChecker()
        for expr in self.binops:
            first = 1
            for x in [1, self._makeOne(1, checker)]:
                for y in [2, self._makeOne(2, checker)]:
                    if first:
                        z = eval(expr)
                        first = 0
                    else:
                        self.assertEqual(removeSecurityProxy(eval(expr)), z,
                                         "x=%r; y=%r; expr=%r" % (x, y, expr))


class ProxyCTests(unittest.TestCase, ProxyTestBase):

    def _getTargetClass(self):
        from zope.security.proxy import _Proxy
        return _Proxy


class ProxyPyTests(unittest.TestCase, ProxyTestBase):

    def _getTargetClass(self):
        from zope.security.proxy import ProxyPy
        return ProxyPy

    def test_wrapper_checker_unaccessible(self):
        # Can't access '_wrapped' / '_checker' in C version
        target = object()
        checker = object()
        proxy = self._makeOne(target, checker)
        self.assertRaises(AttributeError, getattr, proxy, '_wrapped')
        self.assertRaises(AttributeError, getattr, proxy, '_checker')

    def test_ctor_w_checker(self):
        from zope.security.proxy import getObjectPy, getCheckerPy
        # Can't access '_wrapped' / '_checker' in C version
        target = object()
        checker = object()
        proxy = self._makeOne(target, checker)
        self.assertTrue(getObjectPy(proxy) is target)
        self.assertTrue(getCheckerPy(proxy) is checker)

    def test___delattr___w__wrapped(self):
        target = object()
        checker = object()
        proxy = self._makeOne(target, checker)
        def test():
            del proxy._wrapped
        self.assertRaises(AttributeError, test)

    def test___delattr___w__checker(self):
        target = object()
        checker = object()
        proxy = self._makeOne(target, checker)
        def test():
            del proxy._checker
        self.assertRaises(AttributeError, test)

    def test___pow___w_z_proxied_allowed(self):
        x, y, z = 3, 4, 7
        checker = DummyChecker()
        proxy = self._makeOne(z, checker)
        # Disabled, because a PyProxy cannot lie about its type, so
        # pow(i, j, proxy(k)) will fail with a TypeError
        self.assertRaises(TypeError, pow, (x, y, proxy))

    def test___pow___w_z_proxied_forbidden(self):
        from zope.security.interfaces import ForbiddenAttribute
        x, y, z = 3, 4, 7
        checker = DummyChecker(ForbiddenAttribute)
        proxy = self._makeOne(z, checker)
        # Disabled, because a PyProxy cannot lie about its type, so
        # pow(i, j, proxy(k)) will fail with a TypeError
        self.assertRaises(TypeError, pow, (x, y, proxy))

    def test_getObjectPy_initial_conditions(self):
        # Once upon a time, we dynamically set _builtin_isinstance
        # in z.s.proxy.isinstance itself. And at that time getObjectPy
        # (aka removeSecurityProxy) called z.s.proxy.isinstance if
        # _builtin_isinstance was not set...which recursively calls
        # getObjectPy. The net result was that the very first call
        # to getObjectPy would falsely return the proxy object if passed
        # a proxy, not the wrapped object!
        # This test makes sure we're not dynamically setting that attribute
        # any more.
        import zope.security.proxy

        target = object()
        checker = object()
        proxy = self._makeOne(target, checker)

        orig_builtin_isinstance = zope.security.proxy._builtin_isinstance
        zope.security.proxy._builtin_isinstance = None
        try:
            self.assertRaises(TypeError, zope.security.proxy.getObjectPy, proxy)
        finally:
            zope.security.proxy._builtin_isinstance = orig_builtin_isinstance

class DummyChecker(object):
    _proxied = _checked = None
    def __init__(self, raising=None, allowed=()):
        self._raising = raising
        self._allowed = allowed
    def check(self, target, name):
        self._checked = name
        if name not in self._allowed:
            if self._raising is not None:
                raise self._raising(name)
    check_getattr = check_setattr = check
    def proxy(self, value):
        self._proxied = value
        return value


class Test_getTestProxyItems(unittest.TestCase):

    def _callFUT(self, proxy):
        from zope.security.proxy import getTestProxyItems
        return getTestProxyItems(proxy)

    def test_w_empty_checker(self):
        from zope.security.checker import Checker
        from zope.security.proxy import Proxy
        target = object()
        proxy = Proxy(target, Checker({}))
        self.assertEqual(self._callFUT(proxy), [])

    def test_w_non_empty_checker(self):
        from zope.security.checker import Checker
        from zope.security.checker import CheckerPublic
        from zope.security.proxy import Proxy
        target = object()
        permission = object()
        proxy = Proxy(target,
                      Checker({'foo': CheckerPublic, 'bar': permission}))
        self.assertEqual(self._callFUT(proxy),
                         [('bar', permission), ('foo', CheckerPublic)])


class Test_isinstance(unittest.TestCase):

    def _callFUT(self, object, cls):
        from zope.security.proxy import isinstance
        return isinstance(object, cls)

    def test_w_unproxied_object(self):
        class Foo(object):
            pass
        target = Foo()
        self.assertTrue(self._callFUT(target, Foo))
        self.assertFalse(self._callFUT(target, int))

    def test_w_proxied_object(self):
        from zope.security.checker import Checker
        from zope.security.proxy import Proxy
        class Foo(object):
            pass
        target = Foo()
        proxy = Proxy(target, Checker({}))
        self.assertTrue(self._callFUT(proxy, Foo))
        self.assertFalse(self._callFUT(proxy, int))


# pre-geddon

class Checker(object):

    ok = 1

    unproxied_types = str,

    def check_getattr(self, object, name):
        if name not in ("foo", "next", "__class__", "__name__", "__module__"):
            raise RuntimeError

    def check_setattr(self, object, name):
        if name != "foo":
            raise RuntimeError

    def check(self, object, opname):
        if not self.ok:
            raise RuntimeError

    def proxy(self, value):
        from zope.security.proxy import ProxyFactory
        if type(value) in self.unproxied_types:
            return value
        return ProxyFactory(value, self)


class Something:
    def __init__(self):
        self.foo = [1,2,3]
    def __getitem__(self, key):
        return self.foo[key]
    def __setitem__(self, key, value):
        self.foo[key] = value
    def __delitem__(self, key):
        del self.foo[key]
    def __call__(self, arg):
        return 42
    def __eq__(self, other):
        return self is other
    def __hash__(self):
        return 42
    def __iter__(self):
        return self
    def __next__(self):
        return 42 # Infinite sequence
    next = __next__
    def __len__(self):
        return 42
    def __nonzero__(self):
        return 1
    def __getslice__(self, i, j):
        return [42]
    def __setslice__(self, i, j, value):
        if value != [42]:
            raise ValueError
    def __contains__(self, x):
        return x == 42


class ProxyTests(unittest.TestCase):

    def setUp(self):
        from zope.security.proxy import ProxyFactory
        self.x = Something()
        self.c = Checker()
        self.p = ProxyFactory(self.x, self.c)

    def shouldFail(self, *args):
        self.c.ok = 0
        self.assertRaises(RuntimeError, *args)
        self.c.ok = 1

    def testDerivation(self):
        from zope.security._compat import PURE_PYTHON
        if PURE_PYTHON:
            from zope.proxy import PyProxyBase as ProxyBase
        else:
            from zope.proxy import ProxyBase
        self.assertTrue(isinstance(self.p, ProxyBase))

    def testStr(self):
        from zope.security.proxy import ProxyFactory
        self.assertEqual(str(self.p), str(self.x))

        x = Something()
        c = Checker()
        c.ok = 0
        p = ProxyFactory(x, c)
        s = str(p)
        self.assertTrue(s.startswith(
            "<security proxied %s.%s instance at"
            % (x.__class__.__module__, x.__class__.__name__)),
                        s)

    def testRepr(self):
        from zope.security.proxy import ProxyFactory
        self.assertEqual(repr(self.p), repr(self.x))

        x = Something()
        c = Checker()
        c.ok = 0
        p = ProxyFactory(x, c)
        s = repr(p)
        self.assertTrue(s.startswith(
            "<security proxied %s.%s instance at"
            % (x.__class__.__module__, x.__class__.__name__)),
                        s)

    def testGetAttrOK(self):
        from zope.security.proxy import removeSecurityProxy
        self.assertEqual(removeSecurityProxy(self.p.foo), [1,2,3])

    def testGetAttrFail(self):
        self.assertRaises(RuntimeError, lambda: self.p.bar)

    def testSetAttrOK(self):
        self.p.foo = 42
        self.assertEqual(self.p.foo, 42)

    def testSetAttrFail(self):
        def doit(): self.p.bar = 42
        self.assertRaises(RuntimeError, doit)

    def testGetItemOK(self):
        self.assertEqual(self.p[0], 1)

    def testGetItemFail(self):
        self.shouldFail(lambda: self.p[10])

    def testSetItemOK(self):
        self.p[0] = 42
        self.assertEqual(self.p[0], 42)

    def testSetItemFail(self):
        def doit(): del self.p[0]
        self.shouldFail(doit)

    def testDelItemOK(self):
        self.p[0] = 42
        self.assertEqual(self.p[0], 42)
        del self.p[0]
        self.shouldFail(lambda: self.p[0])

    def testDelItemFail(self):
        def doit(): self.p[10] = 42
        self.shouldFail(doit)

    def testCallOK(self):
        self.assertEqual(self.p(None), 42)

    def testCallFail(self):
        self.shouldFail(self.p, None)

    def testRichCompareOK(self):
        self.assertTrue(self.p == self.x)

##     def testRichCompareFail(self):
##         self.shouldFail(lambda: self.p == self.x)

    def testIterOK(self):
        from zope.security.proxy import removeSecurityProxy
        self.assertEqual(removeSecurityProxy(iter(self.p)), self.x)

    def testIterFail(self):
        self.shouldFail(iter, self.p)

    def testNextOK(self):
        self.assertEqual(self.p.next(), 42)

    def testNextFail(self):
        self.shouldFail(self.p.next)

    @_skip_if_not_Py2
    def testCompareOK(self):
        self.assertEqual(cmp(self.p, self.x), 0)

##     def testCompareFail(self):
##         self.shouldFail(cmp, self.p, self.x)

    def testHashOK(self):
        self.assertEqual(hash(self.p), hash(self.x))

##     def testHashFail(self):
##         self.shouldFail(hash, self.p)

    def testNonzeroOK(self):
        self.assertEqual(not self.p, 0)

##     def testNonzeroFail(self):
##         self.shouldFail(lambda: not self.p)

    def testLenOK(self):
        self.assertEqual(len(self.p), 42)

    def testLenFail(self):
        self.shouldFail(len, self.p)

    @_skip_if_not_Py2
    def testSliceOK(self):
        from zope.security.proxy import removeSecurityProxy
        self.assertEqual(removeSecurityProxy(self.p[:]), [42])

    def testSliceFail(self):
        self.shouldFail(lambda: self.p[:])

    def testSetSliceOK(self):
        self.p[:] = [42]

    def testSetSliceFail(self):
        def doit(): self.p[:] = [42]
        self.shouldFail(doit)

    def testContainsOK(self):
        self.assertTrue(42 in self.p)

    def testContainsFail(self):
        self.shouldFail(lambda: 42 in self.p)

    def testGetObject(self):
        from zope.security.proxy import removeSecurityProxy
        self.assertEqual(self.x, removeSecurityProxy(self.p))

    def testGetChecker(self):
        from zope.security.proxy import getChecker
        self.assertEqual(self.c, getChecker(self.p))


    # XXX: PyPy 2.5.0 has a bug where proxys around types
    # aren't correctly hashable, which breaks this part of the
    # test. This is fixed in 2.5.1+, but as of 2015-05-28,
    # TravisCI still uses 2.5.0.

    @_skip_if_pypy250
    def testProxiedClassicClassAsDictKey(self):
        from zope.security.proxy import ProxyFactory
        class C(object):
            pass
        d = {C: C()}
        pC = ProxyFactory(C, self.c)
        self.assertEqual(d[pC], d[C])

    @_skip_if_pypy250
    def testProxiedNewClassAsDictKey(self):
        from zope.security.proxy import ProxyFactory
        class C(object):
            pass
        d = {C: C()}
        pC = ProxyFactory(C, self.c)
        self.assertEqual(d[pC], d[C])

    unops = ["-x", "+x", "abs(x)", "~x", "int(x)", "float(x)"]
    if PYTHON2:
        unops.append("long(x)")

    def test_unops(self):
        # We want the starting value of the expressions to be a proxy,
        # but we don't want to create new proxies as a result of
        # evaluation, so we have to extend the list of types that
        # aren't proxied.
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import removeSecurityProxy
        self.c.unproxied_types = [str, int, float]
        if PYTHON2:
            self.c.unproxied_types.append(long)
        for expr in self.unops:
            x = 1
            y = eval(expr)
            # Make sure 'x' is a proxy always:
            x = ProxyFactory(1, self.c)
            z = eval(expr)
            self.assertEqual(removeSecurityProxy(z), y,
                             "x=%r; expr=%r" % (x, expr))
            self.shouldFail(lambda x: eval(expr), x)

    @_skip_if_not_Py2
    def test_odd_unops(self):
        # unops that don't return a proxy
        P = self.c.proxy
        for func in (
            hex, oct,
            # lambda x: not x,
            ):
            self.assertEqual(func(P(100)), func(100))
            self.shouldFail(func, P(100))

    binops = [
        "x+y", "x-y", "x*y", "x/y", "divmod(x, y)", "x**y", "x//y",
        "x<<y", "x>>y", "x&y", "x|y", "x^y",
        ]

    def test_binops(self):
        from zope.security.proxy import removeSecurityProxy
        P = self.c.proxy
        for expr in self.binops:
            first = 1
            for x in [1, P(1)]:
                for y in [2, P(2)]:
                    if first:
                        z = eval(expr)
                        first = 0
                    else:
                        self.assertEqual(removeSecurityProxy(eval(expr)), z,
                                         "x=%r; y=%r; expr=%r" % (x, y, expr))
                        self.shouldFail(lambda x, y: eval(expr), x, y)

    def test_inplace(self):
        # TODO: should test all inplace operators...
        from zope.security.proxy import removeSecurityProxy
        P = self.c.proxy

        pa = P(1)
        pa += 2
        self.assertEqual(removeSecurityProxy(pa), 3)

        a = [1, 2, 3]
        pa = qa = P(a)
        pa += [4, 5, 6]
        self.assertTrue(pa is qa)
        self.assertEqual(a, [1, 2, 3, 4, 5, 6])

        def doit():
            pa = P(1)
            pa += 2
        self.shouldFail(doit)

        pa = P(2)
        pa **= 2
        self.assertEqual(removeSecurityProxy(pa), 4)

        def doit():
            pa = P(2)
            pa **= 2
        self.shouldFail(doit)

    @_skip_if_not_Py2
    def test_coerce(self):
        from zope.security.proxy import removeSecurityProxy
        P = self.c.proxy

        # Before 2.3, coerce() of two proxies returns them unchanged
        import sys
        fixed_coerce = sys.version_info >= (2, 3, 0)

        x = P(1)
        y = P(2)
        a, b = coerce(x, y)
        self.assertTrue(a is x and b is y)

        x = P(1)
        y = P(2.1)
        a, b = coerce(x, y)
        self.assertTrue(removeSecurityProxy(a) == 1.0 and b is y)
        if fixed_coerce:
            self.assertTrue(type(removeSecurityProxy(a)) is float and b is y)

        x = P(1.1)
        y = P(2)
        a, b = coerce(x, y)
        self.assertTrue(a is x and removeSecurityProxy(b) == 2.0)
        if fixed_coerce:
            self.assertTrue(a is x and type(removeSecurityProxy(b)) is float)

        x = P(1)
        y = 2
        a, b = coerce(x, y)
        self.assertTrue(a is x and b is y)

        x = P(1)
        y = 2.1
        a, b = coerce(x, y)
        self.assertTrue(type(removeSecurityProxy(a)) is float and b is y)

        x = P(1.1)
        y = 2
        a, b = coerce(x, y)
        self.assertTrue(a is x and type(removeSecurityProxy(b)) is float)

        x = 1
        y = P(2)
        a, b = coerce(x, y)
        self.assertTrue(a is x and b is y)

        x = 1.1
        y = P(2)
        a, b = coerce(x, y)
        self.assertTrue(a is x and type(removeSecurityProxy(b)) is float)

        x = 1
        y = P(2.1)
        a, b = coerce(x, y)
        self.assertTrue(type(removeSecurityProxy(a)) is float and b is y)


def test_using_mapping_slots_hack():
    """The security proxy will use mapping slots, on the checker to go faster

    If a checker implements normally, a checkers's check and
    check_getattr methods are used to check operator and attribute
    access:

      >>> from zope.security.proxy import ProxyFactory
      >>> log = []
      >>> def dump():
      ...     out = '\\n'.join(log)
      ...     del log[:]
      ...     return out
      >>> class Checker(object):
      ...     def check(self, object, name):
      ...         log.append(('check %s' % name))
      ...     def check_getattr(self, object, name):
      ...         log.append(('check_getattr %s' % name))
      ...     def proxy(self, object):
      ...         return 1
      >>> def f():
      ...     pass
      >>> p = ProxyFactory(f, Checker())
      >>> p.__name__
      1
      >>> dump()
      'check_getattr __name__'
      >>> p()
      1
      >>> dump()
      'check __call__'

    But, if the checker has a __setitem__ method:

      >>> def __setitem__(self, object, name):
      ...     log.append(('__setitem__ %s' % name))
      >>> Checker.__setitem__ = __setitem__

    It will be used rather than either check or check_getattr:

      >>> p.__name__
      1
      >>> dump()
      '__setitem__ __name__'
      >>> p()
      1
      >>> dump()
      '__setitem__ __call__'

    If a checker has a __getitem__ method:

      >>> def __getitem__(self, object):
      ...     return 2
      >>> Checker.__getitem__ = __getitem__

    It will be used rather than it's proxy method:

      >>> p.__name__
      2
      >>> dump()
      '__setitem__ __name__'
      >>> p()
      2
      >>> dump()
      '__setitem__ __call__'

    """


class LocationProxySecurityCheckerTests(unittest.TestCase):

    def test_LocationProxy_gets_a_security_checker_when_importing_z_security(
            self):
        # Regression test for a problem introduced in 3.8.1 and fixed in
        # 3.8.3. For details see change log.
        import sys
        from zope.location.location import LocationProxy
        import zope.security
        from zope.security._compat import reload
        # This attribute is set when zope.security.decorator is imported, to
        # show that it will be set too, if zope.security.proxy is imported
        # we set it to a different value at first:
        del LocationProxy.__Security_checker__
        self.assertFalse(
            hasattr(LocationProxy, '__Security_checker__'))
        # After deleting zope.security.decorator and reloading
        # zope.security.proxy the attribute is set again:
        del sys.modules["zope.security.decorator"]
        reload(zope.security)
        self.assertTrue(
            hasattr(LocationProxy, '__Security_checker__'))


def test_suite():
    suite = unittest.TestSuite((
        unittest.makeSuite(ProxyPyTests),
        unittest.makeSuite(Test_getTestProxyItems),
        unittest.makeSuite(Test_isinstance),
        # pre-geddon
        unittest.makeSuite(ProxyTests),
        unittest.makeSuite(LocationProxySecurityCheckerTests),
    ))
    if not (PYPY or PURE_PYTHON):
        suite.addTest(unittest.makeSuite(ProxyCTests))
    return suite
