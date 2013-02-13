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

from zope.security._compat import PYTHON2

def _skip_if_not_Py2(testfunc):
    from functools import update_wrapper
    if not PYTHON2:
        def dummy(self):
            pass
        update_wrapper(dummy, testfunc)
        return dummy
    return testfunc


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

    def testProxiedClassicClassAsDictKey(self):
        from zope.security.proxy import ProxyFactory
        class C(object):
            pass
        d = {C: C()}
        pC = ProxyFactory(C, self.c)
        self.assertEqual(d[pC], d[C])

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

    def test_LocationProxy_gets_a_security_checker_when_importing_z_s_proxy(
            self):
        # Regression test for a problem introduced in 3.8.1 and fixed in
        # 3.8.3. For details see change log.
        import sys
        from zope.location.location import LocationProxy
        import zope.security.proxy
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
        reload(zope.security.proxy)
        self.assertTrue(
            hasattr(LocationProxy, '__Security_checker__'))


def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(Test_getTestProxyItems),
        unittest.makeSuite(Test_isinstance),
        # pre-geddon
        unittest.makeSuite(ProxyTests),
        unittest.makeSuite(LocationProxySecurityCheckerTests),
    ))
