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
"""Test checkers for standard types

This is a test of the assertions made in
zope.security.checkers._default_checkers.
"""
import unittest

def check_forbidden_get(object, attr):
    from zope.security.interfaces import ForbiddenAttribute
    try:
        return getattr(object, attr)
    except ForbiddenAttribute, e:
        return 'ForbiddenAttribute: %s' % e[0]


def check_forbidden_setitem(object, item, value):
    from zope.security.interfaces import ForbiddenAttribute
    try:
        object[item] = value
    except ForbiddenAttribute, e:
        return 'ForbiddenAttribute: %s' % e[0]


def check_forbidden_delitem(object, item):
    from zope.security.interfaces import ForbiddenAttribute
    try:
        del object[item]
    except ForbiddenAttribute, e:
        return 'ForbiddenAttribute: %s' % e[0]


def check_forbidden_call(callable, *args):
    from zope.security.interfaces import ForbiddenAttribute
    try:
        return callable(*args)
    except ForbiddenAttribute, e:
        return 'ForbiddenAttribute: %s' % e[0]


def test_classic_class():
    """

    >>> from zope.security.checker import ProxyFactory
    >>> class C:
    ...    x = 1
    >>> C = ProxyFactory(C)
    >>> check_forbidden_call(C)
    'ForbiddenAttribute: __call__'
    >>> check_forbidden_get(C, '__dict__')
    'ForbiddenAttribute: __dict__'
    >>> s = str(C)
    >>> s = `C`
    >>> int(C.__module__ == __name__)
    1
    >>> len(C.__bases__)
    0

    Always available:

    >>> int(C < C)
    0
    >>> int(C > C)
    0
    >>> int(C <= C)
    1
    >>> int(C >= C)
    1
    >>> int(C == C)
    1
    >>> int(C != C)
    0
    >>> int(bool(C))
    1

    """

def test_classic_instance():
    """

    >>> from zope.security.checker import NamesChecker
    >>> from zope.security.checker import ProxyFactory
    >>> class C(object):
    ...    x, y = 1, 2
    >>> c = ProxyFactory(C(), NamesChecker(['x']))
    >>> check_forbidden_get(c, 'y')
    'ForbiddenAttribute: y'
    >>> check_forbidden_get(c, 'z')
    'ForbiddenAttribute: z'
    >>> c.x
    1
    >>> int(c.__class__ == C)
    1

    Always available:

    >>> int(c < c)
    0
    >>> int(c > c)
    0
    >>> int(c <= c)
    1
    >>> int(c >= c)
    1
    >>> int(c == c)
    1
    >>> int(c != c)
    0
    >>> int(bool(c))
    1
    >>> int(c.__class__ == C)
    1

    """

def test_rocks():
    """
    >>> from zope.security.checker import ProxyFactory
    >>> int(type(ProxyFactory(  object()  )) is object)
    1
    >>> int(type(ProxyFactory(  1  )) is int)
    1
    >>> int(type(ProxyFactory(  1.0  )) is float)
    1
    >>> int(type(ProxyFactory(  1l  )) is long)
    1
    >>> int(type(ProxyFactory(  1j  )) is complex)
    1
    >>> int(type(ProxyFactory(  None  )) is type(None))
    1
    >>> int(type(ProxyFactory(  'xxx'  )) is str)
    1
    >>> int(type(ProxyFactory(  u'xxx'  )) is unicode)
    1
    >>> int(type(ProxyFactory(  True  )) is type(True))
    1

    >>> from datetime import timedelta, datetime, date, time, tzinfo
    >>> int(type(ProxyFactory(  timedelta(1)  )) is timedelta)
    1
    >>> int(type(ProxyFactory(  datetime(2000, 1, 1)  )) is datetime)
    1
    >>> int(type(ProxyFactory(  date(2000, 1, 1)  )) is date)
    1
    >>> int(type(ProxyFactory(  time()  )) is time)
    1
    >>> int(type(ProxyFactory(  tzinfo() )) is tzinfo)
    1

    >>> try:
    ...     from pytz import UTC
    ... except ImportError:  # pytz checker only if pytz is present.
    ...     UTC = None
    >>> int(UTC is None or type(ProxyFactory(  UTC )) is type(UTC))
    1
    """

def test_iter_of_sequences():
    """
    >>> class X(object):
    ...   d = 1, 2, 3
    ...   def __getitem__(self, i):
    ...      return self.d[i]
    ...
    >>> x = X()

    We can iterate over sequences

    >>> list(x)
    [1, 2, 3]

    >>> from zope.security.checker import NamesChecker
    >>> from zope.security.checker import ProxyFactory
    >>> c = NamesChecker(['__getitem__'])
    >>> p = ProxyFactory(x, c)

    Even if they are proxied

    >>> list(p)
    [1, 2, 3]

    But if the class has an iter:

    >>> X.__iter__ = lambda self: iter(self.d)
    >>> list(x)
    [1, 2, 3]

    We shouldn't be able to iterate if we don't have an assertion:

    >>> check_forbidden_call(list, p)
    'ForbiddenAttribute: __iter__'
    """

def test_interfaces_and_declarations():
    """Test that we can still use interfaces though proxies

    >>> import zope.interface
    >>> class I(zope.interface.Interface):
    ...     pass
    >>> class IN(zope.interface.Interface):
    ...     pass
    >>> class II(zope.interface.Interface):
    ...     pass
    >>> @zope.interface.implementer(I)
    ... @zope.interface.provider(IN)
    ... class N(object):
    ...     pass
    >>> n = N()
    >>> zope.interface.directlyProvides(n, II)
    >>> from zope.security.checker import ProxyFactory
    >>> N = ProxyFactory(N)
    >>> n = ProxyFactory(n)
    >>> I.implementedBy(N)
    True
    >>> IN.providedBy(N)
    True
    >>> I.providedBy(n)
    True
    >>> II.providedBy(n)
    True
    """

def test_ABCMeta():
    """
    Test that we work with the ABCMeta meta class

    >>> import abc
    >>> class MyABC:
    ...     __metaclass__ = abc.ABCMeta

    >>> class Foo(MyABC): pass

    >>> class Bar(Foo): pass

    >>> from zope.security.checker import ProxyFactory
    >>> PBar = ProxyFactory(Bar)
    >>> [c.__name__ for c in PBar.__mro__]
    ['Bar', 'Foo', 'MyABC', 'object']

    >>> check_forbidden_call(PBar)
    'ForbiddenAttribute: __call__'
    >>> check_forbidden_get(PBar, '__dict__')
    'ForbiddenAttribute: __dict__'
    >>> s = str(PBar)
    >>> s = `PBar`
    >>> int(PBar.__module__ == __name__)
    1
    >>> len(PBar.__bases__)
    1

    Always available:

    >>> int(PBar < PBar)
    0
    >>> int(PBar > PBar)
    0
    >>> int(PBar <= PBar)
    1
    >>> int(PBar >= PBar)
    1
    >>> int(PBar == PBar)
    1
    >>> int(PBar != PBar)
    0
    >>> int(bool(PBar))
    1
    >>> int(PBar.__class__ == abc.ABCMeta)
    1
    """


def test_suite():
    from doctest import DocTestSuite
    return unittest.TestSuite((
        DocTestSuite(),
    ))
