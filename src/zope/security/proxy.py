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
"""
Helper functions for proxies.

.. seealso:: :ref:`proxy-known-issues`
"""
import functools
import sys

from zope.proxy import PyProxyBase

from zope.security._compat import PURE_PYTHON


def _check_name(meth, wrap_result=True):
    name = meth.__name__

    def _wrapper(self, *args, **kw):
        wrapped = super(PyProxyBase, self).__getattribute__('_wrapped')
        checker = super(PyProxyBase, self).__getattribute__('_checker')
        checker.check(wrapped, name)
        res = meth(self, *args, **kw)
        if not wrap_result:
            return res
        return checker.proxy(res)
    return functools.update_wrapper(_wrapper, meth)


def _check_name_inplace(meth):
    name = meth.__name__

    def _wrapper(self, *args, **kw):
        wrapped = super(PyProxyBase, self).__getattribute__('_wrapped')
        checker = super(PyProxyBase, self).__getattribute__('_checker')
        checker.check(wrapped, name)
        w_meth = getattr(wrapped, name, None)
        if w_meth is not None:
            # The proxy object cannot change; we are modifying in place.
            self._wrapped = w_meth(*args, **kw)
            return self
        x_name = '__%s__' % name[3:-2]
        return ProxyPy(getattr(wrapped, x_name)(*args, **kw), checker)
    return functools.update_wrapper(_wrapper, meth)


def _fmt_address(obj):
    # Try to replicate PyString_FromString("%p", obj), which actually uses
    # the platform sprintf(buf, "%p", obj), which we cannot access from Python
    # directly (and ctypes seems like overkill).
    if sys.platform != 'win32':
        return '0x%0x' % id(obj)
    if sys.maxsize < 2**32:  # pragma: no cover
        return '0x%08X' % id(obj)
    return '0x%016X' % id(obj)  # pragma: no cover


class ProxyPy(PyProxyBase):
    """
    The pure-Python reference implementation of a security proxy.

    This should normally not be created directly, instead use the
    :func:`~.ProxyFactory`.

    You can choose to use this implementation instead of the C implementation
    by default by setting the ``PURE_PYTHON`` environment variable before
    :mod:`zope.security` is imported.
    """
    __slots__ = ('_wrapped', '_checker')

    def __new__(cls, value, checker):
        inst = super().__new__(cls)
        inst._wrapped = value
        inst._checker = checker
        return inst

    def __init__(self, value, checker):
        if checker is None:
            raise ValueError('checker may now be None')
        self._wrapped = value
        self._checker = checker

    # Attribute protocol
    def __getattribute__(self, name):
        if name in ('_wrapped', '_checker'):
            # Only allow _wrapped and _checker to be accessed from inside.
            if sys._getframe(1).f_locals.get('self') is not self:
                raise AttributeError(name)
        wrapped = super().__getattribute__('_wrapped')
        if name == '_wrapped':
            return wrapped
        checker = super().__getattribute__('_checker')
        if name == '_checker':
            return checker
        if name not in ('__cmp__', '__hash__', '__bool__',
                        '__lt__', '__le__', '__eq__', '__ne__', '__ge__',
                        '__gt__'):
            checker.check_getattr(wrapped, name)
        if name in ('__reduce__', '__reduce_ex__'):
            # The superclass specifically denies access to __reduce__
            # and __reduce__ex__, not letting proxies be pickled. But
            # for backwards compatibility, we need to be able to
            # pickle proxies. See checker:Global for an example.
            val = getattr(wrapped, name)
        elif name == '__module__':
            # The superclass deals with descriptors found in the type
            # of this object just like the Python language spec states, letting
            # them have precedence over things found in the instance. This
            # normally makes us a better proxy implementation. However, the
            # C version of this code in _proxy doesn't take that same care and
            # instead uses the generic object attribute access methods directly
            # on the wrapped object. This is a behaviour difference; so far,
            # it's only been noticed for the __module__ attribute, which
            # checker:Global wants to override but couldn't because this
            # object's type's __module__ would get in the way. That broke
            # pickling, and checker:Global can't return anything more
            # sophisticated than a str (a tuple) because it gets proxied and
            # breaks pickling again. Our solution is to match the C version for
            # this one attribute.
            val = getattr(wrapped, name)
        else:
            val = super().__getattribute__(name)
        return checker.proxy(val)

    def __getattr__(self, name):
        # We only get here if __getattribute__ has already raised an
        # AttributeError (we have to implement this because the super
        # class does). We expect that we will also raise that same
        # error, one way or another---either it will be forbidden by
        # the checker or it won't exist. However, if the underlying
        # object is playing games in *its*
        # __getattribute__/__getattr__, and we call getattr() on it,
        # (maybe there are threads involved), we might actually
        # succeed this time.

        # The C implementation *does not* do two checks; it only does
        # one check, and raises either the ForbiddenAttribute or the
        # underlying AttributeError, *without* invoking any defined
        # __getattribute__/__getattr__ more than once. So we
        # explicitly do the same. The consequence is that we lose a
        # good stack trace if the object implemented its own methods
        # but we're consistent. We would provide a better error
        # message or even subclass of AttributeError, but that's liable to
        # break (doc)tests.
        wrapped = super().__getattribute__('_wrapped')
        checker = super().__getattribute__('_checker')
        checker.check_getattr(wrapped, name)
        raise AttributeError(name)

    def __setattr__(self, name, value):
        if name in ('_wrapped', '_checker'):
            return super().__setattr__(name, value)
        wrapped = super().__getattribute__('_wrapped')
        checker = super().__getattribute__('_checker')
        checker.check_setattr(wrapped, name)
        setattr(wrapped, name, value)

    def __delattr__(self, name):
        if name in ('_wrapped', '_checker'):
            raise AttributeError()
        wrapped = super().__getattribute__('_wrapped')
        checker = super().__getattribute__('_checker')
        checker.check_setattr(wrapped, name)
        delattr(wrapped, name)

    def __lt__(self, other):
        # no check
        wrapped = super().__getattribute__('_wrapped')
        return wrapped < other

    def __le__(self, other):
        # no check
        wrapped = super().__getattribute__('_wrapped')
        return wrapped <= other

    def __eq__(self, other):
        # no check
        wrapped = super().__getattribute__('_wrapped')
        return wrapped == other

    def __ne__(self, other):
        # no check
        wrapped = super().__getattribute__('_wrapped')
        return wrapped != other

    def __ge__(self, other):
        # no check
        wrapped = super().__getattribute__('_wrapped')
        return wrapped >= other

    def __gt__(self, other):
        # no check
        wrapped = super().__getattribute__('_wrapped')
        return wrapped > other

    def __hash__(self):
        # no check
        wrapped = super().__getattribute__('_wrapped')
        return hash(wrapped)

    def __bool__(self):
        # no check
        wrapped = super().__getattribute__('_wrapped')
        return bool(wrapped)

    def __length_hint__(self):
        # no check
        wrapped = super().__getattribute__('_wrapped')
        try:
            hint = wrapped.__length_hint__
        except AttributeError:
            return NotImplemented
        else:
            return hint()

    def __str__(self):
        try:
            return _check_name(PyProxyBase.__str__)(self)
        # The C implementation catches almost all exceptions; the
        # exception is a TypeError that's raised when the repr returns
        # the wrong type of object.
        except TypeError:
            raise
        except:  # noqa: E722 do not use bare 'except'
            # The C implementation catches all exceptions.
            wrapped = super().__getattribute__('_wrapped')
            return '<security proxied {}.{} instance at {}>'.format(
                wrapped.__class__.__module__, wrapped.__class__.__name__,
                _fmt_address(wrapped))

    def __repr__(self):
        try:
            return _check_name(PyProxyBase.__repr__)(self)
        # The C implementation catches almost all exceptions; the
        # exception is a TypeError that's raised when the repr returns
        # the wrong type of object.
        except TypeError:
            raise
        except:  # noqa: E722 do not use bare 'except'
            wrapped = super().__getattribute__('_wrapped')
            return '<security proxied {}.{} instance at {}>'.format(
                wrapped.__class__.__module__, wrapped.__class__.__name__,
                _fmt_address(wrapped))


for name in ['__call__',
             # '__repr__',
             # '__str__',
             # '__unicode__', # Unchecked in C proxy
             '__reduce__',
             '__reduce_ex__',
             # '__lt__',      # Unchecked in C proxy (rich comparison)
             # '__le__',      # Unchecked in C proxy (rich comparison)
             # '__eq__',      # Unchecked in C proxy (rich comparison)
             # '__ne__',      # Unchecked in C proxy (rich comparison)
             # '__ge__',      # Unchecked in C proxy (rich comparison)
             # '__gt__',      # Unchecked in C proxy (rich comparison)
             # '__bool__',    # Unchecked in C proxy (rich comparison)
             # '__hash__',    # Unchecked in C proxy (rich comparison)
             # '__cmp__',     # Unchecked in C proxy
             '__getitem__',
             '__setitem__',
             '__delitem__',
             '__iter__',
             '__next__',
             'next',
             '__contains__',
             '__neg__',
             '__pos__',
             '__abs__',
             '__invert__',
             '__complex__',
             '__int__',
             '__float__',
             '__index__',
             '__add__',
             '__sub__',
             '__mul__',
             '__truediv__',
             '__floordiv__',
             '__mod__',
             '__divmod__',
             '__pow__',
             '__radd__',
             '__rsub__',
             '__rmul__',
             '__rtruediv__',
             '__rfloordiv__',
             '__rmod__',
             '__rdivmod__',
             '__rpow__',
             '__lshift__',
             '__rshift__',
             '__and__',
             '__xor__',
             '__or__',
             '__rlshift__',
             '__rrshift__',
             '__rand__',
             '__rxor__',
             '__ror__',
             ]:
    meth = getattr(PyProxyBase, name)
    setattr(ProxyPy, name, _check_name(meth))

for name in (
        '__len__',
):
    meth = getattr(PyProxyBase, name)
    setattr(ProxyPy, name, _check_name(meth, False))

for name in ['__iadd__',
             '__isub__',
             '__imul__',
             '__itruediv__',
             '__ifloordiv__',
             '__imod__',
             '__ilshift__',
             '__irshift__',
             '__iand__',
             '__ixor__',
             '__ior__',
             '__ipow__',
             ]:
    meth = getattr(PyProxyBase, name)
    setattr(ProxyPy, name, _check_name_inplace(meth))


def getCheckerPy(proxy):
    return super(ProxyPy, proxy).__getattribute__('_checker')


_builtin_isinstance = sys.modules['builtins'].isinstance


def getObjectPy(proxy):
    if not _builtin_isinstance(proxy, ProxyPy):
        return proxy
    return super(ProxyPy, proxy).__getattribute__('_wrapped')


_c_available = not PURE_PYTHON
if _c_available:  # pragma: no cover
    try:
        from zope.security._proxy import _Proxy
    except (ImportError, AttributeError):
        _c_available = False


getChecker = getCheckerPy
getObject = getObjectPy
Proxy = ProxyPy

if _c_available:  # pragma: no cover
    from zope.security._proxy import getChecker
    from zope.security._proxy import getObject
    Proxy = _Proxy

removeSecurityProxy = getObject


def getTestProxyItems(proxy):
    """Return a sorted sequence of checker names and permissions for testing
    """
    checker = getChecker(proxy)
    return sorted(checker.get_permissions.items())


def isinstance(object, cls):
    """Test whether an *object* is an instance of a type.

    This works even if the object is security proxied.
    """
    # The removeSecurityProxy call is OK here because it is *only*
    # being used for isinstance
    return _builtin_isinstance(removeSecurityProxy(object), cls)
