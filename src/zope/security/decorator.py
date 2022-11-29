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
"""Decorator support

Decorators are proxies that are mostly transparent but that may provide
additional features.
"""

from zope.proxy import ProxyBase
from zope.proxy import getProxiedObject
from zope.proxy.decorator import SpecificationDecoratorBase

from zope.security.checker import CombinedChecker
from zope.security.checker import selectChecker
from zope.security.proxy import Proxy
from zope.security.proxy import getChecker


class DecoratedSecurityCheckerDescriptor(object):
    """Descriptor for a Decorator that provides a decorated security checker.
    """

    def __get__(self, inst, cls=None):
        if inst is None:
            return self
        else:
            proxied_object = getProxiedObject(inst)
            if type(proxied_object) is Proxy:
                checker = getChecker(proxied_object)
            else:
                checker = getattr(proxied_object, '__Security_checker__', None)
                if checker is None:
                    checker = selectChecker(proxied_object)
            wrapper_checker = selectChecker(inst)
            if wrapper_checker is None and checker is None:
                raise AttributeError("%r has no attribute %r" %
                                     (proxied_object.__class__.__name__,
                                      '__Security_checker__'))
            elif wrapper_checker is None:
                return checker
            elif checker is None:
                return wrapper_checker
            else:
                return CombinedChecker(wrapper_checker, checker)

    def __set__(self, inst, value):
        raise TypeError("Can't set __Security_checker__ on a decorated object")


class SecurityCheckerDecoratorBase(ProxyBase):
    """Base class for proxy that provides additional security declarations."""

    __Security_checker__ = DecoratedSecurityCheckerDescriptor()


class DecoratorBase(SpecificationDecoratorBase, SecurityCheckerDecoratorBase):
    """Base class for a proxy that provides both additional interfaces and
    security declarations."""


# zope.location was made independent of security. To work together with
# security, we re-inject the DecoratedSecurityCheckerDescriptor onto the
# location proxy from here.
# This is the only sane place we found for doing it: it kicks in as soon
# as someone starts using security proxies.
import zope.location.location  # noqa: E402 module level import not at top


zope.location.location.LocationProxy.__Security_checker__ = (
    DecoratedSecurityCheckerDescriptor())
