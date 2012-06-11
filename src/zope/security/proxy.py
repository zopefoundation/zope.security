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
"""Helper functions for Proxies.

$Id$
"""
__docformat__ = 'restructuredtext'

from zope.security._proxy import getChecker, getObject
from zope.security._proxy import _Proxy as Proxy

removeSecurityProxy = getObject

# This import represents part of the API for this module
from zope.security.checker import ProxyFactory

def getTestProxyItems(proxy):
    """Try to get checker names and permissions for testing

    If this succeeds, a sorted sequence of items is returned,
    otherwise, None is returned.
    """
    checker = getChecker(proxy)
    items = checker.get_permissions.items()
    items.sort()
    return items


builtin_isinstance = isinstance
def isinstance(object, cls):
    """Test whether an object is an instance of a type.

    This works even if the object is security proxied:

      >>> class C1(object):
      ...     pass

      >>> c = C1()
      >>> isinstance(c, C1)
      True

      >>> from zope.security.checker import ProxyFactory
      >>> isinstance(ProxyFactory(c), C1)
      True

      >>> class C2(C1):
      ...     pass

      >>> c = C2()
      >>> isinstance(c, C1)
      True

      >>> from zope.security.checker import ProxyFactory
      >>> isinstance(ProxyFactory(c), C1)
      True

    """

    # The removeSecurityProxy call is OK here because it is *only*
    # being used for isinstance

    return builtin_isinstance(removeSecurityProxy(object), cls)


# zope.location was made independent of security. To work together with
# security, we re-inject the DecoratedSecurityCheckerDescriptor onto the
# location proxy from here.
# This is the only sane place we found for doing it: it kicks in as soon
# as someone starts using security proxies.
import zope.location.location
from zope.security.decorator import DecoratedSecurityCheckerDescriptor
zope.location.location.LocationProxy.__Security_checker__ = (
    DecoratedSecurityCheckerDescriptor())
