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
"""
__docformat__ = 'restructuredtext'

from zope.security._proxy import getChecker
from zope.security._proxy import getObject
from zope.security._proxy import _Proxy as Proxy

# We need the injection of DecoratedSecurityCheckerDescriptor into
# zope.location's LocationProxy as soon someone uses security proxies by
# importing zope.security.proxy:
import zope.security.decorator


removeSecurityProxy = getObject

# This import represents part of the API for this module
from zope.security.checker import ProxyFactory

def getTestProxyItems(proxy):
    """Return a sorted sequence of checker names and permissions for testing
    """
    checker = getChecker(proxy)
    return sorted(checker.get_permissions.items())


builtin_isinstance = None
def isinstance(object, cls):
    """Test whether an object is an instance of a type.

    This works even if the object is security proxied:
    """
    global builtin_isinstance
    if builtin_isinstance is None:
        builtin_isinstance = __builtins__['isinstance']
    # The removeSecurityProxy call is OK here because it is *only*
    # being used for isinstance
    return builtin_isinstance(removeSecurityProxy(object), cls)
