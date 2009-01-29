##############################################################################
#
# Copyright (c) 2009 Zope Corporation and Contributors.
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
"""Make LocationProxies security-aware.

This module does a somewhat hard hack and is intended to be refactored
at some point, but helps avoiding to have zope.location depend on
zope.security.

We start with an unlocated class that will be wrapped by a
LocationProxy:

>>> class Unlocated(object):
...     a = 'a'

>>> unlocated = Unlocated()

Now we create a location proxy around it:

>>> from zope.location.location import LocationProxy
>>> located = LocationProxy(unlocated)

We define a checker for the unlocated object, which will also be
used by the security proxy as the LocationProxy defines
__Security_checker__:

>>> from zope.security.checker import NamesChecker, defineChecker
>>> unlocatedChecker = NamesChecker(['a'])
>>> defineChecker(Unlocated, unlocatedChecker)

>>> from zope.security.proxy import ProxyFactory
>>> secure_located = ProxyFactory(located)
>>> secure_located.a
'a'

"""

import zope.location.location
from zope.security.decorator import DecoratedSecurityCheckerDescriptor

zope.location.location.LocationProxy.__Security_checker__ = (
    DecoratedSecurityCheckerDescriptor())
