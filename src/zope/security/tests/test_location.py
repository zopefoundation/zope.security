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
"""Context Tests
"""

import doctest


def test_locationproxy_security():
    """We start with an unlocated class that will be wrapped by a
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


def test_suite():
    return doctest.DocTestSuite()
