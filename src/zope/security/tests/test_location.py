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
"""Test location support
"""
import unittest


def _skip_wo_zope_location(testfunc):
    try:
        import zope.location
    except ImportError:
        from functools import update_wrapper
        def dummy(self):
            pass
        update_wrapper(dummy, testfunc)
        return dummy
    else:
        return testfunc


class LocationSecurityProxyTests(unittest.TestCase):

    @_skip_wo_zope_location
    def test_locationproxy_security(self):
        from zope.location.location import LocationProxy
        from zope.security.checker import defineChecker
        from zope.security.checker import NamesChecker
        from zope.security.proxy import ProxyFactory
        class Unlocated(object):
            a = 'a'
        unlocated = Unlocated()
        located = LocationProxy(unlocated)

        # define a checker for the unlocated object, which will also be
        # used by the security proxy as the LocationProxy defines
        # __Security_checker__:
        unlocatedChecker = NamesChecker(['a'])
        defineChecker(Unlocated, unlocatedChecker)

        secure_located = ProxyFactory(located)
        self.assertEqual(secure_located.a, 'a')


def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(LocationSecurityProxyTests),
    ))
