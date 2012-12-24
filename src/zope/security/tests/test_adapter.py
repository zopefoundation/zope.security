##############################################################################
#
# Copyright (c) 2004 Zope Foundation and Contributors.
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


class Test_assertLocation(unittest.TestCase):

    def _callFUT(self, adapter, parent):
        from zope.security.adapter import assertLocation
        return assertLocation(adapter, parent)

    @_skip_wo_zope_location
    def test_w_non_ILocation(self):
        from zope.location import LocationProxy
        from zope.proxy import getProxiedObject
        class _Adapter(object):
            pass
        adapter = _Adapter()
        parent = object()
        returned = self._callFUT(adapter, parent)
        self.assertTrue(isinstance(returned, LocationProxy))
        self.assertTrue(getProxiedObject(returned) is adapter)
        self.assertTrue(returned.__parent__ is parent)

    @_skip_wo_zope_location
    def test_w_ILocation_no_parent(self):
        from zope.interface import implementer
        from zope.location import ILocation
        @implementer(ILocation)
        class _Adapter(object):
            __parent__ = None
        adapter = _Adapter()
        parent = object()
        returned = self._callFUT(adapter, parent)
        self.assertTrue(returned is adapter)
        self.assertTrue(returned.__parent__ is parent)

    @_skip_wo_zope_location
    def test_w_ILocation_w_parent(self):
        from zope.interface import implementer
        from zope.location import ILocation
        parent = object()
        @implementer(ILocation)
        class _Adapter(object):
            __parent__ = parent
        adapter = _Adapter()
        new_parent = object()
        returned = self._callFUT(adapter, new_parent)
        self.assertTrue(returned is adapter)
        self.assertTrue(returned.__parent__ is parent)


def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(Test_assertLocation),
    ))
