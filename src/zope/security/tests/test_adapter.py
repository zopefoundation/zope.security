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
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
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


class LocatingTrustedAdapterFactoryTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.security.adapter import LocatingTrustedAdapterFactory
        return LocatingTrustedAdapterFactory

    def _makeOne(self, factory):
        return self._getTargetClass()(factory)

    def _makeFactory(self):
        class _Factory(object):
            __name__ = 'testing'
            __module__ = 'zope.security.tests.test_adapter'
            def __call__(self, *args):
                self._called_with = args
                return self
        return _Factory()

    def test_ctor(self):
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        self.assertTrue(ltaf.factory is factory)
        self.assertEqual(ltaf.__name__, 'testing')
        self.assertEqual(ltaf.__module__, 'zope.security.tests.test_adapter')

    @_skip_wo_zope_location
    def test__call__w_non_ILocation_non_spacesuit(self):
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        before = factory.__dict__.copy()
        returned = ltaf(adapter)
        self.assertTrue(returned is factory)
        after = dict([(k, v) for k, v in returned.__dict__.items()
                         if k != '_called_with'])
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before) # no added attrs

    @_skip_wo_zope_location
    def test__call__w_non_ILocation_non_spacesuit_multiple_args(self):
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        extra = object()
        before = factory.__dict__.copy()
        returned = ltaf(adapter, extra)
        self.assertTrue(returned is factory)
        after = dict([(k, v) for k, v in returned.__dict__.items()
                         if k != '_called_with'])
        self.assertEqual(factory._called_with, (adapter, extra))
        self.assertEqual(after, before) # no added attrs

    @_skip_wo_zope_location
    def test__call__w_ILocation_w_existing_parent_non_spacesuit(self):
        from zope.interface import directlyProvides
        from zope.location import ILocation
        factory = self._makeFactory()
        parent = factory.__parent__ = object()
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        before = factory.__dict__.copy()
        returned = ltaf(adapter)
        self.assertTrue(returned is factory)
        self.assertTrue(returned.__parent__ is parent)

    @_skip_wo_zope_location
    def test__call__w_ILocation_wo_existing_parent_non_spacesuit(self):
        from zope.interface import directlyProvides
        from zope.location import ILocation
        factory = self._makeFactory()
        factory.__parent__ = None
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        before = factory.__dict__.copy()
        returned = ltaf(adapter)
        self.assertTrue(returned is factory)
        self.assertTrue(returned.__parent__ is adapter)

    @_skip_wo_zope_location
    def test__call__w_non_ILocation_w_spacesuit(self):
        from zope.proxy import getProxiedObject
        from zope.security.proxy import getObject
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import removeSecurityProxy
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        proxy = ProxyFactory(adapter)
        before = factory.__dict__.copy()
        returned = ltaf(proxy)
        self.assertFalse(returned is factory)
        ploc = removeSecurityProxy(returned)
        self.assertTrue(ploc.__parent__ is adapter)
        unwrapped = getProxiedObject(ploc)
        self.assertTrue(unwrapped is factory)
        after = dict([(k, v) for k, v in unwrapped.__dict__.items()
                         if k not in ('_called_with',)])
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before) # no added attrs

    @_skip_wo_zope_location
    def test__call__w_non_ILocation_w_spacesuit_multiple_args(self):
        from zope.proxy import getProxiedObject
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import removeSecurityProxy
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        extra = object()
        proxy = ProxyFactory(adapter)
        before = factory.__dict__.copy()
        returned = ltaf(proxy, extra)
        self.assertFalse(returned is factory)
        ploc = removeSecurityProxy(returned)
        self.assertTrue(ploc.__parent__ is adapter)
        unwrapped = getProxiedObject(ploc)
        self.assertTrue(unwrapped is factory)
        after = dict([(k, v) for k, v in unwrapped.__dict__.items()
                         if k not in ('_called_with',)])
        self.assertEqual(factory._called_with, (adapter, extra))
        self.assertEqual(after, before) # no added attrs

    @_skip_wo_zope_location
    def test__call__w_non_ILocation_multiple_args_extra_spacesuit(self):
        from zope.proxy import getProxiedObject
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import removeSecurityProxy
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        class _Extra(object):
            pass
        adapter = _NotAdapter()
        extra = _Extra()
        proxy = ProxyFactory(extra)
        before = factory.__dict__.copy()
        returned = ltaf(adapter, proxy)
        self.assertFalse(returned is factory)
        ploc = removeSecurityProxy(returned)
        self.assertTrue(ploc.__parent__ is adapter)
        unwrapped = getProxiedObject(ploc)
        self.assertTrue(unwrapped is factory)
        after = dict([(k, v) for k, v in unwrapped.__dict__.items()
                         if k not in ('_called_with',)])
        self.assertEqual(factory._called_with, (adapter, extra))
        self.assertEqual(after, before) # no added attrs

    @_skip_wo_zope_location
    def test__call__w_ILocation_w_spacesuit(self):
        from zope.interface import directlyProvides
        from zope.location import ILocation
        from zope.security.proxy import getObject
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import removeSecurityProxy
        factory = self._makeFactory()
        factory.__parent__ = factory.__name__ = None
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)
        class _Adapter(object):
            pass
        adapter = _Adapter()
        proxy = ProxyFactory(adapter)
        before = dict([(k, v) for k, v in factory.__dict__.items()
                         if k not in ('_called_with', '__parent__')])
        returned = ltaf(proxy)
        self.assertFalse(returned is factory)
        ploc = removeSecurityProxy(returned)
        self.assertTrue(ploc.__parent__ is adapter)
        unwrapped = getObject(ploc)
        self.assertTrue(unwrapped is factory)
        after = dict([(k, v) for k, v in unwrapped.__dict__.items()
                         if k not in ('_called_with', '__parent__')])
        self.assertEqual(factory._called_with, (adapter,))
        self.assertTrue(factory.__parent__ is adapter)
        self.assertEqual(after, before) # no added attrs

    @_skip_wo_zope_location
    def test__call__w_ILocation_w_spacesuit_w_existing_parent(self):
        from zope.interface import directlyProvides
        from zope.location import ILocation
        from zope.security.proxy import getObject
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import removeSecurityProxy
        factory = self._makeFactory()
        factory.__name__ = None
        factory.__parent__ = parent = object()
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)
        class _Adapter(object):
            pass
        adapter = _Adapter()
        proxy = ProxyFactory(adapter)
        before = dict([(k, v) for k, v in factory.__dict__.items()
                         if k not in ('_called_with', '__parent__')])
        returned = ltaf(proxy)
        self.assertFalse(returned is factory)
        ploc = removeSecurityProxy(returned)
        self.assertTrue(ploc.__parent__ is parent)
        unwrapped = getObject(ploc)
        self.assertTrue(unwrapped is factory)
        after = dict([(k, v) for k, v in unwrapped.__dict__.items()
                         if k not in ('_called_with', '__parent__')])
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before) # no added attrs


class TrustedAdapterFactoryTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.security.adapter import TrustedAdapterFactory
        return TrustedAdapterFactory

    def _makeOne(self, factory):
        return self._getTargetClass()(factory)

    def _makeFactory(self):
        class _Factory(object):
            __name__ = 'testing'
            __module__ = 'zope.security.tests.test_adapter'
            def __call__(self, *args):
                self._called_with = args
                return self
        return _Factory()

    @_skip_wo_zope_location
    def test__call__w_non_ILocation_w_spacesuit(self):
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import removeSecurityProxy
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        proxy = ProxyFactory(adapter)
        before = factory.__dict__.copy()
        returned = ltaf(proxy)
        self.assertFalse(returned is factory)
        unwrapped = removeSecurityProxy(returned)
        self.assertTrue('__parent__' not in unwrapped.__dict__)
        self.assertTrue(unwrapped is factory)
        after = dict([(k, v) for k, v in unwrapped.__dict__.items()
                         if k not in ('_called_with',)])
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before) # no added attrs

    @_skip_wo_zope_location
    def test__call__w_non_ILocation_w_spacesuit_multiple_args(self):
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import removeSecurityProxy
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        extra = object()
        proxy = ProxyFactory(adapter)
        before = factory.__dict__.copy()
        returned = ltaf(proxy, extra)
        self.assertFalse(returned is factory)
        unwrapped = removeSecurityProxy(returned)
        self.assertTrue('__parent__' not in unwrapped.__dict__)
        self.assertTrue(unwrapped is factory)
        after = dict([(k, v) for k, v in unwrapped.__dict__.items()
                         if k not in ('_called_with',)])
        self.assertEqual(factory._called_with, (adapter, extra))
        self.assertEqual(after, before) # no added attrs

    @_skip_wo_zope_location
    def test__call__w_non_ILocation_multiple_args_extra_spacesuit(self):
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import removeSecurityProxy
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        class _Extra(object):
            pass
        adapter = _NotAdapter()
        extra = _Extra()
        proxy = ProxyFactory(extra)
        before = factory.__dict__.copy()
        returned = ltaf(adapter, proxy)
        self.assertFalse(returned is factory)
        unwrapped = removeSecurityProxy(returned)
        self.assertTrue('__parent__' not in unwrapped.__dict__)
        self.assertTrue(unwrapped is factory)
        after = dict([(k, v) for k, v in unwrapped.__dict__.items()
                         if k not in ('_called_with',)])
        self.assertEqual(factory._called_with, (adapter, extra))
        self.assertEqual(after, before) # no added attrs

    @_skip_wo_zope_location
    def test__call__w_ILocation_w_spacesuit(self):
        from zope.interface import directlyProvides
        from zope.location import ILocation
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import removeSecurityProxy
        factory = self._makeFactory()
        factory.__parent__ = factory.__name__ = None
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)
        class _Adapter(object):
            pass
        adapter = _Adapter()
        proxy = ProxyFactory(adapter)
        before = dict([(k, v) for k, v in factory.__dict__.items()
                         if k not in ('_called_with', '__parent__')])
        returned = ltaf(proxy)
        self.assertFalse(returned is factory)
        unwrapped = removeSecurityProxy(returned)
        self.assertTrue(unwrapped.__parent__ is adapter)
        self.assertTrue(unwrapped is factory)
        after = dict([(k, v) for k, v in unwrapped.__dict__.items()
                         if k not in ('_called_with', '__parent__')])
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before) # no added attrs

    @_skip_wo_zope_location
    def test__call__w_ILocation_w_spacesuit_w_existing_parent(self):
        from zope.interface import directlyProvides
        from zope.location import ILocation
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import removeSecurityProxy
        factory = self._makeFactory()
        factory.__name__ = None
        factory.__parent__ = parent = object()
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)
        class _Adapter(object):
            pass
        adapter = _Adapter()
        proxy = ProxyFactory(adapter)
        before = dict([(k, v) for k, v in factory.__dict__.items()
                         if k not in ('_called_with', '__parent__')])
        returned = ltaf(proxy)
        self.assertFalse(returned is factory)
        unwrapped = removeSecurityProxy(returned)
        self.assertTrue(unwrapped.__parent__ is parent)
        self.assertTrue(unwrapped is factory)
        after = dict([(k, v) for k, v in unwrapped.__dict__.items()
                         if k not in ('_called_with', '__parent__')])
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before) # no added attrs


class LocatingUntrustedAdapterFactoryTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.security.adapter import LocatingUntrustedAdapterFactory
        return LocatingUntrustedAdapterFactory

    def _makeOne(self, factory):
        return self._getTargetClass()(factory)

    def _makeFactory(self):
        class _Factory(object):
            __name__ = 'testing'
            __module__ = 'zope.security.tests.test_adapter'
            def __call__(self, *args):
                self._called_with = args
                return self
        return _Factory()

    def test_ctor(self):
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        self.assertTrue(ltaf.factory is factory)
        self.assertEqual(ltaf.__name__, 'testing')
        self.assertEqual(ltaf.__module__, 'zope.security.tests.test_adapter')

    @_skip_wo_zope_location
    def test__call__w_non_ILocation(self):
        from zope.proxy import getProxiedObject
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        before = factory.__dict__.copy()
        returned = ltaf(adapter)
        self.assertFalse(returned is factory)
        unwrapped = getProxiedObject(returned)
        self.assertTrue(unwrapped is factory)
        after = dict([(k, v) for k, v in returned.__dict__.items()
                         if k != '_called_with'])
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before) # no added attrs

    @_skip_wo_zope_location
    def test__call__w_non_ILocation_multiple_args(self):
        from zope.proxy import getProxiedObject
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        extra = object()
        before = factory.__dict__.copy()
        returned = ltaf(adapter, extra)
        self.assertFalse(returned is factory)
        unwrapped = getProxiedObject(returned)
        self.assertTrue(unwrapped is factory)
        after = dict([(k, v) for k, v in returned.__dict__.items()
                         if k != '_called_with'])
        self.assertEqual(factory._called_with, (adapter, extra))
        self.assertEqual(after, before) # no added attrs

    @_skip_wo_zope_location
    def test__call__w_ILocation_w_existing_parent(self):
        from zope.interface import directlyProvides
        from zope.location import ILocation
        factory = self._makeFactory()
        parent = factory.__parent__ = object()
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        before = factory.__dict__.copy()
        returned = ltaf(adapter)
        self.assertTrue(returned is factory)
        self.assertTrue(returned.__parent__ is parent)

    @_skip_wo_zope_location
    def test__call__w_ILocation_wo_existing_parent(self):
        from zope.interface import directlyProvides
        from zope.location import ILocation
        factory = self._makeFactory()
        factory.__parent__ = None
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        before = factory.__dict__.copy()
        returned = ltaf(adapter)
        self.assertTrue(returned is factory)
        self.assertTrue(returned.__parent__ is adapter)


def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(Test_assertLocation),
        unittest.makeSuite(LocatingTrustedAdapterFactoryTests),
        unittest.makeSuite(TrustedAdapterFactoryTests),
        unittest.makeSuite(LocatingUntrustedAdapterFactoryTests),
    ))
