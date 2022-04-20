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

from zope.interface import directlyProvides
from zope.interface import implementer
from zope.location import ILocation
from zope.location import LocationProxy
from zope.proxy import getProxiedObject


# pylint:disable=attribute-defined-outside-init,protected-access


class Test_assertLocation(unittest.TestCase):

    def _callFUT(self, adapter, parent):
        from zope.security.adapter import assertLocation
        return assertLocation(adapter, parent)

    def test_w_non_ILocation(self):
        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        parent = object()
        returned = self._callFUT(adapter, parent)
        self.assertTrue(isinstance(returned, LocationProxy))
        self.assertIs(getProxiedObject(returned), adapter)
        self.assertIs(returned.__parent__, parent)

    def test_w_ILocation_no_parent(self):
        @implementer(ILocation)
        class _Adapter(object):
            __parent__ = None
        adapter = _Adapter()
        parent = object()
        returned = self._callFUT(adapter, parent)
        self.assertIs(returned, adapter)
        self.assertIs(returned.__parent__, parent)

    def test_w_ILocation_w_parent(self):
        parent = object()

        @implementer(ILocation)
        class _Adapter(object):
            __parent__ = parent
        adapter = _Adapter()
        new_parent = object()
        returned = self._callFUT(adapter, new_parent)
        self.assertIs(returned, adapter)
        self.assertIs(returned.__parent__, parent)


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
            _called_with = ()

            def __call__(self, *args):
                self._called_with = args
                return self
        return _Factory()

    def test_ctor(self):
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        self.assertIs(ltaf.factory, factory)
        self.assertEqual(ltaf.__name__, 'testing')
        self.assertEqual(ltaf.__module__, 'zope.security.tests.test_adapter')

    def test__call__w_non_ILocation_non_spacesuit(self):
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)

        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        before = factory.__dict__.copy()
        returned = ltaf(adapter)
        self.assertIs(returned, factory)
        after = {k: v for k, v in returned.__dict__.items()
                 if k != '_called_with'}
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before)  # no added attrs

    def test__call__w_non_ILocation_non_spacesuit_multiple_args(self):
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)

        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        extra = object()
        before = factory.__dict__.copy()
        returned = ltaf(adapter, extra)
        self.assertIs(returned, factory)
        after = {k: v for k, v in returned.__dict__.items()
                 if k != '_called_with'}
        self.assertEqual(factory._called_with, (adapter, extra))
        self.assertEqual(after, before)  # no added attrs

    def test__call__w_ILocation_w_existing_parent_non_spacesuit(self):
        factory = self._makeFactory()
        parent = factory.__parent__ = object()
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)

        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        returned = ltaf(adapter)
        self.assertIs(returned, factory)
        self.assertIs(returned.__parent__, parent)

    def test__call__w_ILocation_wo_existing_parent_non_spacesuit(self):
        factory = self._makeFactory()
        factory.__parent__ = None
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)

        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        returned = ltaf(adapter)
        self.assertIs(returned, factory)
        self.assertIs(returned.__parent__, adapter)

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
        ploc = removeSecurityProxy(returned)
        self.assertIs(ploc.__parent__, adapter)
        unwrapped = getProxiedObject(ploc)
        self.assertIs(unwrapped, factory)
        after = {k: v for k, v in unwrapped.__dict__.items()
                 if k not in ('_called_with',)}
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before)  # no added attrs

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
        ploc = removeSecurityProxy(returned)
        self.assertIs(ploc.__parent__, adapter)
        unwrapped = getProxiedObject(ploc)
        self.assertIs(unwrapped, factory)
        after = {k: v for k, v in unwrapped.__dict__.items()
                 if k not in ('_called_with',)}
        self.assertEqual(factory._called_with, (adapter, extra))
        self.assertEqual(after, before)  # no added attrs

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
        ploc = removeSecurityProxy(returned)
        self.assertIs(ploc.__parent__, adapter)
        unwrapped = getProxiedObject(ploc)
        self.assertIs(unwrapped, factory)
        after = {k: v for k, v in unwrapped.__dict__.items()
                 if k not in ('_called_with',)}
        self.assertEqual(factory._called_with, (adapter, extra))
        self.assertEqual(after, before)  # no added attrs

    def test__call__w_ILocation_w_spacesuit(self):
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import getObject
        from zope.security.proxy import removeSecurityProxy
        factory = self._makeFactory()
        factory.__parent__ = factory.__name__ = None
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)

        class _Adapter(object):
            pass
        adapter = _Adapter()
        proxy = ProxyFactory(adapter)
        before = {k: v for k, v in factory.__dict__.items()
                  if k not in ('_called_with', '__parent__')}
        returned = ltaf(proxy)
        self.assertFalse(returned is factory)
        ploc = removeSecurityProxy(returned)
        self.assertIs(ploc.__parent__, adapter)
        unwrapped = getObject(ploc)
        self.assertIs(unwrapped, factory)
        after = {k: v for k, v in unwrapped.__dict__.items()
                 if k not in ('_called_with', '__parent__')}
        self.assertEqual(factory._called_with, (adapter,))
        self.assertIs(factory.__parent__, adapter)
        self.assertEqual(after, before)  # no added attrs

    def test__call__w_ILocation_w_spacesuit_w_existing_parent(self):
        from zope.security.proxy import ProxyFactory
        from zope.security.proxy import getObject
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
        before = {k: v for k, v in factory.__dict__.items()
                  if k not in ('_called_with', '__parent__')}
        returned = ltaf(proxy)
        self.assertFalse(returned is factory)
        ploc = removeSecurityProxy(returned)
        self.assertIs(ploc.__parent__, parent)
        unwrapped = getObject(ploc)
        self.assertIs(unwrapped, factory)
        after = {k: v for k, v in unwrapped.__dict__.items()
                 if k not in ('_called_with', '__parent__')}
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before)  # no added attrs


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
        self.assertIs(unwrapped, factory)
        after = {k: v for k, v in unwrapped.__dict__.items()
                 if k not in ('_called_with',)}
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before)  # no added attrs

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
        self.assertIs(unwrapped, factory)
        after = {k: v for k, v in unwrapped.__dict__.items()
                 if k not in ('_called_with',)}
        self.assertEqual(factory._called_with, (adapter, extra))
        self.assertEqual(after, before)  # no added attrs

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
        self.assertIs(unwrapped, factory)
        after = {k: v for k, v in unwrapped.__dict__.items()
                 if k not in ('_called_with',)}
        self.assertEqual(factory._called_with, (adapter, extra))
        self.assertEqual(after, before)  # no added attrs

    def test__call__w_ILocation_w_spacesuit(self):
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
        before = {k: v for k, v in factory.__dict__.items()
                  if k not in ('_called_with', '__parent__')}
        returned = ltaf(proxy)
        self.assertFalse(returned is factory)
        unwrapped = removeSecurityProxy(returned)
        self.assertIs(unwrapped.__parent__, adapter)
        self.assertIs(unwrapped, factory)
        after = {k: v for k, v in unwrapped.__dict__.items()
                 if k not in ('_called_with', '__parent__')}
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before)  # no added attrs

    def test__call__w_ILocation_w_spacesuit_w_existing_parent(self):
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
        before = {k: v for k, v in factory.__dict__.items()
                  if k not in ('_called_with', '__parent__')}
        returned = ltaf(proxy)
        self.assertFalse(returned is factory)
        unwrapped = removeSecurityProxy(returned)
        self.assertIs(unwrapped.__parent__, parent)
        self.assertIs(unwrapped, factory)
        after = {k: v for k, v in unwrapped.__dict__.items()
                 if k not in ('_called_with', '__parent__')}
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before)  # no added attrs


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
            _called_with = ()

            def __call__(self, *args):
                self._called_with = args
                return self
        return _Factory()

    def test_ctor(self):
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)
        self.assertIs(ltaf.factory, factory)
        self.assertEqual(ltaf.__name__, 'testing')
        self.assertEqual(ltaf.__module__, 'zope.security.tests.test_adapter')

    def test__call__w_non_ILocation(self):
        factory = self._makeFactory()
        ltaf = self._makeOne(factory)

        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        before = factory.__dict__.copy()
        returned = ltaf(adapter)
        self.assertFalse(returned is factory)
        unwrapped = getProxiedObject(returned)
        self.assertIs(unwrapped, factory)
        after = {k: v for k, v in returned.__dict__.items()
                 if k != '_called_with'}
        self.assertEqual(factory._called_with, (adapter,))
        self.assertEqual(after, before)  # no added attrs

    def test__call__w_non_ILocation_multiple_args(self):
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
        self.assertIs(unwrapped, factory)
        after = {k: v for k, v in returned.__dict__.items()
                 if k != '_called_with'}
        self.assertEqual(factory._called_with, (adapter, extra))
        self.assertEqual(after, before)  # no added attrs

    def test__call__w_ILocation_w_existing_parent(self):
        factory = self._makeFactory()
        parent = factory.__parent__ = object()
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)

        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        returned = ltaf(adapter)
        self.assertIs(returned, factory)
        self.assertIs(returned.__parent__, parent)

    def test__call__w_ILocation_wo_existing_parent(self):
        factory = self._makeFactory()
        factory.__parent__ = None
        directlyProvides(factory, ILocation)
        ltaf = self._makeOne(factory)

        class _NotAdapter(object):
            pass
        adapter = _NotAdapter()
        returned = ltaf(adapter)
        self.assertIs(returned, factory)
        self.assertIs(returned.__parent__, adapter)


def test_suite():
    return unittest.defaultTestLoader.loadTestsFromName(__name__)
