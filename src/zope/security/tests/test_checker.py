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
"""Tests for zope.security.checker
"""
import unittest

def _skip_if_not_Py2(testfunc):
    import sys
    return unittest.skipIf(sys.version_info[0] >= 3, "Needs Python 2")(testfunc)

def _skip_if_no_btrees(testfunc):
    try:
        import BTrees
    except ImportError:
        return unittest.skip("BTrees is not installed")(testfunc)
    else:
        return testfunc

class Test_ProxyFactory(unittest.TestCase):

    def _callFUT(self, object, checker=None):
        from zope.security.checker import ProxyFactory
        return ProxyFactory(object, checker)

    def test_w_already_proxied_no_checker(self):
        from zope.security.proxy import Proxy, getChecker
        obj = object()
        def _check(*x):
            pass
        proxy = Proxy(obj, _check)
        returned = self._callFUT(proxy, None)
        self.assertTrue(returned is proxy)
        self.assertTrue(getChecker(returned) is _check)

    def test_w_already_proxied_same_checker(self):
        from zope.security.proxy import Proxy, getChecker
        obj = object()
        def _check(*x):
            pass
        proxy = Proxy(obj, _check)
        returned = self._callFUT(proxy, _check)
        self.assertTrue(returned is proxy)
        self.assertTrue(getChecker(returned) is _check)

    def test_w_already_proxied_different_checker(self):
        from zope.security.proxy import Proxy
        obj = object()
        def _check(*x):
            pass
        proxy = Proxy(obj, _check)
        def _sneaky(*x):
            pass
        self.assertRaises(TypeError, self._callFUT, proxy, _sneaky)

    def test_w_explicit_checker(self):
        from zope.security.proxy import getChecker
        obj = object()
        def _check(*x):
            pass
        returned = self._callFUT(obj, _check)
        self.assertFalse(returned is obj)
        self.assertTrue(getChecker(returned) is _check)

    def test_no_checker_no_dunder_no_select(self):
        obj = object()
        returned = self._callFUT(obj)
        self.assertTrue(returned is obj)

    def test_no_checker_w_dunder(self):
        from zope.security.proxy import getChecker, getObject
        _check = object() # don't use a func, due to bound method
        class _WithChecker(object):
            __Security_checker__ = _check
        obj = _WithChecker()
        returned = self._callFUT(obj)
        self.assertFalse(returned is obj)
        self.assertTrue(getObject(returned) is obj)
        self.assertTrue(getChecker(returned) is _check)

    def test_no_checker_no_dunder_w_select(self):
        from zope.security.checker import Checker
        from zope.security.checker import _checkers
        from zope.security.checker import _clear
        from zope.security.proxy import getChecker, getObject
        class _Obj(object):
            pass
        obj = _Obj()
        _checker = Checker({})
        def _check(*args):
            return _checker
        _checkers[_Obj] = _check
        try:
            returned = self._callFUT(obj)
            self.assertFalse(returned is obj)
            self.assertTrue(getObject(returned) is obj)
            self.assertTrue(getChecker(returned) is _checker)
        finally:
            _clear()


class Test_canWrite(unittest.TestCase):

    def _callFUT(self, obj, name):
        from zope.security.checker import canWrite
        return canWrite(obj, name)

    def _makeChecker(self, ch_get=None, ch_set=None):
        class _Checker(object):
            def check_getattr(self, obj, name):
                if ch_get is not None:
                    raise ch_get()
            def check_setattr(self, obj, name):
                if ch_set is not None:
                    raise ch_set()
        return _Checker()

    def test_ok(self):
        from zope.security.proxy import Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker())
        self.assertTrue(self._callFUT(proxy, 'whatever'))

    def test_w_setattr_unauth(self):
        from zope.security.interfaces import Unauthorized
        from zope.security.proxy import Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker(ch_set=Unauthorized))
        self.assertFalse(self._callFUT(proxy, 'whatever'))

    def test_w_setattr_forbidden_getattr_allowed(self):
        from zope.security.interfaces import ForbiddenAttribute
        from zope.security.proxy import Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker(ch_set=ForbiddenAttribute))
        self.assertFalse(self._callFUT(proxy, 'whatever'))

    def test_w_setattr_forbidden_getattr_unauth(self):
        from zope.security.interfaces import ForbiddenAttribute
        from zope.security.interfaces import Unauthorized
        from zope.security.proxy import Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker(ch_get=Unauthorized,
                                             ch_set=ForbiddenAttribute))
        self.assertFalse(self._callFUT(proxy, 'whatever'))

    def test_w_setattr_forbidden_getattr_forbidden(self):
        from zope.security.interfaces import ForbiddenAttribute
        from zope.security.proxy import Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker(ch_get=ForbiddenAttribute,
                                             ch_set=ForbiddenAttribute))
        self.assertRaises(ForbiddenAttribute, self._callFUT, proxy, 'whatever')


class Test_canAccess(unittest.TestCase):

    def _callFUT(self, obj, name):
        from zope.security.checker import canAccess
        return canAccess(obj, name)

    def _makeChecker(self, ch_get=None):
        class _Checker(object):
            def check_getattr(self, obj, name):
                if ch_get is not None:
                    raise ch_get()
        return _Checker()

    def test_ok(self):
        from zope.security.proxy import Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker())
        self.assertTrue(self._callFUT(proxy, 'whatever'))

    def test_w_getattr_unauth(self):
        from zope.security.interfaces import Unauthorized
        from zope.security.proxy import Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker(ch_get=Unauthorized))
        self.assertFalse(self._callFUT(proxy, 'whatever'))

    def test_w_setattr_forbidden_getattr_allowed(self):
        from zope.security.interfaces import ForbiddenAttribute
        from zope.security.proxy import Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker(ch_get=ForbiddenAttribute))
        self.assertRaises(ForbiddenAttribute, self._callFUT, proxy, 'whatever')


_marker = []
class CheckerTestsBase(object):

    def _getTargetClass(self):
        from zope.security.checker import Checker
        return Checker

    def _makeOne(self, get_permissions=_marker, set_permissions=_marker):
        if get_permissions is _marker:
            get_permissions = {}
        if set_permissions is _marker:
            return self._getTargetClass()(get_permissions)
        return self._getTargetClass()(get_permissions, set_permissions)

    def test_class_conforms_to_IChecker(self):
        from zope.interface.verify import verifyClass
        from zope.security.interfaces import IChecker
        verifyClass(IChecker, self._getTargetClass())

    def test_instance_conforms_to_IChecker(self):
        from zope.interface.verify import verifyObject
        from zope.security.interfaces import IChecker
        verifyObject(IChecker, self._makeOne())

    def test_ctor_w_non_dict_get_permissions(self):
        self.assertRaises(TypeError, self._makeOne, object())

    def test_ctor_w_non_dict_set_permissions(self):
        self.assertRaises(TypeError, self._makeOne, {}, object())

    def test_permission_id_miss(self):
        checker = self._makeOne()
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_permission_id_hit(self):
        checker = self._makeOne({'name': 'PERMISSION'})
        self.assertEqual(checker.permission_id('name'), 'PERMISSION')

    def test_setattr_permission_id_miss_none_set(self):
        checker = self._makeOne()
        self.assertTrue(checker.setattr_permission_id('nonesuch') is None)

    def test_setattr_permission_id_miss(self):
        checker = self._makeOne(set_permissions={'name': 'PERMISSION'})
        self.assertTrue(checker.setattr_permission_id('nonesuch') is None)

    def test_setattr_permission_id_hit(self):
        checker = self._makeOne(set_permissions={'name': 'PERMISSION'})
        self.assertEqual(checker.setattr_permission_id('name'), 'PERMISSION')

    def test_check_setattr_miss_none_set(self):
        from zope.security.interfaces import ForbiddenAttribute
        checker = self._makeOne()
        obj = object()
        self.assertRaises(ForbiddenAttribute,
                          checker.check_setattr, obj, 'nonesuch')

    def test_check_setattr_miss(self):
        from zope.security.interfaces import ForbiddenAttribute
        checker = self._makeOne(set_permissions={'name': 'PERMISSION'})
        obj = object()
        self.assertRaises(ForbiddenAttribute,
                          checker.check_setattr, obj, 'nonesuch')

    def test_check_setattr_public(self):
        from zope.security.checker import CheckerPublic
        checker = self._makeOne(set_permissions={'name': CheckerPublic})
        obj = object()
        self.assertEqual(checker.check_setattr(obj, 'name'), None)

    def test_check_setattr_w_interaction_allows(self):
        from zope.security._definitions import thread_local
        class _Interaction(object):
            def checkPermission(self, obj, perm):
                return True
        checker = self._makeOne(set_permissions={'name': 'view'})
        obj = object()
        thread_local.interaction = _Interaction()
        try:
            self.assertEqual(checker.check_setattr(obj, 'name'), None)
        finally:
            del thread_local.interaction

    def test_check_setattr_w_interaction_denies(self):
        from zope.security.interfaces import Unauthorized
        from zope.security._definitions import thread_local
        class _Interaction(object):
            def checkPermission(self, obj, perm):
                return False
        checker = self._makeOne(set_permissions={'name': 'view'})
        obj = object()
        thread_local.interaction = _Interaction()
        try:
            self.assertRaises(Unauthorized,
                              checker.check_setattr, obj, 'name')
        finally:
            del thread_local.interaction

    def test_check_miss(self):
        from zope.security.interfaces import ForbiddenAttribute
        checker = self._makeOne()
        obj = object()
        self.assertRaises(ForbiddenAttribute,
                          checker.check, obj, 'nonesuch')

    def test_check_available_by_default(self):
        checker = self._makeOne()
        obj = object()
        self.assertEqual(checker.check(obj, '__repr__'), None)

    def test_check_public(self):
        from zope.security.checker import CheckerPublic
        checker = self._makeOne({'name': CheckerPublic})
        obj = object()
        self.assertEqual(checker.check(obj, 'name'), None)

    def test_check_non_public_w_interaction_allows(self):
        from zope.security._definitions import thread_local
        class _Interaction(object):
            def checkPermission(self, obj, perm):
                return True
        checker = self._makeOne({'name': 'view'})
        obj = object()
        thread_local.interaction = _Interaction()
        try:
            self.assertEqual(checker.check(obj, 'name'), None)
        finally:
            del thread_local.interaction

    def test_check_non_public_w_interaction_denies(self):
        from zope.security.interfaces import Unauthorized
        from zope.security._definitions import thread_local
        class _Interaction(object):
            def checkPermission(self, obj, perm):
                return False
        checker = self._makeOne({'name': 'view'})
        obj = object()
        thread_local.interaction = _Interaction()
        try:
            self.assertRaises(Unauthorized,
                              checker.check, obj, 'name')
        finally:
            del thread_local.interaction

    def test_proxy_already_proxied(self):
        from zope.security.proxy import Proxy, getChecker
        obj = object()
        def _check(*x):
            pass
        proxy = Proxy(obj, _check)
        checker = self._makeOne({'name': 'view'})
        returned = checker.proxy(proxy)
        self.assertTrue(returned is proxy)
        self.assertTrue(getChecker(returned) is _check)

    def test_proxy_no_dunder_no_select(self):
        obj = object()
        checker = self._makeOne()
        returned = checker.proxy(obj)
        self.assertTrue(returned is obj)

    def test_proxy_no_checker_w_dunder(self):
        from zope.security.proxy import getChecker, getObject
        _check = object() # don't use a func, due to bound method
        class _WithChecker(object):
            __Security_checker__ = _check
        obj = _WithChecker()
        checker = self._makeOne()
        returned = checker.proxy(obj)
        self.assertFalse(returned is obj)
        self.assertTrue(getObject(returned) is obj)
        self.assertTrue(getChecker(returned) is _check)

    def test_proxy_no_checker_no_dunder_w_select(self):
        from zope.security.checker import Checker
        from zope.security.checker import _checkers
        from zope.security.checker import _clear
        from zope.security.proxy import getChecker, getObject
        class _Obj(object):
            pass
        obj = _Obj()
        _checker = Checker({})
        def _check(*args):
            return _checker
        _checkers[_Obj] = _check
        try:
            checker = self._makeOne()
            returned = checker.proxy(obj)
            self.assertFalse(returned is obj)
            self.assertTrue(getObject(returned) is obj)
            self.assertTrue(getChecker(returned) is _checker)
        finally:
            _clear()

    def _check_iteration_of_dict_like(self, dict_like):
        from zope.security.proxy import Proxy
        from zope.security.checker import Checker
        from zope.security.checker import _default_checkers

        checker = _default_checkers[dict]

        proxy = Proxy(dict_like, checker)
        # empty
        self.assertEqual([], list(proxy.items()))
        self.assertEqual([], list(proxy.keys()))
        self.assertEqual([], list(proxy.values()))
        self.assertEqual([], list(proxy))

        # With an object
        dict_like[1] = 2
        self.assertEqual([(1, 2)], list(proxy.items()))
        self.assertEqual([1], list(proxy.keys()))
        self.assertEqual([1], list(proxy))
        self.assertEqual([2], list(proxy.values()))


    @_skip_if_no_btrees
    def test_iteration_of_btree_items_keys_values(self):
        # iteration of BTree.items() is allowed by default.
        import BTrees
        for name in ('IF', 'II', 'IO', 'OI', 'OO'):
            for family_name in ('family32', 'family64'):
                family = getattr(BTrees, family_name)
                btree = getattr(family, name).BTree()
                self._check_iteration_of_dict_like(btree)

    def test_iteration_of_odict_items_keys_values(self):
        # iteration of OrderedDict.items() is allowed by default.
        from collections import OrderedDict

        odict = OrderedDict()
        self._check_iteration_of_dict_like(odict)

    def test_iteration_of_dict_items_keys_values(self):
        # iteration of regular dict is allowed by default
        self._check_iteration_of_dict_like(dict())

class CheckerPyTests(unittest.TestCase, CheckerTestsBase):

    def _getTargetClass(self):
        from zope.security.checker import CheckerPy
        return CheckerPy


class CheckerTests(unittest.TestCase, CheckerTestsBase):

    def _getTargetClass(self):
        from zope.security.checker import Checker
        return Checker


class TracebackSupplementTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.security.checker import TracebackSupplement
        return TracebackSupplement

    def _makeOne(self, obj):
        return self._getTargetClass()(obj)

    def test_getInfo_builtin_types(self):
        from zope.security._compat import _BUILTINS
        for val, typ in [('', 'str'),
                         (0, 'int'),
                         (1.0, 'float'),
                         ((), 'tuple'),
                         ([], 'list'),
                         ({}, 'dict'),
                        ]:
            tbs = self._makeOne(val)
            self.assertEqual(tbs.getInfo().splitlines(),
                            ['   - class: %s.%s' % (_BUILTINS, typ),
                             '   - type: %s.%s' % (_BUILTINS, typ),
                            ])

    def test_getInfo_newstyle_instance(self):
        class C(object):
            pass
        tbs = self._makeOne(C())
        self.assertEqual(tbs.getInfo().splitlines(),
                         ['   - class: %s.C' % self.__class__.__module__,
                          '   - type: %s.C' % self.__class__.__module__,
                         ])

    @_skip_if_not_Py2
    def test_getInfo_classic_instance(self):
        exec("class C: pass", globals(), locals())
        tbs = self._makeOne(locals()['C']())
        self.assertEqual(tbs.getInfo().splitlines(),
                         ['   - class: %s.C' % self.__class__.__module__,
                          '   - type: __builtin__.instance',
                         ])


class GlobalTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.security.checker import Global
        return Global

    def _makeOne(self, name, module=_marker):
        if module is _marker:
            return self._getTargetClass()(name)
        return self._getTargetClass()(name, module)

    def test_ctor_name_and_module(self):
        global glob
        glob = self._makeOne('foo', 'bar.baz')
        self.assertEqual(glob.__name__, 'foo')
        self.assertEqual(glob.__module__, 'bar.baz')

    def test___reduce__(self):
        glob = self._makeOne('foo', 'bar.baz')
        self.assertEqual(glob.__reduce__(), 'foo')

    def test___repr__(self):
        glob = self._makeOne('foo', 'bar.baz')
        self.assertEqual(repr(glob), 'Global(foo,bar.baz)')


class Test_NamesChecker(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.security.checker import NamesChecker
        return NamesChecker(*args, **kw)

    def test_empty_names_no_kw(self):
        from zope.interface.verify import verifyObject
        from zope.security.interfaces import IChecker
        checker = self._callFUT()
        verifyObject(IChecker, checker)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_w_names_no_kw(self):
        from zope.security.checker import CheckerPublic
        checker = self._callFUT(('foo', 'bar', 'baz'))
        self.assertTrue(checker.permission_id('foo') is CheckerPublic)
        self.assertTrue(checker.permission_id('bar') is CheckerPublic)
        self.assertTrue(checker.permission_id('baz') is CheckerPublic)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_w_names_no_kw_explicit_permission(self):
        other_perm = object()
        checker = self._callFUT(('foo', 'bar', 'baz'),
                                permission_id=other_perm)
        self.assertTrue(checker.permission_id('foo') is other_perm)
        self.assertTrue(checker.permission_id('bar') is other_perm)
        self.assertTrue(checker.permission_id('baz') is other_perm)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_w_names_w_kw_no_clash(self):
        from zope.security.checker import CheckerPublic
        other_perm = object()
        checker = self._callFUT(('foo', 'bar', 'baz'), bam=other_perm)
        self.assertTrue(checker.permission_id('foo') is CheckerPublic)
        self.assertTrue(checker.permission_id('bar') is CheckerPublic)
        self.assertTrue(checker.permission_id('baz') is CheckerPublic)
        self.assertTrue(checker.permission_id('bam') is other_perm)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_w_names_w_kw_w_clash(self):
        from zope.security.checker import DuplicationError
        other_perm = object()
        self.assertRaises(DuplicationError,
                          self._callFUT, ('foo',), foo=other_perm)


class Test_InterfaceChecker(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.security.checker import InterfaceChecker
        return InterfaceChecker(*args, **kw)

    def test_simple_iface_wo_kw(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.security.checker import CheckerPublic
        class IFoo(Interface):
            bar = Attribute('Bar')
        checker = self._callFUT(IFoo)
        self.assertTrue(checker.permission_id('bar') is CheckerPublic)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_simple_iface_w_explicit_permission(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        class IFoo(Interface):
            bar = Attribute('Bar')
        other_perm = object()
        checker = self._callFUT(IFoo, other_perm)
        self.assertTrue(checker.permission_id('bar') is other_perm)

    def test_simple_iface_w_kw(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.security.checker import CheckerPublic
        class IFoo(Interface):
            bar = Attribute('Bar')
        other_perm = object()
        checker = self._callFUT(IFoo, baz=other_perm)
        self.assertTrue(checker.permission_id('bar') is CheckerPublic)
        self.assertTrue(checker.permission_id('baz') is other_perm)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_derived_iface(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.security.checker import CheckerPublic
        class IFoo(Interface):
            bar = Attribute('Bar')
        class IBar(IFoo):
            baz = Attribute('Baz')
        checker = self._callFUT(IBar)
        self.assertTrue(checker.permission_id('bar') is CheckerPublic)
        self.assertTrue(checker.permission_id('baz') is CheckerPublic)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_w_clash(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.security.checker import DuplicationError
        class IFoo(Interface):
            bar = Attribute('Bar')
            bam = Attribute('Bam')
        other_perm = object()
        self.assertRaises(DuplicationError,
                          self._callFUT, IFoo, bar=other_perm)


class Test_MultiChecker(unittest.TestCase):

    def _callFUT(self, specs):
        from zope.security.checker import MultiChecker
        return MultiChecker(specs)

    def test_empty(self):
        from zope.interface.verify import verifyObject
        from zope.security.interfaces import IChecker
        checker = self._callFUT([])
        verifyObject(IChecker, checker)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_w_spec_as_names(self):
        from zope.security.checker import CheckerPublic
        checker = self._callFUT([(('foo', 'bar', 'baz'), CheckerPublic)])
        self.assertTrue(checker.permission_id('foo') is CheckerPublic)
        self.assertTrue(checker.permission_id('bar') is CheckerPublic)
        self.assertTrue(checker.permission_id('baz') is CheckerPublic)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_w_spec_as_iface(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        class IFoo(Interface):
            bar = Attribute('Bar')
        other_perm = object()
        checker = self._callFUT([(IFoo, other_perm)])
        self.assertTrue(checker.permission_id('bar') is other_perm)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_w_spec_as_names_and_iface(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.security.checker import CheckerPublic
        class IFoo(Interface):
            bar = Attribute('Bar')
        other_perm = object()
        checker = self._callFUT([(IFoo, other_perm),
                                 (('foo', 'baz'), CheckerPublic)])
        self.assertTrue(checker.permission_id('foo') is CheckerPublic)
        self.assertTrue(checker.permission_id('bar') is other_perm)
        self.assertTrue(checker.permission_id('baz') is CheckerPublic)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_w_spec_as_names_and_iface_clash(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.security.checker import CheckerPublic
        from zope.security.checker import DuplicationError
        class IFoo(Interface):
            bar = Attribute('Bar')
        other_perm = object()
        self.assertRaises(DuplicationError,
                          self._callFUT, [(IFoo, other_perm),
                                          (('foo', 'bar'), CheckerPublic)])

    def test_w_spec_as_mapping(self):
        from zope.security.checker import CheckerPublic
        other_perm = object()
        spec = {'foo': CheckerPublic,
                'bar': other_perm,
               }
        checker = self._callFUT([spec])
        self.assertTrue(checker.permission_id('foo') is CheckerPublic)
        self.assertTrue(checker.permission_id('bar') is other_perm)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_w_spec_as_names_and_mapping_clash(self):
        from zope.security.checker import CheckerPublic
        from zope.security.checker import DuplicationError
        other_perm = object()
        spec = {'foo': other_perm,
               }
        self.assertRaises(DuplicationError,
                          self._callFUT,
                          [(('foo', 'bar'), CheckerPublic), spec])



class _SelectCheckerBase(object):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def test_w_basic_types_NoProxy(self):
        import datetime
        from zope.i18nmessageid import Message
        from zope.security._compat import _u
        msg = Message('msg')
        for obj in [object(),
                    42,
                    3.14,
                    None,
                    _u('text'),
                    b'binary',
                    msg,
                    True,
                    datetime.timedelta(1),
                    datetime.datetime.now(),
                    datetime.date.today(),
                    datetime.datetime.now().time(),
                    datetime.tzinfo(),
                   ]:
            self.assertTrue(self._callFUT(obj) is None)

    def test_w_checker_inst(self):
        from zope.security.checker import Checker
        from zope.security.checker import _checkers
        class Foo(object):
            pass
        checker = _checkers[Foo] = Checker({})
        self.assertTrue(self._callFUT(Foo()) is checker)

    def test_w_factory_returning_checker(self):
        from zope.security.checker import Checker
        from zope.security.checker import _checkers
        class Foo(object):
            pass
        checker = Checker({})
        def _factory(obj):
            return checker
        _checkers[Foo] = _factory
        self.assertTrue(self._callFUT(Foo()) is checker)

    def test_w_factory_returning_NoProxy(self):
        from zope.security.checker import NoProxy
        from zope.security.checker import _checkers
        class Foo(object):
            pass
        def _factory(obj):
            return NoProxy
        _checkers[Foo] = _factory
        self.assertTrue(self._callFUT(Foo()) is None)

    def test_w_factory_returning_None(self):
        from zope.security.checker import _checkers
        class Foo(object):
            pass
        def _factory(obj):
            pass
        _checkers[Foo] = _factory
        self.assertTrue(self._callFUT(Foo()) is None)

    def test_w_factory_factory(self):
        from zope.security.checker import Checker
        from zope.security.checker import _checkers
        class Foo(object):
            pass
        checker = Checker({})
        def _factory(obj):
            return checker
        def _factory_factory(obj):
            return _factory
        _checkers[Foo] = _factory_factory
        self.assertTrue(self._callFUT(Foo()) is checker)



class Test_selectCheckerPy(unittest.TestCase, _SelectCheckerBase):

    def _callFUT(self, obj):
        from zope.security.checker import selectCheckerPy
        return selectCheckerPy(obj)



class Test_selectChecker(unittest.TestCase, _SelectCheckerBase):

    def _callFUT(self, obj):
        from zope.security.checker import selectChecker
        return selectChecker(obj)


class Test_getCheckerForInstancesOf(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def _callFUT(self, obj):
        from zope.security.checker import getCheckerForInstancesOf
        return getCheckerForInstancesOf(obj)

    def test_miss(self):
        class Unknown(object):
            pass
        self.assertTrue(self._callFUT(Unknown) is None)

    def test_hit(self):
        from zope.security.checker import _checkers
        class Foo(object):
            pass
        checker = _checkers[Foo] = object()
        self.assertTrue(self._callFUT(Foo) is checker)


class Test_defineChecker(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def _callFUT(self, type_, checker):
        from zope.security.checker import defineChecker
        return defineChecker(type_, checker)

    def test_w_wrong_type(self):
        from zope.security._compat import _u
        checker = object()
        for obj in [object(),
                    42,
                    3.14,
                    None,
                    _u('text'),
                    b'binary',
                    True,
                   ]:
            self.assertRaises(TypeError, self._callFUT, obj, checker)

    def test_w_duplicate(self):
        from zope.exceptions import DuplicationError
        from zope.security.checker import _checkers
        class Foo(object):
            pass
        checker1, checker2 = object(), object()
        _checkers[Foo] = checker1
        self.assertRaises(DuplicationError, self._callFUT, Foo, checker2)

    def test_w_newstyle_class(self):
        from zope.security.checker import _checkers
        checker = object()
        class Foo(object):
            pass
        self._callFUT(Foo, checker)
        self.assertTrue(_checkers[Foo] is checker)

    def test_w_module(self):
        import zope.interface
        from zope.security.checker import _checkers
        checker = object()
        self._callFUT(zope.interface, checker)
        self.assertTrue(_checkers[zope.interface] is checker)

    @_skip_if_not_Py2
    def test_w_oldstyle_class(self):
        from zope.security.checker import _checkers
        checker = object()
        class Foo:
            pass
        self._callFUT(Foo, checker)
        self.assertTrue(_checkers[Foo] is checker)


class Test_undefineChecker(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def _callFUT(self, type_):
        from zope.security.checker import undefineChecker
        return undefineChecker(type_)

    def test_miss(self):
        class Foo(object):
            pass
        self.assertRaises(KeyError, self._callFUT, Foo)

    def test_hit(self):
        from zope.security.checker import _checkers
        class Foo(object):
            pass
        checker = _checkers[Foo] = object()
        self._callFUT(Foo)
        self.assertFalse(Foo in _checkers)


class CombinedCheckerTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.security.checker import CombinedChecker
        return CombinedChecker

    def _makeOne(self, checker1=None, checker2=None):
        if checker1 is None:
            checker1 = self._makeOther()
        if checker2 is None:
            checker1 = self._makeOther()
        return self._getTargetClass()(checker1, checker2)

    def _makeOther(self, get_permissions=None, set_permissions=None):
        from zope.security.checker import Checker
        if get_permissions is None:
            get_permissions = {}
        if set_permissions is None:
            set_permissions = {}
        return Checker(get_permissions, set_permissions)

    def test_class_conforms_to_IChecker(self):
        from zope.interface.verify import verifyClass
        from zope.security.interfaces import IChecker
        verifyClass(IChecker, self._getTargetClass())

    def test_instance_conforms_to_IChecker(self):
        from zope.interface.verify import verifyObject
        from zope.security.interfaces import IChecker
        verifyObject(IChecker, self._makeOne())

    def test_check_lhs_ok_rhs_not_called(self):
        from zope.security.checker import CheckerPublic
        from zope.security.checker import Checker
        class _NeverCalled(Checker):
            def check(self, *args, **kw):
                raise AssertionError
        obj = object()
        lhs = self._makeOther({'name': CheckerPublic})
        rhs = _NeverCalled({})
        combined = self._makeOne(lhs, rhs)
        combined.check(object(), 'name') # no raise

    def test_check_lhs_unauth_rhs_ok(self):
        from zope.security.checker import CheckerPublic
        from zope.security._definitions import thread_local
        class _Interaction(object):
            def checkPermission(self, obj, perm):
                return False
        obj = object()
        lhs = self._makeOther({'name': 'view'}) # unauth
        rhs = self._makeOther({'name': CheckerPublic})
        combined = self._makeOne(lhs, rhs)
        thread_local.interaction = _Interaction()
        try:
            combined.check(object(), 'name') #no raise
        finally:
            del thread_local.interaction

    def test_check_lhs_unauth_rhs_forbidden(self):
        from zope.security.interfaces import Unauthorized
        from zope.security._definitions import thread_local
        class _Interaction(object):
            def checkPermission(self, obj, perm):
                return False
        obj = object()
        lhs = self._makeOther({'name': 'view'}) # unauth
        rhs = self._makeOther() # forbidden
        combined = self._makeOne(lhs, rhs)
        thread_local.interaction = _Interaction()
        try:
            self.assertRaises(Unauthorized,
                              combined.check, object(), 'name')
        finally:
            del thread_local.interaction

    def test_check_lhs_unauth_rhs_unauth(self):
        from zope.security.interfaces import Unauthorized
        from zope.security._definitions import thread_local
        class _Interaction(object):
            def checkPermission(self, obj, perm):
                return False
        obj = object()
        lhs = self._makeOther({'name': 'view'}) # unauth
        rhs = self._makeOther({'name': 'inspect'})
        combined = self._makeOne(lhs, rhs)
        thread_local.interaction = _Interaction()
        try:
            self.assertRaises(Unauthorized,
                              combined.check, object(), 'name')
        finally:
            del thread_local.interaction

    def test_check_lhs_forbidden_rhs_ok(self):
        from zope.security.checker import CheckerPublic
        obj = object()
        lhs = self._makeOther() # forbidden
        rhs = self._makeOther({'name': CheckerPublic})
        combined = self._makeOne(lhs, rhs)
        combined.check(object(), 'name') # no raise

    def test_check_lhs_forbidden_rhs_forbidden(self):
        from zope.security.interfaces import Forbidden
        obj = object()
        lhs = self._makeOther() # forbidden
        rhs = self._makeOther() # forbidden
        combined = self._makeOne(lhs, rhs)
        self.assertRaises(Forbidden,
                          combined.check, object(), 'name')

    def test_check_lhs_forbidden_rhs_unauth(self):
        from zope.security.interfaces import Unauthorized
        from zope.security._definitions import thread_local
        class _Interaction(object):
            def checkPermission(self, obj, perm):
                return False
        obj = object()
        lhs = self._makeOther() # Forbidden
        rhs = self._makeOther({'name': 'inspect'})
        combined = self._makeOne(lhs, rhs)
        thread_local.interaction = _Interaction()
        try:
            self.assertRaises(Unauthorized,
                              combined.check, object(), 'name')
        finally:
            del thread_local.interaction

    def test_check_setattr_lhs_ok_rhs_not_called(self):
        from zope.security.checker import CheckerPublic
        from zope.security.checker import Checker
        class _NeverCalled(Checker):
            def check_setattr(self, *args, **kw):
                raise AssertionError
        obj = object()
        lhs = self._makeOther(set_permissions={'name': CheckerPublic})
        rhs = _NeverCalled({})
        combined = self._makeOne(lhs, rhs)
        combined.check_setattr(object(), 'name') # no raise

    def test_check_setattr_lhs_unauth_rhs_ok(self):
        from zope.security.checker import CheckerPublic
        from zope.security._definitions import thread_local
        class _Interaction(object):
            def checkPermission(self, obj, perm):
                return False
        obj = object()
        lhs = self._makeOther(set_permissions={'name': 'update'}) # unauth
        rhs = self._makeOther(set_permissions={'name': CheckerPublic})
        combined = self._makeOne(lhs, rhs)
        thread_local.interaction = _Interaction()
        try:
            combined.check_setattr(object(), 'name') # no raise
        finally:
            del thread_local.interaction

    def test_check_setattr_lhs_unauth_rhs_forbidden(self):
        from zope.security.interfaces import Unauthorized
        from zope.security._definitions import thread_local
        class _Interaction(object):
            def checkPermission(self, obj, perm):
                return False
        obj = object()
        lhs = self._makeOther(set_permissions={'name': 'view'}) # unauth
        rhs = self._makeOther() # forbidden
        combined = self._makeOne(lhs, rhs)
        thread_local.interaction = _Interaction()
        try:
            self.assertRaises(Unauthorized,
                              combined.check_setattr, object(), 'name')
        finally:
            del thread_local.interaction

    def test_check_setattr_lhs_unauth_rhs_unauth(self):
        from zope.security.interfaces import Unauthorized
        from zope.security._definitions import thread_local
        class _Interaction(object):
            def checkPermission(self, obj, perm):
                return False
        obj = object()
        lhs = self._makeOther(set_permissions={'name': 'view'}) # unauth
        rhs = self._makeOther(set_permissions={'name': 'inspect'}) # unauth
        combined = self._makeOne(lhs, rhs)
        thread_local.interaction = _Interaction()
        try:
            self.assertRaises(Unauthorized,
                              combined.check_setattr, object(), 'name')
        finally:
            del thread_local.interaction

    def test_check_setattr_lhs_forbidden_rhs_ok(self):
        from zope.security.checker import CheckerPublic
        obj = object()
        lhs = self._makeOther() # forbidden
        rhs = self._makeOther(set_permissions={'name': CheckerPublic})
        combined = self._makeOne(lhs, rhs)
        combined.check_setattr(object(), 'name') # no raise

    def test_check_setattr_lhs_forbidden_rhs_forbidden(self):
        from zope.security.interfaces import Forbidden
        obj = object()
        lhs = self._makeOther() # forbidden
        rhs = self._makeOther() # forbidden
        combined = self._makeOne(lhs, rhs)
        self.assertRaises(Forbidden,
                          combined.check_setattr, object(), 'name')

    def test_check_setattr_lhs_forbidden_rhs_unauth(self):
        from zope.security.interfaces import Unauthorized
        from zope.security._definitions import thread_local
        class _Interaction(object):
            def checkPermission(self, obj, perm):
                return False
        obj = object()
        lhs = self._makeOther() # forbidden
        rhs = self._makeOther(set_permissions={'name': 'inspect'}) # unauth
        combined = self._makeOne(lhs, rhs)
        thread_local.interaction = _Interaction()
        try:
            self.assertRaises(Unauthorized,
                              combined.check_setattr, object(), 'name')
        finally:
            del thread_local.interaction


class CheckerLoggingMixinTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.security.checker import CheckerLoggingMixin
        return CheckerLoggingMixin

    def _makeOne(self, raising=None):
        class _Checker(object):
            def __init__(self, raising, stream):
                self._file = stream
                self._raising = raising
            def check(self, object, name):
                if self._raising:
                    raise self._raising
            check_getattr = check_setattr = check
        class _Derived(self._getTargetClass(), _Checker):
            pass
        return _Derived(raising, self._makeStream())

    def _makeStream(self):
        class _Stream(list):
            def write(self, msg):
                self.append(msg)
        return _Stream()

    def _makeObject(self):
        class _Object(object):
            def __repr__(self):
                return 'TESTING'
        return _Object()

    def test_check_ok_normal_verbosity(self):
        checker = self._makeOne()
        checker.check(self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 0)

    def test_check_ok_raised_verbosity_available_by_default(self):
        checker = self._makeOne()
        checker.verbosity = 2
        checker.check(self._makeObject(), '__name__')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] + Always available: __name__ on TESTING\n')

    def test_check_ok_raised_verbosity_normal_name(self):
        checker = self._makeOne()
        checker.verbosity = 2
        checker.check(self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] + Granted: name on TESTING\n')

    def test_check_unauthorized(self):
        from zope.security.interfaces import Unauthorized
        checker = self._makeOne(Unauthorized)
        self.assertRaises(Unauthorized,
                          checker.check, self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] - Unauthorized: name on TESTING\n')

    def test_check_unauthorized_raised_verbosity(self):
        from zope.security.interfaces import Unauthorized
        checker = self._makeOne(Unauthorized)
        checker.verbosity = 2
        self.assertRaises(Unauthorized,
                          checker.check, self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] - Unauthorized: name on TESTING\n')

    def test_check_forbidden_attribute(self):
        from zope.security.interfaces import ForbiddenAttribute
        checker = self._makeOne(ForbiddenAttribute)
        self.assertRaises(ForbiddenAttribute,
                          checker.check, self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] - Forbidden: name on TESTING\n')

    def test_check_getattr_ok_normal_verbosity(self):
        checker = self._makeOne()
        checker.check(self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 0)

    def test_check_getattr_ok_raised_verbosity_available_by_default(self):
        checker = self._makeOne()
        checker.verbosity = 2
        checker.check_getattr(self._makeObject(), '__name__')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] + Always available getattr: '
                         '__name__ on TESTING\n')

    def test_check_getattr_ok_raised_verbosity_normal_name(self):
        checker = self._makeOne()
        checker.verbosity = 2
        checker.check_getattr(self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] + Granted getattr: name on TESTING\n')

    def test_check_getattr_unauthorized(self):
        from zope.security.interfaces import Unauthorized
        checker = self._makeOne(Unauthorized)
        self.assertRaises(Unauthorized,
                          checker.check_getattr, self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] - Unauthorized getattr: name on TESTING\n')

    def test_check_getattr_forbidden_attribute(self):
        from zope.security.interfaces import ForbiddenAttribute
        checker = self._makeOne(ForbiddenAttribute)
        self.assertRaises(ForbiddenAttribute,
                          checker.check_getattr, self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] - Forbidden getattr: name on TESTING\n')

    def test_check_setattr_ok_normal_verbosity(self):
        checker = self._makeOne()
        checker.check_setattr(self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 0)

    def test_check_setattr_ok_raised_verbosity_normal_name(self):
        checker = self._makeOne()
        checker.verbosity = 2
        checker.check_setattr(self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] + Granted setattr: name on TESTING\n')

    def test_check_setattr_unauthorized(self):
        from zope.security.interfaces import Unauthorized
        checker = self._makeOne(Unauthorized)
        self.assertRaises(Unauthorized,
                          checker.check_setattr, self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] - Unauthorized setattr: name on TESTING\n')

    def test_check_setattr_forbidden_attribute(self):
        from zope.security.interfaces import ForbiddenAttribute
        checker = self._makeOne(ForbiddenAttribute)
        self.assertRaises(ForbiddenAttribute,
                          checker.check_setattr, self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] - Forbidden setattr: name on TESTING\n')

    def test_check_setitem_unauthorized(self):
        # __setitem__ is an alias for check_getattr, used for speed reasons
        # (AFAIU calling tp_setitem from C is much faster than calling a
        # method by name).
        from zope.security.interfaces import Unauthorized
        checker = self._makeOne(Unauthorized)
        self.assertRaises(Unauthorized,
                          checker.__setitem__, self._makeObject(), 'name')
        self.assertEqual(len(checker._file), 1)
        self.assertEqual(checker._file[0],
                         '[CHK] - Unauthorized getattr: name on TESTING\n')


class Test__instanceChecker(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def _callFUT(self, type_):
        from zope.security.checker import _instanceChecker
        return _instanceChecker(type_)

    def test_miss(self):
        from zope.security.checker import _defaultChecker
        class Foo(object):
            pass
        self.assertTrue(self._callFUT(Foo()) is _defaultChecker)

    def test_hit(self):
        from zope.security.checker import _checkers
        class Foo(object):
            pass
        checker = _checkers[Foo] = object()
        self.assertTrue(self._callFUT(Foo()) is checker)


class Test_moduleChecker(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def _callFUT(self, type_):
        from zope.security.checker import moduleChecker
        return moduleChecker(type_)

    def test_miss(self):
        from zope.interface import verify
        self.assertTrue(self._callFUT(verify) is None)

    def test_hit(self):
        from zope.interface import verify
        from zope.security.checker import _checkers
        checker = _checkers[verify] = object()
        self.assertTrue(self._callFUT(verify) is checker)


class BasicTypesTests(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def test___setitem__(self):
        from zope.security.checker import BasicTypes
        from zope.security.checker import _checkers
        class Foo(object):
            pass
        checker = object()
        BasicTypes[Foo] = checker
        self.assertTrue(BasicTypes[Foo] is checker)
        self.assertTrue(_checkers[Foo] is checker)

    def test___delitem__(self):
        from zope.security.checker import BasicTypes
        from zope.security.checker import _checkers
        class Foo(object):
            pass
        checker = object()
        BasicTypes[Foo] = checker
        del BasicTypes[Foo]
        self.assertFalse(Foo in BasicTypes)
        self.assertFalse(Foo in _checkers)

    def test_clear(self):
        from zope.security.checker import BasicTypes
        self.assertRaises(NotImplementedError, BasicTypes.clear)

    def test_update(self):
        from zope.security.checker import BasicTypes
        from zope.security.checker import _checkers
        class Foo(object):
            pass
        checker = object()
        BasicTypes.update({Foo:  checker})
        self.assertTrue(BasicTypes[Foo] is checker)
        self.assertTrue(_checkers[Foo] is checker)


# Pre-geddon tests start here

class Test(unittest.TestCase):

    def setUp(self):
        from zope.security.management import newInteraction
        from zope.security.management import setSecurityPolicy
        from zope.security.checker import _clear
        _clear()
        self.__oldpolicy = setSecurityPolicy(self._makeSecurityPolicy())
        newInteraction()

    def tearDown(self):
        from zope.security.management import endInteraction
        from zope.security.management import setSecurityPolicy
        from zope.security.checker import _clear
        endInteraction()
        setSecurityPolicy(self.__oldpolicy)
        _clear()

    def _makeSecurityPolicy(self):
        from zope.interface import implementer
        from zope.security.interfaces import ISecurityPolicy
        @implementer(ISecurityPolicy)
        class SecurityPolicy(object):
            def checkPermission(self, permission, object):
                return permission == 'test_allowed'
        return SecurityPolicy

    @_skip_if_not_Py2
    def test_defineChecker_oldstyle_class(self):
        import types
        from zope.security.checker import defineChecker
        from zope.security.checker import NamesChecker
        class ClassicClass:
            __metaclass__ = types.ClassType
        defineChecker(ClassicClass, NamesChecker())

    def test_defineChecker_newstyle_class(self):
        from zope.security.checker import defineChecker
        from zope.security.checker import NamesChecker
        class NewStyleClass:
            __metaclass__ = type
        defineChecker(NewStyleClass, NamesChecker())

    def test_defineChecker_module(self):
        import zope.security
        from zope.security.checker import defineChecker
        from zope.security.checker import NamesChecker
        defineChecker(zope.security, NamesChecker())

    def test_defineChecker_error(self):
        from zope.security.checker import defineChecker
        from zope.security.checker import NamesChecker
        not_a_type = object()
        self.assertRaises(TypeError,
                defineChecker, not_a_type, NamesChecker())

    def _makeClasses(self):
        import types
        class OldInst:
            __metaclass__ = types.ClassType
            a = 1
            def b(self):
                pass
            c = 2
            def gete(self):
                return 3
            e = property(gete)
            def __getitem__(self, x):
                return 5, x
            def __setitem__(self, x, v):
                pass

        class NewInst(object, OldInst):
            # This is not needed, but left in to show the change of metaclass
            # __metaclass__ = type
            def gete(self):
                return 3
            def sete(self, v):
                pass
            e = property(gete, sete)

        return OldInst, NewInst

    # check_getattr cases:
    #
    # - no attribute there
    # - method
    # - allow and disallow by permission
    @_skip_if_not_Py2
    def test_check_getattr(self):
        from zope.security.interfaces import Forbidden
        from zope.security.interfaces import Unauthorized
        from zope.security.checker import NamesChecker
        from zope.security.checker import CheckerPublic

        OldInst, NewInst = self._makeClasses()

        oldinst = OldInst()
        oldinst.d = OldInst()

        newinst = NewInst()
        newinst.d = NewInst()

        for inst in oldinst, newinst:
            checker = NamesChecker(['a', 'b', 'c', '__getitem__'], 'perm')

            self.assertRaises(Unauthorized, checker.check_getattr, inst, 'a')
            self.assertRaises(Unauthorized, checker.check_getattr, inst, 'b')
            self.assertRaises(Unauthorized, checker.check_getattr, inst, 'c')
            self.assertRaises(Unauthorized, checker.check, inst, '__getitem__')
            self.assertRaises(Forbidden, checker.check, inst, '__setitem__')
            self.assertRaises(Forbidden, checker.check_getattr, inst, 'd')
            self.assertRaises(Forbidden, checker.check_getattr, inst, 'e')
            self.assertRaises(Forbidden, checker.check_getattr, inst, 'f')

            checker = NamesChecker(['a', 'b', 'c', '__getitem__'],
                                   'test_allowed')

            checker.check_getattr(inst, 'a')
            checker.check_getattr(inst, 'b')
            checker.check_getattr(inst, 'c')
            checker.check(inst, '__getitem__')
            self.assertRaises(Forbidden, checker.check, inst, '__setitem__')
            self.assertRaises(Forbidden, checker.check_getattr, inst, 'd')
            self.assertRaises(Forbidden, checker.check_getattr, inst, 'e')
            self.assertRaises(Forbidden, checker.check_getattr, inst, 'f')

            checker = NamesChecker(['a', 'b', 'c', '__getitem__'],
                                   CheckerPublic)

            checker.check_getattr(inst, 'a')
            checker.check_getattr(inst, 'b')
            checker.check_getattr(inst, 'c')
            checker.check(inst, '__getitem__')
            self.assertRaises(Forbidden, checker.check, inst, '__setitem__')
            self.assertRaises(Forbidden, checker.check_getattr, inst, 'd')
            self.assertRaises(Forbidden, checker.check_getattr, inst, 'e')
            self.assertRaises(Forbidden, checker.check_getattr, inst, 'f')

    @_skip_if_not_Py2
    def test_check_setattr(self):
        from zope.security.interfaces import Forbidden
        from zope.security.interfaces import Unauthorized
        from zope.security.checker import Checker
        from zope.security.checker import CheckerPublic

        OldInst, NewInst = self._makeClasses()

        oldinst = OldInst()
        oldinst.d = OldInst()

        newinst = NewInst()
        newinst.d = NewInst()

        for inst in oldinst, newinst:
            checker = Checker({}, {'a': 'perm', 'z': 'perm'})

            self.assertRaises(Unauthorized, checker.check_setattr, inst, 'a')
            self.assertRaises(Unauthorized, checker.check_setattr, inst, 'z')
            self.assertRaises(Forbidden, checker.check_setattr, inst, 'c')
            self.assertRaises(Forbidden, checker.check_setattr, inst, 'd')
            self.assertRaises(Forbidden, checker.check_setattr, inst, 'e')
            self.assertRaises(Forbidden, checker.check_setattr, inst, 'f')

            checker = Checker({}, {'a': 'test_allowed', 'z': 'test_allowed'})

            checker.check_setattr(inst, 'a')
            checker.check_setattr(inst, 'z')
            self.assertRaises(Forbidden, checker.check_setattr, inst, 'd')
            self.assertRaises(Forbidden, checker.check_setattr, inst, 'e')
            self.assertRaises(Forbidden, checker.check_setattr, inst, 'f')

            checker = Checker({}, {'a': CheckerPublic, 'z': CheckerPublic})

            checker.check_setattr(inst, 'a')
            checker.check_setattr(inst, 'z')
            self.assertRaises(Forbidden, checker.check_setattr, inst, 'd')
            self.assertRaises(Forbidden, checker.check_setattr, inst, 'e')
            self.assertRaises(Forbidden, checker.check_setattr, inst, 'f')

    @_skip_if_not_Py2
    def test_proxy(self):
        from zope.security.proxy import getChecker
        from zope.security.proxy import removeSecurityProxy
        from zope.security.checker import BasicTypes_examples
        from zope.security.checker import CheckerPublic
        from zope.security.checker import NamesChecker

        OldInst, NewInst = self._makeClasses()

        checker = NamesChecker(())

        rocks = tuple(BasicTypes_examples.values())
        for rock in rocks:
            proxy = checker.proxy(rock)
            self.assertTrue(proxy is rock, (rock, type(proxy)))

        for class_ in OldInst, NewInst:
            inst = class_()

            for ob in inst, class_:
                proxy = checker.proxy(ob)
                self.assertTrue(removeSecurityProxy(proxy) is ob)
                checker = getChecker(proxy)
                if ob is inst:
                    self.assertEqual(checker.permission_id('__str__'),
                                     None)
                else:
                    self.assertEqual(checker.permission_id('__str__'),
                                     CheckerPublic)

            #No longer doing anything special for transparent proxies.
            #A proxy needs to provide its own security checker.
            #
            #special = NamesChecker(['a', 'b'], 'test_allowed')
            #defineChecker(class_, special)
            #
            #class TransparentProxy(object):
            #    def __init__(self, ob):
            #        self._ob = ob
            #
            #   def __getattribute__(self, name):
            #       ob = object.__getattribute__(self, '_ob')
            #       return getattr(ob, name)
            #for ob in inst, TransparentProxy(inst):
            #    proxy = checker.proxy(ob)
            #    self.assertTrue(removeSecurityProxy(proxy) is ob)
            #
            #    checker = getChecker(proxy)
            #    self.assertTrue(checker is special,
            #                    checker.get_permissions)
            #
            #    proxy2 = checker.proxy(proxy)
            #    self.assertTrue(proxy2 is proxy, [proxy, proxy2])

    def test_iteration(self):
        from zope.security.checker import ProxyFactory
        from zope.security.checker import selectChecker

        for i in ((1,), [1]):
            _iter = iter(i)
            proxy = ProxyFactory(_iter, selectChecker(_iter))
            self.assertEqual(next(proxy), 1)

    def testLayeredProxies(self):
        #Test that a Proxy will not be re-proxied.
        from zope.security.proxy import Proxy, getObject
        from zope.security.checker import Checker
        from zope.security.checker import NamesChecker
        class Base:
            __Security_checker__ = NamesChecker(['__Security_checker__'])
        base = Base()
        checker = Checker({})

        # base is not proxied, so we expect a proxy
        proxy1 = checker.proxy(base)
        self.assertTrue(type(proxy1) is Proxy)
        self.assertTrue(getObject(proxy1) is base)

        # proxy is a proxy, so we don't expect to get another
        proxy2 = checker.proxy(proxy1)
        self.assertTrue(proxy2 is proxy1)
        self.assertTrue(getObject(proxy2) is base)


    def testMultiChecker(self):
        from zope.interface import Interface

        class I1(Interface):
            def f1(): ''
            def f2(): ''

        class I2(I1):
            def f3(): ''
            def f4(): ''

        class I3(Interface):
            def g(): ''

        from zope.exceptions import DuplicationError

        from zope.security.checker import MultiChecker

        self.assertRaises(DuplicationError,
                          MultiChecker,
                          [(I1, 'p1'), (I2, 'p2')])

        self.assertRaises(DuplicationError,
                          MultiChecker,
                          [(I1, 'p1'), {'f2': 'p2'}])

        MultiChecker([(I1, 'p1'), (I2, 'p1')])

        checker = MultiChecker([
            (I2, 'p1'),
            {'a': 'p3'},
            (I3, 'p2'),
            (('x','y','z'), 'p4'),
            ])

        self.assertEqual(checker.permission_id('f1'), 'p1')
        self.assertEqual(checker.permission_id('f2'), 'p1')
        self.assertEqual(checker.permission_id('f3'), 'p1')
        self.assertEqual(checker.permission_id('f4'), 'p1')
        self.assertEqual(checker.permission_id('g'), 'p2')
        self.assertEqual(checker.permission_id('a'), 'p3')
        self.assertEqual(checker.permission_id('x'), 'p4')
        self.assertEqual(checker.permission_id('y'), 'p4')
        self.assertEqual(checker.permission_id('z'), 'p4')
        self.assertEqual(checker.permission_id('zzz'), None)

    def testAlwaysAvailable(self):
        from zope.security.checker import NamesChecker
        checker = NamesChecker(())
        class C(object): pass
        self.assertEqual(checker.check(C, '__hash__'), None)
        self.assertEqual(checker.check(C, '__nonzero__'), None)
        self.assertEqual(checker.check(C, '__class__'), None)
        self.assertEqual(checker.check(C, '__implements__'), None)
        self.assertEqual(checker.check(C, '__lt__'), None)
        self.assertEqual(checker.check(C, '__le__'), None)
        self.assertEqual(checker.check(C, '__gt__'), None)
        self.assertEqual(checker.check(C, '__ge__'), None)
        self.assertEqual(checker.check(C, '__eq__'), None)
        self.assertEqual(checker.check(C, '__ne__'), None)
        self.assertEqual(checker.check(C, '__name__'), None)
        self.assertEqual(checker.check(C, '__parent__'), None)

    @_skip_if_not_Py2
    def test_setattr(self):
        from zope.security.interfaces import Forbidden
        from zope.security.checker import NamesChecker

        OldInst, NewInst = self._makeClasses()

        checker = NamesChecker(['a', 'b', 'c', '__getitem__'],
                               'test_allowed')

        for inst in NewInst(), OldInst():
            self.assertRaises(Forbidden, checker.check_setattr, inst, 'a')
            self.assertRaises(Forbidden, checker.check_setattr, inst, 'z')

    # TODO: write a test to see that
    # Checker.check/check_setattr handle permission
    # values that evaluate to False

    def test_ProxyFactory(self):
        from zope.security.checker import _defaultChecker
        from zope.security.checker import defineChecker
        from zope.security.checker import NamesChecker
        from zope.security.checker import ProxyFactory
        from zope.security.proxy import getChecker
        from zope.security.proxy import Proxy
        class SomeClass(object):
            pass
        checker = NamesChecker()
        specific_checker = NamesChecker()
        checker_as_magic_attr = NamesChecker()

        obj = SomeClass()

        proxy = ProxyFactory(obj)
        self.assertTrue(type(proxy) is Proxy)
        self.assertTrue(getChecker(proxy) is _defaultChecker)

        defineChecker(SomeClass, checker)

        proxy = ProxyFactory(obj)
        self.assertTrue(type(proxy) is Proxy)
        self.assertTrue(getChecker(proxy) is checker)

        obj.__Security_checker__ = checker_as_magic_attr

        proxy = ProxyFactory(obj)
        self.assertTrue(type(proxy) is Proxy)
        self.assertTrue(getChecker(proxy) is checker_as_magic_attr)

        proxy = ProxyFactory(obj, specific_checker)
        self.assertTrue(type(proxy) is Proxy)
        self.assertTrue(getChecker(proxy) is specific_checker)

    def test_define_and_undefineChecker(self):
        from zope.security.checker import defineChecker
        from zope.security.checker import NamesChecker
        from zope.security.checker import undefineChecker
        class SomeClass(object):
            pass
        obj = SomeClass()

        checker = NamesChecker()
        from zope.security.checker import _defaultChecker, selectChecker
        self.assertTrue(selectChecker(obj) is _defaultChecker)
        defineChecker(SomeClass, checker)
        self.assertTrue(selectChecker(obj) is checker)
        undefineChecker(SomeClass)
        self.assertTrue(selectChecker(obj) is _defaultChecker)

    def test_ProxyFactory_using_proxy(self):
        from zope.security.checker import ProxyFactory
        from zope.security.checker import NamesChecker
        class SomeClass(object):
            pass
        obj = SomeClass()
        checker = NamesChecker()
        proxy1 = ProxyFactory(obj)

        proxy2 = ProxyFactory(proxy1)
        self.assertTrue(proxy1 is proxy2)

        # Trying to change the checker on a proxy.
        self.assertRaises(TypeError, ProxyFactory, proxy1, checker)

        # Setting exactly the same checker as the proxy already has.
        proxy1 = ProxyFactory(obj, checker)
        proxy2 = ProxyFactory(proxy1, checker)
        self.assertTrue(proxy1 is proxy2)

    def test_canWrite_canAccess(self):
        # the canWrite and canAccess functions are conveniences.  Often code
        # wants to check if a certain option is open to a user before
        # presenting it.  If the code relies on a certain permission, the
        # Zope 3 goal of keeping knowledge of security assertions out of the
        # code and only in the zcml assertions is broken.  Instead, ask if the
        # current user canAccess or canWrite some pertinent aspect of the
        # object.  canAccess is used for both read access on an attribute
        # and call access to methods.

        # For example, consider this humble pair of class and object.
        from zope.security.interfaces import Forbidden
        from zope.security.checker import Checker
        from zope.security.checker import canAccess
        from zope.security.checker import canWrite
        from zope.security.checker import defineChecker
        class SomeClass(object):
            pass
        obj = SomeClass()

        # We will establish a checker for the class.  This is the standard
        # name-based checker, and works by specifying two dicts, one for read
        # and one for write.  Each item in the dictionary should be an
        # attribute name and the permission required to read or write it.

        # For these tests, the SecurityPolicy defined at the top of this file
        # is in place.  It is a stub.  Normally, the security policy would
        # have knowledge of interactions and participants, and would determine
        # on the basis of the particpants and the object if a certain permission
        # were authorized.  This stub simply says that the 'test_allowed'
        # permission is authorized and nothing else is, for any object you pass
        # it.

        # Therefore, according to the checker created here, the current
        # 'interaction' (as stubbed out in the security policy) will be allowed
        # to access and write foo, and access bar.  The interaction is
        # unauthorized for accessing baz and writing bar.  Any other access or
        # write is not merely unauthorized but forbidden--including write access
        # for baz.
        checker = Checker(
            {'foo':'test_allowed', # these are the read settings
             'bar':'test_allowed',
             'baz':'you_will_not_have_this_permission'},
            {'foo':'test_allowed', # these are the write settings
             'bar':'you_will_not_have_this_permission',
             'bing':'you_will_not_have_this_permission'})
        defineChecker(SomeClass, checker)

        # so, our hapless interaction may write and access foo...
        self.assertTrue(canWrite(obj, 'foo'))
        self.assertTrue(canAccess(obj, 'foo'))

        # ...may access, but not write, bar...
        self.assertTrue(not canWrite(obj, 'bar'))
        self.assertTrue(canAccess(obj, 'bar'))

        # ...and may access baz.
        self.assertTrue(not canAccess(obj, 'baz'))

        # there are no security assertions for writing or reading shazam, so
        # checking these actually raises Forbidden.  The rationale behind
        # exposing the Forbidden exception is primarily that it is usually
        # indicative of programming or configuration errors.
        self.assertRaises(Forbidden, canAccess, obj, 'shazam')
        self.assertRaises(Forbidden, canWrite, obj, 'shazam')

        # However, we special-case canWrite when an attribute has a Read
        # setting but no Write setting.  Consider the 'baz' attribute from the
        # checker above: it is readonly.  All users are forbidden to write
        # it.  This is a very reasonable configuration.  Therefore, canWrite
        # will hide the Forbidden exception if and only if there is a
        # setting for accessing the attribute.
        self.assertTrue(not canWrite(obj, 'baz'))

        # The reverse is not true at the moment: an unusal case like the
        # write-only 'bing' attribute will return a boolean for canWrite,
        # but canRead will simply raise a Forbidden exception, without checking
        # write settings.
        self.assertTrue(not canWrite(obj, 'bing'))
        self.assertRaises(Forbidden, canAccess, obj, 'bing')

class TestCheckerPublic(unittest.TestCase):

    def test_that_pickling_CheckerPublic_retains_identity(self):
        from zope.security._compat import _pickle
        from zope.security.checker import CheckerPublic
        self.assertTrue(_pickle.loads(_pickle.dumps(CheckerPublic))
                     is
                     CheckerPublic)

    def test_that_CheckerPublic_identity_works_even_when_proxied(self):
        from zope.security.checker import ProxyFactory
        from zope.security.checker import CheckerPublic
        self.assertTrue(ProxyFactory(CheckerPublic) is CheckerPublic)


class TestMixinDecoratedChecker(unittest.TestCase):

    def decoratedSetUp(self):
        from zope.security.management import getInteraction
        from zope.security.management import newInteraction
        from zope.security.management import setSecurityPolicy
        self.policy = self._makeSecurityPolicy()
        self._oldpolicy = setSecurityPolicy(self.policy)
        newInteraction()
        self.interaction = getInteraction()
        self.obj = object()

    def decoratedTearDown(self):
        from zope.security.management import endInteraction
        from zope.security.management import setSecurityPolicy
        endInteraction()
        setSecurityPolicy(self._oldpolicy)

    def _makeSecurityPolicy(self):
        from zope.interface import implementer
        from zope.security.interfaces import ISecurityPolicy
        @implementer(ISecurityPolicy)
        class RecordedSecurityPolicy(object):
            def __init__(self):
                self._checked = []
                self.permissions = {}
            def checkPermission(self, permission, object):
                self._checked.append(permission)
                return self.permissions.get(permission, True)
            def checkChecked(self, checked):
                res = self._checked == checked
                self._checked = []
                return res
        return RecordedSecurityPolicy

    def check_checking_impl(self, checker):
        from zope.security.interfaces import ForbiddenAttribute
        o = self.obj
        checker.check_getattr(o, 'both_get_set')
        self.assertTrue(self.interaction.checkChecked(['dc_get_permission']))
        checker.check_getattr(o, 'c_only')
        self.assertTrue(self.interaction.checkChecked(['get_permission']))
        checker.check_getattr(o, 'd_only')
        self.assertTrue(self.interaction.checkChecked(['dc_get_permission']))
        self.assertRaises(ForbiddenAttribute,
                          checker.check_getattr, o,
                          'completely_different_attr')
        self.assertTrue(self.interaction.checkChecked([]))
        checker.check(o, '__str__')
        self.assertTrue(self.interaction.checkChecked(['get_permission']))

        checker.check_setattr(o, 'both_get_set')
        self.assertTrue(self.interaction.checkChecked(['dc_set_permission']))
        self.assertRaises(ForbiddenAttribute,
                          checker.check_setattr, o, 'c_only')
        self.assertTrue(self.interaction.checkChecked([]))
        self.assertRaises(ForbiddenAttribute,
                          checker.check_setattr, o, 'd_only')
        self.assertTrue(self.interaction.checkChecked([]))

    @property
    def originalChecker(self):
        from zope.security.checker import NamesChecker
        return NamesChecker(['both_get_set', 'c_only', '__str__'],
                            'get_permission')

    decorationSetMap = {'both_get_set': 'dc_set_permission'}

    decorationGetMap = {'both_get_set': 'dc_get_permission',
                        'd_only': 'dc_get_permission'}

    @property
    def overridingChecker(self):
        from zope.security.checker import Checker
        return Checker(self.decorationGetMap, self.decorationSetMap)

class TestCombinedChecker(TestMixinDecoratedChecker, unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.decoratedSetUp()

    def tearDown(self):
        self.decoratedTearDown()
        unittest.TestCase.tearDown(self)

    def test_checking(self):
        from zope.security.interfaces import Unauthorized
        from zope.security.checker import CombinedChecker
        cc = CombinedChecker(self.overridingChecker, self.originalChecker)
        self.check_checking_impl(cc)

        # When a permission is not authorized by the security policy,
        # the policy is queried twice per check_getattr -- once for each
        # checker.
        self.interaction.permissions['dc_get_permission'] = False
        cc.check_getattr(self.obj, 'both_get_set')
        self.assertTrue(
            self.interaction.checkChecked(['dc_get_permission',
                                           'get_permission'])
            )

        # This should raise Unauthorized instead of ForbiddenAttribute, since
        # access can be granted if you e.g. login with different credentials.
        self.assertRaises(Unauthorized, cc.check_getattr, self.obj, 'd_only')
        self.assertRaises(Unauthorized, cc.check, self.obj, 'd_only')

    def test_interface(self):
        from zope.interface.verify import verifyObject
        from zope.security.checker import CombinedChecker
        from zope.security.interfaces import IChecker
        dc = CombinedChecker(self.overridingChecker, self.originalChecker)
        verifyObject(IChecker, dc)


class TestBasicTypes(unittest.TestCase):

    def test(self):
        from zope.security.checker import BasicTypes
        from zope.security.checker import NoProxy
        from zope.security.checker import _checkers
        from zope.security.checker import _clear
        class MyType(object): pass
        class MyType2(object): pass

        # When an item is added to the basic types, it should also be added to
        # the list of checkers.
        BasicTypes[MyType] = NoProxy
        self.assertTrue(MyType in _checkers)

        # If we clear the checkers, the type should still be there
        _clear()
        self.assertTrue(MyType in BasicTypes)
        self.assertTrue(MyType in _checkers)

        # Now delete the type from the dictionary, will also delete it from
        # the checkers
        del BasicTypes[MyType]
        self.assertTrue(MyType not in BasicTypes)
        self.assertTrue(MyType not in _checkers)

        # The quick way of adding new types is using update
        BasicTypes.update({MyType: NoProxy, MyType2: NoProxy})
        self.assertTrue(MyType in BasicTypes)
        self.assertTrue(MyType2 in BasicTypes)
        self.assertTrue(MyType in _checkers)
        self.assertTrue(MyType2 in _checkers)

        # Let's remove the two new types
        del BasicTypes[MyType]
        del BasicTypes[MyType2]

        # Of course, BasicTypes is a full dictionary. This dictionary is by
        # default filled with several entries:
        keys = BasicTypes.keys()
        self.assertTrue(bool in keys)
        self.assertTrue(int in keys)
        self.assertTrue(float in keys)
        self.assertTrue(str in keys)
        try:
            unicode
        except NameError: #pragma NO COVER Py3k
            pass
        else:             #pragma NO COVER Python2
            self.assertTrue(unicode in keys)
        self.assertTrue(object in keys)
        # ...

        # Finally, the ``clear()`` method has been deactivated to avoid
        # unwanted deletions.
        self.assertRaises(NotImplementedError, BasicTypes.clear)

def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(Test_ProxyFactory),
        unittest.makeSuite(Test_canWrite),
        unittest.makeSuite(Test_canAccess),
        unittest.makeSuite(Test_canAccess),
        unittest.makeSuite(CheckerPyTests),
        unittest.makeSuite(CheckerTests),
        unittest.makeSuite(TracebackSupplementTests),
        unittest.makeSuite(GlobalTests),
        unittest.makeSuite(Test_NamesChecker),
        unittest.makeSuite(Test_InterfaceChecker),
        unittest.makeSuite(Test_MultiChecker),
        unittest.makeSuite(Test_selectCheckerPy),
        unittest.makeSuite(Test_selectChecker),
        unittest.makeSuite(Test_getCheckerForInstancesOf),
        unittest.makeSuite(Test_defineChecker),
        unittest.makeSuite(Test_undefineChecker),
        unittest.makeSuite(CombinedCheckerTests),
        unittest.makeSuite(CheckerLoggingMixinTests),
        unittest.makeSuite(Test__instanceChecker),
        unittest.makeSuite(Test_moduleChecker),
        unittest.makeSuite(BasicTypesTests),
        # pre-geddon fossils
        unittest.makeSuite(Test),
        unittest.makeSuite(TestCheckerPublic),
        unittest.makeSuite(TestCombinedChecker),
        unittest.makeSuite(TestBasicTypes),
    ))
