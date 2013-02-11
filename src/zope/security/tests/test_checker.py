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
    from functools import update_wrapper
    if sys.version_info[0] >= 3:
        def dummy(self):
            pass
        update_wrapper(dummy, testfunc)
        return dummy
    return testfunc

class Test_ProxyFactory(unittest.TestCase):

    def _callFUT(self, object, checker=None):
        from zope.security.checker import ProxyFactory
        return ProxyFactory(object, checker)

    def test_w_already_proxied_no_checker(self):
        from zope.security._proxy import _Proxy as Proxy
        from zope.security._proxy import getChecker
        obj = object()
        def _check(*x):
            pass
        proxy = Proxy(obj, _check)
        returned = self._callFUT(proxy, None)
        self.assertTrue(returned is proxy)
        self.assertTrue(getChecker(returned) is _check)

    def test_w_already_proxied_same_checker(self):
        from zope.security._proxy import _Proxy as Proxy
        from zope.security._proxy import getChecker
        obj = object()
        def _check(*x):
            pass
        proxy = Proxy(obj, _check)
        returned = self._callFUT(proxy, _check)
        self.assertTrue(returned is proxy)
        self.assertTrue(getChecker(returned) is _check)

    def test_w_already_proxied_different_checker(self):
        from zope.security._proxy import _Proxy as Proxy
        obj = object()
        def _check(*x):
            pass
        proxy = Proxy(obj, _check)
        def _sneaky(*x):
            pass
        self.assertRaises(TypeError, self._callFUT, proxy, _sneaky)

    def test_w_explicit_checker(self):
        from zope.security._proxy import getChecker
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
        from zope.security._proxy import getChecker
        from zope.security._proxy import getObject
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
        from zope.security._proxy import getChecker
        from zope.security._proxy import getObject
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
        from zope.security._proxy import _Proxy as Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker())
        self.assertTrue(self._callFUT(proxy, 'whatever'))

    def test_w_setattr_unauth(self):
        from zope.security.interfaces import Unauthorized
        from zope.security._proxy import _Proxy as Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker(ch_set=Unauthorized))
        self.assertFalse(self._callFUT(proxy, 'whatever'))

    def test_w_setattr_forbidden_getattr_allowed(self):
        from zope.security.interfaces import ForbiddenAttribute
        from zope.security._proxy import _Proxy as Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker(ch_set=ForbiddenAttribute))
        self.assertFalse(self._callFUT(proxy, 'whatever'))

    def test_w_setattr_forbidden_getattr_unauth(self):
        from zope.security.interfaces import ForbiddenAttribute
        from zope.security.interfaces import Unauthorized
        from zope.security._proxy import _Proxy as Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker(ch_get=Unauthorized,
                                             ch_set=ForbiddenAttribute))
        self.assertFalse(self._callFUT(proxy, 'whatever'))

    def test_w_setattr_forbidden_getattr_forbidden(self):
        from zope.security.interfaces import ForbiddenAttribute
        from zope.security._proxy import _Proxy as Proxy
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
        from zope.security._proxy import _Proxy as Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker())
        self.assertTrue(self._callFUT(proxy, 'whatever'))

    def test_w_getattr_unauth(self):
        from zope.security.interfaces import Unauthorized
        from zope.security._proxy import _Proxy as Proxy
        obj = object()
        proxy = Proxy(obj, self._makeChecker(ch_get=Unauthorized))
        self.assertFalse(self._callFUT(proxy, 'whatever'))

    def test_w_setattr_forbidden_getattr_allowed(self):
        from zope.security.interfaces import ForbiddenAttribute
        from zope.security._proxy import _Proxy as Proxy
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
        from zope.security._proxy import _Proxy as Proxy
        from zope.security._proxy import getChecker
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
        from zope.security._proxy import getChecker
        from zope.security._proxy import getObject
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
        from zope.security._proxy import getChecker
        from zope.security._proxy import getObject
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
        for val, typ in [('', 'str'),
                         (0, 'int'),
                         (1.0, 'float'),
                         ((), 'tuple'),
                         ([], 'list'),
                         ({}, 'dict'),
                        ]:
            tbs = self._makeOne(val)
            self.assertEqual(tbs.getInfo().splitlines(),
                            ['   - class: __builtin__.%s' % typ,
                             '   - type: __builtin__.%s' % typ,
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
        other_checker = object()
        checker = self._callFUT(('foo', 'bar', 'baz'),
                                permission_id=other_checker)
        self.assertTrue(checker.permission_id('foo') is other_checker)
        self.assertTrue(checker.permission_id('bar') is other_checker)
        self.assertTrue(checker.permission_id('baz') is other_checker)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_w_names_w_kw_no_clash(self):
        from zope.security.checker import CheckerPublic
        other_checker = object()
        checker = self._callFUT(('foo', 'bar', 'baz'), bam=other_checker)
        self.assertTrue(checker.permission_id('foo') is CheckerPublic)
        self.assertTrue(checker.permission_id('bar') is CheckerPublic)
        self.assertTrue(checker.permission_id('baz') is CheckerPublic)
        self.assertTrue(checker.permission_id('bam') is other_checker)
        self.assertTrue(checker.permission_id('nonesuch') is None)

    def test_w_names_w_kw_w_clash(self):
        from zope.security.checker import DuplicationError
        other_checker = object()
        self.assertRaises(DuplicationError,
                          self._callFUT, ('foo',), foo=other_checker)


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
        other_checker = object()
        checker = self._callFUT(IFoo, other_checker)
        self.assertTrue(checker.permission_id('bar') is other_checker)

    def test_simple_iface_w_kw(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.security.checker import CheckerPublic
        class IFoo(Interface):
            bar = Attribute('Bar')
        other_checker = object()
        checker = self._callFUT(IFoo, baz=other_checker)
        self.assertTrue(checker.permission_id('bar') is CheckerPublic)
        self.assertTrue(checker.permission_id('baz') is other_checker)
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
        other_checker = object()
        self.assertRaises(DuplicationError,
                          self._callFUT, IFoo, bar=other_checker)



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

    def test_typesAcceptedByDefineChecker(self):
        import types
        import zope.security
        from zope.security.checker import defineChecker
        from zope.security.checker import NamesChecker
        class ClassicClass:
            __metaclass__ = types.ClassType
        class NewStyleClass:
            __metaclass__ = type
        not_a_type = object()
        defineChecker(ClassicClass, NamesChecker())
        defineChecker(NewStyleClass, NamesChecker())
        defineChecker(zope.security, NamesChecker())
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
            self.failUnless(proxy is rock, (rock, type(proxy)))

        for class_ in OldInst, NewInst:
            inst = class_()

            for ob in inst, class_:
                proxy = checker.proxy(ob)
                self.failUnless(removeSecurityProxy(proxy) is ob)
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
            #    self.failUnless(removeSecurityProxy(proxy) is ob)
            #
            #    checker = getChecker(proxy)
            #    self.failUnless(checker is special,
            #                    checker.get_permissions)
            #
            #    proxy2 = checker.proxy(proxy)
            #    self.failUnless(proxy2 is proxy, [proxy, proxy2])

    def testLayeredProxies(self):
        #Test that a Proxy will not be re-proxied.
        from zope.proxy import getProxiedObject
        from zope.security.proxy import Proxy
        from zope.security.checker import Checker
        from zope.security.checker import NamesChecker
        class Base:
            __Security_checker__ = NamesChecker(['__Security_checker__'])
        base = Base()
        checker = Checker({})

        # base is not proxied, so we expect a proxy
        proxy1 = checker.proxy(base)
        self.assert_(type(proxy1) is Proxy)
        self.assert_(getProxiedObject(proxy1) is base)

        # proxy is a proxy, so we don't expect to get another
        proxy2 = checker.proxy(proxy1)
        self.assert_(proxy2 is proxy1)
        self.assert_(getProxiedObject(proxy2) is base)


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
        self.assert_(type(proxy) is Proxy)
        self.assert_(getChecker(proxy) is _defaultChecker)

        defineChecker(SomeClass, checker)

        proxy = ProxyFactory(obj)
        self.assert_(type(proxy) is Proxy)
        self.assert_(getChecker(proxy) is checker)

        obj.__Security_checker__ = checker_as_magic_attr

        proxy = ProxyFactory(obj)
        self.assert_(type(proxy) is Proxy)
        self.assert_(getChecker(proxy) is checker_as_magic_attr)

        proxy = ProxyFactory(obj, specific_checker)
        self.assert_(type(proxy) is Proxy)
        self.assert_(getChecker(proxy) is specific_checker)

    def test_define_and_undefineChecker(self):
        from zope.security.checker import defineChecker
        from zope.security.checker import NamesChecker
        from zope.security.checker import undefineChecker
        class SomeClass(object):
            pass
        obj = SomeClass()

        checker = NamesChecker()
        from zope.security.checker import _defaultChecker, selectChecker
        self.assert_(selectChecker(obj) is _defaultChecker)
        defineChecker(SomeClass, checker)
        self.assert_(selectChecker(obj) is checker)
        undefineChecker(SomeClass)
        self.assert_(selectChecker(obj) is _defaultChecker)

    def test_ProxyFactory_using_proxy(self):
        from zope.security.checker import ProxyFactory
        from zope.security.checker import NamesChecker
        class SomeClass(object):
            pass
        obj = SomeClass()
        checker = NamesChecker()
        proxy1 = ProxyFactory(obj)

        proxy2 = ProxyFactory(proxy1)
        self.assert_(proxy1 is proxy2)

        # Trying to change the checker on a proxy.
        self.assertRaises(TypeError, ProxyFactory, proxy1, checker)

        # Setting exactly the same checker as the proxy already has.
        proxy1 = ProxyFactory(obj, checker)
        proxy2 = ProxyFactory(proxy1, checker)
        self.assert_(proxy1 is proxy2)

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
        self.assert_(canWrite(obj, 'foo'))
        self.assert_(canAccess(obj, 'foo'))

        # ...may access, but not write, bar...
        self.assert_(not canWrite(obj, 'bar'))
        self.assert_(canAccess(obj, 'bar'))

        # ...and may access baz.
        self.assert_(not canAccess(obj, 'baz'))

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
        self.assert_(not canWrite(obj, 'baz'))

        # The reverse is not true at the moment: an unusal case like the
        # write-only 'bing' attribute will return a boolean for canWrite,
        # but canRead will simply raise a Forbidden exception, without checking
        # write settings.
        self.assert_(not canWrite(obj, 'bing'))
        self.assertRaises(Forbidden, canAccess, obj, 'bing')

class TestCheckerPublic(unittest.TestCase):

    def test_that_pickling_CheckerPublic_retains_identity(self):
        import pickle
        from zope.security.checker import CheckerPublic
        self.assert_(pickle.loads(pickle.dumps(CheckerPublic))
                     is
                     CheckerPublic)

    def test_that_CheckerPublic_identity_works_even_when_proxied(self):
        from zope.security.checker import ProxyFactory
        from zope.security.checker import CheckerPublic
        self.assert_(ProxyFactory(CheckerPublic) is CheckerPublic)


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
        self.assert_(self.interaction.checkChecked(['dc_get_permission']))
        checker.check_getattr(o, 'c_only')
        self.assert_(self.interaction.checkChecked(['get_permission']))
        checker.check_getattr(o, 'd_only')
        self.assert_(self.interaction.checkChecked(['dc_get_permission']))
        self.assertRaises(ForbiddenAttribute,
                          checker.check_getattr, o,
                          'completely_different_attr')
        self.assert_(self.interaction.checkChecked([]))
        checker.check(o, '__str__')
        self.assert_(self.interaction.checkChecked(['get_permission']))

        checker.check_setattr(o, 'both_get_set')
        self.assert_(self.interaction.checkChecked(['dc_set_permission']))
        self.assertRaises(ForbiddenAttribute,
                          checker.check_setattr, o, 'c_only')
        self.assert_(self.interaction.checkChecked([]))
        self.assertRaises(ForbiddenAttribute,
                          checker.check_setattr, o, 'd_only')
        self.assert_(self.interaction.checkChecked([]))

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
        self.assert_(
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
        self.assert_(MyType in _checkers)

        # If we clear the checkers, the type should still be there
        _clear()
        self.assert_(MyType in BasicTypes)
        self.assert_(MyType in _checkers)

        # Now delete the type from the dictionary, will also delete it from
        # the checkers
        del BasicTypes[MyType]
        self.assert_(MyType not in BasicTypes)
        self.assert_(MyType not in _checkers)

        # The quick way of adding new types is using update
        BasicTypes.update({MyType: NoProxy, MyType2: NoProxy})
        self.assert_(MyType in BasicTypes)
        self.assert_(MyType2 in BasicTypes)
        self.assert_(MyType in _checkers)
        self.assert_(MyType2 in _checkers)

        # Let's remove the two new types
        del BasicTypes[MyType]
        del BasicTypes[MyType2]

        # Of course, BasicTypes is a full dictionary. This dictionary is by
        # default filled with several entries:
        keys = BasicTypes.keys()
        keys.sort()
        self.assert_(bool in keys)
        self.assert_(int in keys)
        self.assert_(float in keys)
        self.assert_(str in keys)
        self.assert_(unicode in keys)
        self.assert_(object in keys)
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
        # pre-geddon fossils
        unittest.makeSuite(Test),
        unittest.makeSuite(TestCheckerPublic),
        unittest.makeSuite(TestCombinedChecker),
        unittest.makeSuite(TestBasicTypes),
    ))
