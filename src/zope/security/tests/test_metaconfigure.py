##############################################################################
#
# Copyright (c) 2012 Zope Foundation and Contributors.
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
"""Test ZCML directives
"""
import unittest

class Test_dottedName(unittest.TestCase):

    def _callFUT(self, obj):
        from zope.security.metaconfigure import dottedName
        return dottedName(obj)

    def test_dottted_name_w_None(self):
        self.assertEqual(self._callFUT(None), 'None')

    def test_dottted_name_w_class(self):
        self.assertEqual(self._callFUT(Test_dottedName),
                         'zope.security.tests.test_metaconfigure.' +
                         'Test_dottedName')


class Test_protectModule(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def _callFUT(self, module, name, permission):
        from zope.security.metaconfigure import protectModule
        return protectModule(module, name, permission)

    def test_check_wo_existing_module_checker(self):
        from zope.security import tests as module
        from zope.security.checker import _checkers
        perm = object()
        self._callFUT(module, 'name', perm)
        checker = _checkers[module]
        self.assertTrue(checker.get_permissions['name'] is perm)

    def test_check_w_existing_module_checker_zope_Public(self):
        from zope.security import tests as module
        from zope.security.checker import Checker
        from zope.security.checker import CheckerPublic
        from zope.security.checker import _checkers
        before = _checkers[module] = Checker({'other': CheckerPublic})
        self._callFUT(module, 'name', 'zope.Public')
        checker = _checkers[module]
        self.assertTrue(checker is before)
        self.assertTrue(checker.get_permissions['name'] is CheckerPublic)


class Test_allow(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def _callFUT(self, context, attributes=None, interface=None):
        from zope.security.metaconfigure import allow
        if interface is None:
            if attributes is None:
                return allow(context)
            return allow(context, attributes)
        if attributes is None:
            return allow(context, interface=interface)
        return allow(context, attributes, interface)

    def test_empty(self):
        context = DummyZCMLContext()
        self._callFUT(context)
        self.assertEqual(len(context._actions), 0)

    def test_w_attributes(self):
        from zope.security.metaconfigure import protectModule
        ATTRS = ['foo', 'bar']
        context = DummyZCMLContext()
        context.module = 'testing'
        self._callFUT(context, ATTRS)
        self.assertEqual(len(context._actions), len(ATTRS))
        self.assertEqual(context._actions[0]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'foo'))
        self.assertTrue(context._actions[0]['callable'] is protectModule)
        self.assertEqual(context._actions[0]['args'],
                         ('testing', 'foo', 'zope.Public'))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'bar'))
        self.assertTrue(context._actions[1]['callable'] is protectModule)
        self.assertEqual(context._actions[1]['args'],
                         ('testing', 'bar', 'zope.Public'))

    def test_w_interface(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.security.metaconfigure import protectModule
        class IFoo(Interface):
            bar = Attribute('Bar')
        context = DummyZCMLContext()
        context.module = 'testing'
        self._callFUT(context, interface=[IFoo])
        self.assertEqual(len(context._actions), 1)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'bar'))
        self.assertTrue(context._actions[0]['callable'] is protectModule)
        self.assertEqual(context._actions[0]['args'],
                         ('testing', 'bar', 'zope.Public'))

    def test_w_both(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.security.metaconfigure import protectModule
        class IFoo(Interface):
            bar = Attribute('Bar')
            baz = Attribute('Baz')
        ATTRS = ['foo', 'bar']
        context = DummyZCMLContext()
        context.module = 'testing'
        self._callFUT(context, ATTRS, [IFoo])
        self.assertEqual(len(context._actions), 3)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'foo'))
        self.assertTrue(context._actions[0]['callable'] is protectModule)
        self.assertEqual(context._actions[0]['args'],
                         ('testing', 'foo', 'zope.Public'))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'bar'))
        self.assertTrue(context._actions[1]['callable'] is protectModule)
        self.assertEqual(context._actions[1]['args'],
                         ('testing', 'bar', 'zope.Public'))
        self.assertEqual(context._actions[2]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'baz'))
        self.assertTrue(context._actions[2]['callable'] is protectModule)
        self.assertEqual(context._actions[2]['args'],
                         ('testing', 'baz', 'zope.Public'))


class Test_requre(unittest.TestCase):

    def setUp(self):
        from zope.security.checker import _clear
        _clear()

    def tearDown(self):
        from zope.security.checker import _clear
        _clear()

    def _callFUT(self, context, permission, attributes=None, interface=None):
        from zope.security.metaconfigure import require
        if interface is None:
            if attributes is None:
                return require(context, permission)
            return require(context, permission, attributes)
        if attributes is None:
            return require(context, permission, interface=interface)
        return require(context, permission, attributes, interface)

    def test_empty(self):
        context = DummyZCMLContext()
        context.module = 'testing'
        perm = object()
        self._callFUT(context, perm)
        self.assertEqual(len(context._actions), 0)

    def test_w_attributes(self):
        from zope.security.metaconfigure import protectModule
        ATTRS = ['foo', 'bar']
        context = DummyZCMLContext()
        context.module = 'testing'
        perm = object()
        self._callFUT(context, perm, ATTRS)
        self.assertEqual(len(context._actions), len(ATTRS))
        self.assertEqual(context._actions[0]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'foo'))
        self.assertTrue(context._actions[0]['callable'] is protectModule)
        self.assertEqual(context._actions[0]['args'],
                         ('testing', 'foo', perm))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'bar'))
        self.assertTrue(context._actions[1]['callable'] is protectModule)
        self.assertEqual(context._actions[1]['args'],
                         ('testing', 'bar', perm))

    def test_w_interface(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.security.metaconfigure import protectModule
        class IFoo(Interface):
            bar = Attribute('Bar')
        context = DummyZCMLContext()
        context.module = 'testing'
        perm = object()
        self._callFUT(context, perm, interface=[IFoo])
        self.assertEqual(len(context._actions), 1)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'bar'))
        self.assertTrue(context._actions[0]['callable'] is protectModule)
        self.assertEqual(context._actions[0]['args'],
                         ('testing', 'bar', perm))

    def test_w_both(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.security.metaconfigure import protectModule
        class IFoo(Interface):
            bar = Attribute('Bar')
            baz = Attribute('Baz')
        ATTRS = ['foo', 'bar']
        context = DummyZCMLContext()
        context.module = 'testing'
        perm = object()
        self._callFUT(context, perm, ATTRS, [IFoo])
        self.assertEqual(len(context._actions), 3)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'foo'))
        self.assertTrue(context._actions[0]['callable'] is protectModule)
        self.assertEqual(context._actions[0]['args'],
                         ('testing', 'foo', perm))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'bar'))
        self.assertTrue(context._actions[1]['callable'] is protectModule)
        self.assertEqual(context._actions[1]['args'],
                         ('testing', 'bar', perm))
        self.assertEqual(context._actions[2]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'baz'))
        self.assertTrue(context._actions[2]['callable'] is protectModule)
        self.assertEqual(context._actions[2]['args'],
                         ('testing', 'baz', perm))


class DummyZCMLContext(object):

    def __init__(self):
        self._actions = []

    def action(self, **kw):
        self._actions.append(kw.copy())


def test_suite():
    return unittest.TestSuite([
        unittest.makeSuite(Test_dottedName),
        unittest.makeSuite(Test_protectModule),
        unittest.makeSuite(Test_allow),
        unittest.makeSuite(Test_allow),
    ])

