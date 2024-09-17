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

from zope.security.interfaces import PUBLIC_PERMISSION_NAME as zope_Public


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


class ClassDirectiveTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.security.metaconfigure import ClassDirective
        return ClassDirective

    def _makeOne(self, _context, class_):
        return self._getTargetClass()(_context, class_)

    # def test_ctor_non_class(self): TODO  needs better guard in __init__

    def test_implements_empty(self):
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.implements(context, [])
        self.assertEqual(len(context._actions), 0)

    def test_implements_single_interface(self):
        from zope.component.interface import provideInterface
        from zope.interface import Interface
        from zope.interface import classImplements

        class IFoo(Interface):
            pass
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.implements(context, [IFoo])
        self.assertEqual(len(context._actions), 2)
        self.assertEqual(context._actions[0]['discriminator'][:2],
                         ('ContentDirective', Foo, ))  # 3rd is object()
        self.assertIs(context._actions[0]['callable'], classImplements)
        self.assertEqual(context._actions[0]['args'], (Foo, IFoo))
        self.assertIsNone(context._actions[1]['discriminator'])
        self.assertIs(context._actions[1]['callable'], provideInterface)
        self.assertEqual(context._actions[1]['args'],
                         ('zope.security.tests.test_metaconfigure.IFoo', IFoo))

    def test_implements_multiple_interfaces(self):
        from zope.component.interface import provideInterface
        from zope.interface import Interface
        from zope.interface import classImplements

        class IFoo(Interface):
            pass

        class IBar(Interface):
            pass
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.implements(context, [IFoo, IBar])
        self.assertEqual(len(context._actions), 4)
        self.assertEqual(context._actions[0]['discriminator'][:2],
                         ('ContentDirective', Foo, ))  # 3rd is object()
        self.assertIs(context._actions[0]['callable'], classImplements)
        self.assertEqual(context._actions[0]['args'], (Foo, IFoo))
        self.assertIsNone(context._actions[1]['discriminator'])
        self.assertIs(context._actions[1]['callable'], provideInterface)
        self.assertEqual(context._actions[1]['args'],
                         ('zope.security.tests.test_metaconfigure.IFoo', IFoo))
        self.assertEqual(context._actions[2]['discriminator'][:2],
                         ('ContentDirective', Foo, ))  # 3rd is object()
        self.assertIs(context._actions[2]['callable'], classImplements)
        self.assertEqual(context._actions[2]['args'], (Foo, IBar))
        self.assertIsNone(context._actions[3]['discriminator'])
        self.assertIs(context._actions[3]['callable'], provideInterface)
        self.assertEqual(context._actions[3]['args'],
                         ('zope.security.tests.test_metaconfigure.IBar', IBar))

    def test_require_only_like_class(self):
        from zope.security.protectclass import protectLikeUnto

        class Bar:
            pass
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.require(context, like_class=Bar)
        self.assertEqual(len(context._actions), 1)
        self.assertEqual(context._actions[0]['discriminator'][:2],
                         ('mimic', Foo, ))  # 3rd is object()
        self.assertIs(context._actions[0]['callable'], protectLikeUnto)
        self.assertEqual(context._actions[0]['args'], (Foo, Bar))

    def test_require_only_permission(self):
        from zope.configuration.exceptions import ConfigurationError
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        self.assertRaises(ConfigurationError,
                          directive.require, context, permission='testing')

    def test_require_no_like_class_wo_permission(self):
        from zope.configuration.exceptions import ConfigurationError
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        with self.assertRaises(ConfigurationError):
            directive.require(context, attributes=('foo', 'bar'))

    def test_require_w_single_interface(self):
        from zope.component.interface import provideInterface
        from zope.interface import Attribute
        from zope.interface import Interface

        from zope.security.protectclass import protectName

        class IFoo(Interface):
            bar = Attribute("Bar")
            baz = Attribute("Baz")
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.require(context, permission='testing', interface=[IFoo])
        self.assertEqual(len(context._actions), 3)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('protectName', Foo, 'bar'))
        self.assertIs(context._actions[0]['callable'], protectName)
        self.assertEqual(context._actions[0]['args'], (Foo, 'bar', 'testing'))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('protectName', Foo, 'baz'))
        self.assertIs(context._actions[1]['callable'], protectName)
        self.assertEqual(context._actions[1]['args'], (Foo, 'baz', 'testing'))
        self.assertIsNone(context._actions[2]['discriminator'])
        self.assertIs(context._actions[2]['callable'], provideInterface)
        self.assertEqual(context._actions[2]['args'],
                         ('zope.security.tests.test_metaconfigure.IFoo', IFoo))

    def test_require_w_multiple_interfaces(self):
        from zope.component.interface import provideInterface
        from zope.interface import Attribute
        from zope.interface import Interface

        from zope.security.protectclass import protectName

        class IFoo(Interface):
            bar = Attribute("Bar")

        class IBar(Interface):
            baz = Attribute("Baz")
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.require(context, permission='testing',
                          interface=[IFoo, IBar])
        self.assertEqual(len(context._actions), 4)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('protectName', Foo, 'bar'))
        self.assertIs(context._actions[0]['callable'], protectName)
        self.assertEqual(context._actions[0]['args'], (Foo, 'bar', 'testing'))
        self.assertIsNone(context._actions[1]['discriminator'])
        self.assertIs(context._actions[1]['callable'], provideInterface)
        self.assertEqual(context._actions[1]['args'],
                         ('zope.security.tests.test_metaconfigure.IFoo', IFoo))
        self.assertEqual(context._actions[2]['discriminator'],
                         ('protectName', Foo, 'baz'))
        self.assertIs(context._actions[2]['callable'], protectName)
        self.assertEqual(context._actions[2]['args'], (Foo, 'baz', 'testing'))
        self.assertIsNone(context._actions[3]['discriminator'])
        self.assertIs(context._actions[3]['callable'], provideInterface)
        self.assertEqual(context._actions[3]['args'],
                         ('zope.security.tests.test_metaconfigure.IBar', IBar))

    def test_require_w_attributes(self):
        from zope.security.protectclass import protectName
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.require(context, permission='testing',
                          attributes=['bar', 'baz'])
        self.assertEqual(len(context._actions), 2)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('protectName', Foo, 'bar'))
        self.assertIs(context._actions[0]['callable'], protectName)
        self.assertEqual(context._actions[0]['args'], (Foo, 'bar', 'testing'))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('protectName', Foo, 'baz'))
        self.assertIs(context._actions[1]['callable'], protectName)
        self.assertEqual(context._actions[1]['args'], (Foo, 'baz', 'testing'))

    def test_require_w_set_attributes(self):
        from zope.security.protectclass import protectSetAttribute
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.require(context, permission='testing',
                          set_attributes=['bar', 'baz'])
        self.assertEqual(len(context._actions), 2)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('protectSetAttribute', Foo, 'bar'))
        self.assertIs(context._actions[0]['callable'], protectSetAttribute)
        self.assertEqual(context._actions[0]['args'], (Foo, 'bar', 'testing'))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('protectSetAttribute', Foo, 'baz'))
        self.assertIs(context._actions[1]['callable'], protectSetAttribute)
        self.assertEqual(context._actions[1]['args'], (Foo, 'baz', 'testing'))

    def test_require_w_set_schema_normal_fields(self):
        from zope.component.interface import provideInterface
        from zope.interface import Interface
        from zope.schema import Field

        from zope.security.protectclass import protectSetAttribute

        class IFoo(Interface):
            bar = Field("Bar")
            baz = Field("Baz")
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.require(context, permission='testing', set_schema=[IFoo])
        self.assertEqual(len(context._actions), 3)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('protectSetAttribute', Foo, 'bar'))
        self.assertIs(context._actions[0]['callable'], protectSetAttribute)
        self.assertEqual(context._actions[0]['args'], (Foo, 'bar', 'testing'))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('protectSetAttribute', Foo, 'baz'))
        self.assertIs(context._actions[1]['callable'], protectSetAttribute)
        self.assertEqual(context._actions[1]['args'], (Foo, 'baz', 'testing'))
        self.assertIsNone(context._actions[2]['discriminator'])
        self.assertIs(context._actions[2]['callable'], provideInterface)
        self.assertEqual(context._actions[2]['args'],
                         ('zope.security.tests.test_metaconfigure.IFoo', IFoo))

    def test_require_w_set_schema_ignores_non_fields(self):
        from zope.component.interface import provideInterface
        from zope.interface import Attribute
        from zope.interface import Interface

        class IFoo(Interface):
            bar = Attribute("Bar")
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.require(context, permission='testing', set_schema=[IFoo])
        self.assertEqual(len(context._actions), 1)
        self.assertIsNone(context._actions[0]['discriminator'])
        self.assertIs(context._actions[0]['callable'], provideInterface)
        self.assertEqual(context._actions[0]['args'],
                         ('zope.security.tests.test_metaconfigure.IFoo', IFoo))

    def test_require_w_set_schema_ignores_readonly_fields(self):
        from zope.component.interface import provideInterface
        from zope.interface import Interface
        from zope.schema import Field

        class IFoo(Interface):
            bar = Field("Bar", readonly=True)
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.require(context, permission='testing', set_schema=[IFoo])
        self.assertEqual(len(context._actions), 1)
        self.assertIsNone(context._actions[0]['discriminator'])
        self.assertIs(context._actions[0]['callable'], provideInterface)
        self.assertEqual(context._actions[0]['args'],
                         ('zope.security.tests.test_metaconfigure.IFoo', IFoo))

    def test_allow_no_attributes_or_interface(self):
        from zope.configuration.exceptions import ConfigurationError
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        self.assertRaises(ConfigurationError, directive.allow, context)

    def test_allow_w_single_interface(self):
        from zope.component.interface import provideInterface
        from zope.interface import Attribute
        from zope.interface import Interface

        from zope.security.protectclass import protectName

        class IFoo(Interface):
            bar = Attribute("Bar")
            baz = Attribute("Baz")
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.allow(context, interface=[IFoo])
        self.assertEqual(len(context._actions), 3)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('protectName', Foo, 'bar'))
        self.assertIs(context._actions[0]['callable'], protectName)
        self.assertEqual(context._actions[0]['args'],
                         (Foo, 'bar', zope_Public))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('protectName', Foo, 'baz'))
        self.assertIs(context._actions[1]['callable'], protectName)
        self.assertEqual(context._actions[1]['args'],
                         (Foo, 'baz', zope_Public))
        self.assertIsNone(context._actions[2]['discriminator'])
        self.assertIs(context._actions[2]['callable'], provideInterface)
        self.assertEqual(context._actions[2]['args'],
                         ('zope.security.tests.test_metaconfigure.IFoo', IFoo))

    def test_allow_w_multiple_interfaces(self):
        from zope.component.interface import provideInterface
        from zope.interface import Attribute
        from zope.interface import Interface

        from zope.security.protectclass import protectName

        class IFoo(Interface):
            bar = Attribute("Bar")

        class IBar(Interface):
            baz = Attribute("Baz")
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.allow(context, interface=[IFoo, IBar])
        self.assertEqual(len(context._actions), 4)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('protectName', Foo, 'bar'))
        self.assertIs(context._actions[0]['callable'], protectName)
        self.assertEqual(context._actions[0]['args'],
                         (Foo, 'bar', zope_Public))
        self.assertIsNone(context._actions[1]['discriminator'])
        self.assertIs(context._actions[1]['callable'], provideInterface)
        self.assertEqual(context._actions[1]['args'],
                         ('zope.security.tests.test_metaconfigure.IFoo', IFoo))
        self.assertEqual(context._actions[2]['discriminator'],
                         ('protectName', Foo, 'baz'))
        self.assertIs(context._actions[2]['callable'], protectName)
        self.assertEqual(context._actions[2]['args'],
                         (Foo, 'baz', zope_Public))
        self.assertIsNone(context._actions[3]['discriminator'])
        self.assertIs(context._actions[3]['callable'], provideInterface)
        self.assertEqual(context._actions[3]['args'],
                         ('zope.security.tests.test_metaconfigure.IBar', IBar))

    def test_allow_w_attributes(self):
        from zope.security.protectclass import protectName
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        directive.allow(context, attributes=['bar', 'baz'])
        self.assertEqual(len(context._actions), 2)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('protectName', Foo, 'bar'))
        self.assertIs(context._actions[0]['callable'], protectName)
        self.assertEqual(context._actions[0]['args'],
                         (Foo, 'bar', zope_Public))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('protectName', Foo, 'baz'))
        self.assertIs(context._actions[1]['callable'], protectName)
        self.assertEqual(context._actions[1]['args'],
                         (Foo, 'baz', zope_Public))

    def test___call__(self):
        context = DummyZCMLContext()
        directive = self._makeOne(context, Foo)
        self.assertEqual(directive(), ())

    def test_factory_wo_explicit_id(self):
        from zope.component.interface import provideInterface
        from zope.component.interfaces import IFactory
        from zope.component.zcml import handler
        context = DummyZCMLContext()
        context.info = 'INFO'
        directive = self._makeOne(context, Foo)
        directive.factory(context, title='TITLE', description='DESCRIPTION')
        self.assertEqual(len(context._actions), 2)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('utility', IFactory,
                          'zope.security.tests.test_metaconfigure.Foo'))
        self.assertIs(context._actions[0]['callable'], handler)
        args = context._actions[0]['args']
        self.assertEqual(args[0], 'registerUtility')
        factory = args[1]
        self.assertEqual(factory._callable, Foo)
        self.assertEqual(factory.title, 'TITLE')
        self.assertEqual(factory.description, 'DESCRIPTION')
        self.assertEqual(args[2], IFactory)
        self.assertEqual(args[3], 'zope.security.tests.test_metaconfigure.Foo')
        self.assertEqual(args[4], 'INFO')
        self.assertIsNone(context._actions[1]['discriminator'])
        self.assertIs(context._actions[1]['callable'], provideInterface)
        self.assertEqual(context._actions[1]['args'], ('', IFactory))

    def test_factory_w_explicit_id(self):
        from zope.component.interface import provideInterface
        from zope.component.interfaces import IFactory
        from zope.component.zcml import handler
        context = DummyZCMLContext()
        context.info = 'INFO'
        directive = self._makeOne(context, Foo)
        directive.factory(context, id='test_id')
        self.assertEqual(len(context._actions), 2)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('utility', IFactory, 'test_id'))
        self.assertIs(context._actions[0]['callable'], handler)
        args = context._actions[0]['args']
        self.assertEqual(args[0], 'registerUtility')
        factory = args[1]
        self.assertEqual(factory._callable, Foo)
        self.assertEqual(args[2], IFactory)
        self.assertEqual(args[3], 'test_id')
        self.assertEqual(args[4], 'INFO')
        self.assertIsNone(context._actions[1]['discriminator'])
        self.assertIs(context._actions[1]['callable'], provideInterface)
        self.assertEqual(context._actions[1]['args'], ('', IFactory))


class Foo:
    pass


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
        self.assertIs(checker.get_permissions['name'], perm)

    def test_check_w_existing_module_checker_zope_Public(self):
        from zope.security import tests as module
        from zope.security.checker import Checker
        from zope.security.checker import CheckerPublic
        from zope.security.checker import _checkers
        before = _checkers[module] = Checker({'other': CheckerPublic})
        self._callFUT(module, 'name', zope_Public)
        checker = _checkers[module]
        self.assertIs(checker, before)
        self.assertIs(checker.get_permissions['name'], CheckerPublic)


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
        self.assertIs(context._actions[0]['callable'], protectModule)
        self.assertEqual(context._actions[0]['args'],
                         ('testing', 'foo', zope_Public))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'bar'))
        self.assertIs(context._actions[1]['callable'], protectModule)
        self.assertEqual(context._actions[1]['args'],
                         ('testing', 'bar', zope_Public))

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
        self.assertIs(context._actions[0]['callable'], protectModule)
        self.assertEqual(context._actions[0]['args'],
                         ('testing', 'bar', zope_Public))

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
        self.assertIs(context._actions[0]['callable'], protectModule)
        self.assertEqual(context._actions[0]['args'],
                         ('testing', 'foo', zope_Public))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'bar'))
        self.assertIs(context._actions[1]['callable'], protectModule)
        self.assertEqual(context._actions[1]['args'],
                         ('testing', 'bar', zope_Public))
        self.assertEqual(context._actions[2]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'baz'))
        self.assertIs(context._actions[2]['callable'], protectModule)
        self.assertEqual(context._actions[2]['args'],
                         ('testing', 'baz', zope_Public))


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
        self.assertIs(context._actions[0]['callable'], protectModule)
        self.assertEqual(context._actions[0]['args'],
                         ('testing', 'foo', perm))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'bar'))
        self.assertIs(context._actions[1]['callable'], protectModule)
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
        self.assertIs(context._actions[0]['callable'], protectModule)
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
        self.assertIs(context._actions[0]['callable'], protectModule)
        self.assertEqual(context._actions[0]['args'],
                         ('testing', 'foo', perm))
        self.assertEqual(context._actions[1]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'bar'))
        self.assertIs(context._actions[1]['callable'], protectModule)
        self.assertEqual(context._actions[1]['args'],
                         ('testing', 'bar', perm))
        self.assertEqual(context._actions[2]['discriminator'],
                         ('http://namespaces.zope.org/zope:module',
                          'testing', 'baz'))
        self.assertIs(context._actions[2]['callable'], protectModule)
        self.assertEqual(context._actions[2]['args'],
                         ('testing', 'baz', perm))


class DummyZCMLContext:

    def __init__(self):
        self._actions = []

    def action(self, **kw):
        self._actions.append(kw.copy())


def test_suite():
    return unittest.defaultTestLoader.loadTestsFromName(__name__)
