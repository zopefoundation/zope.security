##############################################################################
#
# Copyright (c) 2013 Zope Foundation and Contributors.
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

from zope.security.interfaces import PUBLIC_PERMISSION_NAME as zope_Public


class ConformsToIFromUnicode(object):

    def test_class_conforms_to_IFromUnicode(self):
        from zope.interface.verify import verifyClass
        from zope.schema.interfaces import IFromUnicode
        verifyClass(IFromUnicode, self._getTargetClass())

    def test_instance_conforms_to_IFromUnicode(self):
        from zope.interface.verify import verifyObject
        from zope.schema.interfaces import IFromUnicode
        verifyObject(IFromUnicode, self._makeOne())


class PermissionTests(unittest.TestCase,
                      ConformsToIFromUnicode,
                      ):

    def _getTargetClass(self):
        from zope.security.zcml import Permission
        return Permission

    def _makeOne(self, context=None):
        if context is None:
            context = DummyZCMLContext()
        permission = self._getTargetClass()()
        permission.context = context
        return permission

    def test_fromUnicode_miss(self):
        permission = self._makeOne()
        self.assertEqual(permission.fromUnicode('nonesuch.permission'),
                         'nonesuch.permission')

    def test_fromUnicode_hit(self):
        permission = self._makeOne()
        p_obj = object()
        permission.context.permission_mapping = {'extant.permission': p_obj}
        self.assertTrue(permission.fromUnicode('extant.permission') is p_obj)

    def test__validate_w_public(self):
        context = DummyZCMLContext()
        permission = self._makeOne(context)
        permission._validate(zope_Public)
        self.assertEqual(len(context._actions), 0)

    def test__validate_w_non_public(self):
        from zope.security.permission import checkPermission
        context = DummyZCMLContext()
        permission = self._makeOne(context)
        permission._validate('a.permission')
        self.assertEqual(len(context._actions), 1)
        self.assertEqual(context._actions[0]['discriminator'], None)
        self.assertEqual(context._actions[0]['callable'], checkPermission)
        self.assertEqual(context._actions[0]['args'],
                         (None, 'a.permission'))


class Test_securityPolicy(unittest.TestCase):

    def _callFUT(self, _context, component):
        from zope.security.zcml import securityPolicy
        return securityPolicy(_context, component)

    def test_it(self):
        from zope.security.management import setSecurityPolicy
        context = DummyZCMLContext()
        component = object()
        self._callFUT(context, component)
        self.assertEqual(len(context._actions), 1)
        self.assertEqual(context._actions[0]['discriminator'], 'defaultPolicy')
        self.assertEqual(context._actions[0]['callable'], setSecurityPolicy)
        self.assertEqual(context._actions[0]['args'], (component,))


class Test_permission(unittest.TestCase):

    def _callFUT(self, _context, id, title, description=None):
        from zope.security.zcml import permission
        if description is None:
            return permission(_context, id, title)
        return permission(_context, id, title, description)

    def test_wo_description(self):
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler

        from zope.security.interfaces import IPermission
        context = DummyZCMLContext()
        context.info = 'INFO'
        self._callFUT(context, 'a.permission', 'TITLE')
        self.assertEqual(len(context._actions), 2)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('utility', IPermission, 'a.permission'))
        self.assertEqual(context._actions[0]['callable'], handler)
        args = context._actions[0]['args']
        self.assertEqual(args[0], 'registerUtility')
        permission = args[1]
        self.assertEqual(permission.id, 'a.permission')
        self.assertEqual(permission.title, 'TITLE')
        self.assertEqual(permission.description, '')
        self.assertTrue(context._actions[1]['discriminator'] is None)
        self.assertTrue(context._actions[1]['callable'] is provideInterface)
        self.assertEqual(context._actions[1]['args'], ('', IPermission))

    def test_w_description(self):
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler

        from zope.security.interfaces import IPermission
        context = DummyZCMLContext()
        context.info = 'INFO'
        self._callFUT(context, 'a.permission', 'TITLE', 'DESCRIPTION')
        self.assertEqual(len(context._actions), 2)
        self.assertEqual(context._actions[0]['discriminator'],
                         ('utility', IPermission, 'a.permission'))
        self.assertEqual(context._actions[0]['callable'], handler)
        args = context._actions[0]['args']
        self.assertEqual(args[0], 'registerUtility')
        permission = args[1]
        self.assertEqual(permission.id, 'a.permission')
        self.assertEqual(permission.title, 'TITLE')
        self.assertEqual(permission.description, 'DESCRIPTION')
        self.assertTrue(context._actions[1]['discriminator'] is None)
        self.assertTrue(context._actions[1]['callable'] is provideInterface)
        self.assertEqual(context._actions[1]['args'], ('', IPermission))


class Test_redefinePermission(unittest.TestCase):

    def _callFUT(self, _context, from_, to):
        from zope.security.zcml import redefinePermission
        return redefinePermission(_context, from_, to)

    def test_wo_existing_mapping(self):
        z_context = DummyZCMLContext()

        class Context(object):
            pass
        context = z_context.context = Context()
        after = object()
        self._callFUT(z_context, 'before.permission', after)
        self.assertIs(context.permission_mapping['before.permission'], after)

    def test_w_existing_mapping_wo_existing_key(self):
        z_context = DummyZCMLContext()

        class Context(object):
            pass
        context = z_context.context = Context()
        mapping = context.permission_mapping = {}
        after = object()
        self._callFUT(z_context, 'before.permission', after)
        self.assertIs(context.permission_mapping, mapping)
        self.assertIs(context.permission_mapping['before.permission'], after)

    def test_w_existing_mapping_w_existing_key(self):
        z_context = DummyZCMLContext()

        class Context(object):
            pass
        context = z_context.context = Context()
        mapping = context.permission_mapping = {}
        mapping['before.permission'] = object()
        after = object()
        self._callFUT(z_context, 'before.permission', after)
        self.assertIs(context.permission_mapping, mapping)
        self.assertIs(context.permission_mapping['before.permission'], after)


class DummyZCMLContext(object):

    def __init__(self):
        self._actions = []

    def action(self, **kw):
        self._actions.append(kw)


def test_suite():
    return unittest.TestSuite((
        unittest.defaultTestLoader.loadTestsFromTestCase(PermissionTests),
        unittest.defaultTestLoader.loadTestsFromTestCase(Test_securityPolicy),
        unittest.defaultTestLoader.loadTestsFromTestCase(Test_permission),
        unittest.defaultTestLoader.loadTestsFromTestCase(
            Test_redefinePermission),
    ))
