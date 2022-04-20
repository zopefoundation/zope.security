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
"""Test permissions
"""
import unittest

from zope.component.testing import PlacelessSetup

from zope.security.interfaces import PUBLIC_PERMISSION_NAME as zope_Public


class PermissionTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.security.permission import Permission
        return Permission

    def _makeOne(self, id, *args):
        klass = self._getTargetClass()
        return klass(id, *args)

    def test_class_conforms_to_IPermission(self):
        from zope.interface.verify import verifyClass

        from zope.security.interfaces import IPermission
        verifyClass(IPermission, self._getTargetClass())

    def test_instance_conforms_to_IPermission(self):
        from zope.interface.verify import verifyObject
        from zope.schema import getValidationErrors

        from zope.security.interfaces import IPermission
        verifyObject(IPermission, self._makeOne('testing'))
        self.assertEqual([],
                         getValidationErrors(IPermission,
                                             self._makeOne('testing')))

    def test_ctor_only_id(self):
        permission = self._makeOne('testing')
        self.assertEqual(permission.id, u'testing')
        self.assertEqual(permission.title, u'')
        self.assertEqual(permission.description, u'')

    def test_ctor_w_title_and_description(self):
        permission = self._makeOne('testing', u'TITLE', u'DESCRIPTION')
        self.assertEqual(permission.id, 'testing')
        self.assertEqual(permission.title, u'TITLE')
        self.assertEqual(permission.description, u'DESCRIPTION')


class Test_checkPermission(PlacelessSetup, unittest.TestCase):

    def _callFUT(self, context, permission_id):
        from zope.security.permission import checkPermission
        return checkPermission(context, permission_id)

    def test_w_CheckerPublic(self):
        from zope.security.checker import CheckerPublic
        self._callFUT(None, CheckerPublic)  # no raise

    def test_miss(self):
        self.assertRaises(ValueError, self._callFUT, None, 'nonesuch')

    def test_hit(self):
        from zope.component import provideUtility

        from zope.security.interfaces import IPermission
        permission = object()
        provideUtility(permission, IPermission, 'testing')
        self._callFUT(None, 'testing')  # no raise


class Test_allPermissions(PlacelessSetup, unittest.TestCase):

    def _callFUT(self):
        from zope.security.permission import allPermissions
        return allPermissions()

    def test_empty(self):
        self.assertEqual(list(self._callFUT()), [])

    def test_w_registration(self):
        self.assertEqual(list(self._callFUT()), [])
        from zope.component import provideUtility

        from zope.security.interfaces import IPermission
        permission = object()
        provideUtility(permission, IPermission, 'testing')
        self.assertEqual(list(self._callFUT()), ['testing'])

    def test_skips_zope_Public(self):
        self.assertEqual(list(self._callFUT()), [])
        from zope.component import provideUtility

        from zope.security.checker import CheckerPublic
        from zope.security.interfaces import IPermission
        permission = object()
        provideUtility(permission, IPermission, 'testing')
        provideUtility(CheckerPublic, IPermission, zope_Public)
        self.assertEqual(list(self._callFUT()), ['testing'])


class Test_PermissionsVocabulary(PlacelessSetup, unittest.TestCase):

    def _callFUT(self):
        from zope.security.permission import PermissionsVocabulary
        return PermissionsVocabulary()

    def test_empty(self):
        from zope.schema.vocabulary import SimpleVocabulary
        vocabulary = self._callFUT()
        self.assertTrue(isinstance(vocabulary, SimpleVocabulary))
        self.assertEqual(list(vocabulary), [])

    def test_w_registration(self):
        self.assertEqual(list(self._callFUT()), [])
        from zope.component import provideUtility

        from zope.security.interfaces import IPermission
        permission = object()
        provideUtility(permission, IPermission, 'testing')
        vocabulary = self._callFUT()
        self.assertEqual([x.token for x in vocabulary], ['testing'])

    def test_includes_zope_Public(self):
        self.assertEqual(list(self._callFUT()), [])
        from zope.component import provideUtility

        from zope.security.checker import CheckerPublic
        from zope.security.interfaces import IPermission
        permission = object()
        provideUtility(permission, IPermission, 'testing')
        provideUtility(CheckerPublic, IPermission, zope_Public)
        vocabulary = self._callFUT()
        self.assertEqual(sorted([x.token for x in vocabulary]),
                         ['testing', zope_Public])

    def test_zcml_valid(self):
        from zope.configuration import xmlconfig
        from zope.interface.verify import verifyObject
        from zope.schema import getValidationErrors

        import zope.security
        from zope.security.interfaces import IPermission

        xmlconfig.file('configure.zcml', zope.security)
        vocabulary = self._callFUT()
        vocabulary = sorted(vocabulary, key=lambda term: term.token)
        self.assertEqual(6, len(vocabulary))

        for term in vocabulary:
            p = term.value
            __traceback_info__ = term.token, p
            verifyObject(IPermission, p)
            self.assertEqual([], getValidationErrors(IPermission, p))


class Test_PermissionIdsVocabulary(PlacelessSetup, unittest.TestCase):

    def _callFUT(self):
        from zope.security.permission import PermissionIdsVocabulary
        return PermissionIdsVocabulary()

    def test_empty(self):
        from zope.schema.vocabulary import SimpleVocabulary
        vocabulary = self._callFUT()
        self.assertTrue(isinstance(vocabulary, SimpleVocabulary))
        self.assertEqual(list(vocabulary), [])

    def test_w_registration(self):
        self.assertEqual(list(self._callFUT()), [])
        from zope.component import provideUtility

        from zope.security.interfaces import IPermission
        permission = object()
        provideUtility(permission, IPermission, 'testing')
        vocabulary = self._callFUT()
        self.assertEqual([x.value for x in vocabulary], ['testing'])
        self.assertEqual([x.token for x in vocabulary], ['testing'])

    def test_includes_zope_Public(self):
        self.assertEqual(list(self._callFUT()), [])
        from zope.component import provideUtility

        from zope.security.checker import CheckerPublic
        from zope.security.interfaces import IPermission
        permission = object()
        provideUtility(permission, IPermission, 'testing')
        provideUtility(CheckerPublic, IPermission, zope_Public)
        vocabulary = self._callFUT()
        self.assertEqual([x.value for x in vocabulary],
                         [CheckerPublic, 'testing'])
        self.assertEqual([x.token for x in vocabulary],
                         [zope_Public, 'testing'])


def test_suite():
    return unittest.defaultTestLoader.loadTestsFromName(__name__)
