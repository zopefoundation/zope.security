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


class PermissionTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.security.permission import Permission
        return Permission

    def _makeOne(self, id, title=None, description=None):
        klass = self._getTargetClass()
        if description is None:
            if title is None:
                return klass(id)
            return klass(id, title)
        if title is None:
            return klass(id, description=description)
        return klass(id, title, description)

    def test_class_conforms_to_IPermission(self):
        from zope.interface.verify import verifyClass
        from zope.security.interfaces import IPermission
        verifyClass(IPermission, self._getTargetClass())

    def test_instance_conforms_to_IPermission(self):
        from zope.interface.verify import verifyObject
        from zope.security.interfaces import IPermission
        verifyObject(IPermission, self._makeOne('testing'))

    def test_ctor_only_id(self):
        permission = self._makeOne('testing')
        self.assertEqual(permission.id, 'testing')
        self.assertEqual(permission.title, '')
        self.assertEqual(permission.description, '')

    def test_ctor_w_title_and_description(self):
        permission = self._makeOne('testing', 'TITLE', 'DESCRIPTION')
        self.assertEqual(permission.id, 'testing')
        self.assertEqual(permission.title, 'TITLE')
        self.assertEqual(permission.description, 'DESCRIPTION')


def test_suite():
    return unittest.TestSuite([
            unittest.makeSuite(PermissionTests),
        ])
