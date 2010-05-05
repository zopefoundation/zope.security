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
""" Unit tests for SecurityManagement

$Id$
"""

import unittest

from zope.interface.verify import verifyObject
from zope.testing.cleanup import CleanUp


class Test(CleanUp, unittest.TestCase):

    def test_import(self):
        from zope.security import management
        from zope.security.interfaces import ISecurityManagement
        from zope.security.interfaces import IInteractionManagement

        verifyObject(ISecurityManagement, management)
        verifyObject(IInteractionManagement, management)

    def test_securityPolicy(self):
        from zope.security.management import setSecurityPolicy
        from zope.security.management import getSecurityPolicy
        from zope.security.simplepolicies import PermissiveSecurityPolicy

        policy = PermissiveSecurityPolicy
        setSecurityPolicy(policy)
        self.assert_(getSecurityPolicy() is policy)

    def test_query_new_end_restore_Interaction(self):
        from zope.security.management import queryInteraction
        self.assertEquals(queryInteraction(), None)

        from zope.security.management import newInteraction

        newInteraction()

        interaction = queryInteraction()
        self.assert_(interaction is not None)
        self.assertRaises(AssertionError, newInteraction)

        from zope.security.management import endInteraction
        endInteraction()
        self.assertEquals(queryInteraction(), None)

        from zope.security.management import restoreInteraction
        restoreInteraction()
        self.assert_(interaction is queryInteraction())

        endInteraction()
        self.assertEquals(queryInteraction(), None)

        endInteraction()
        self.assertEquals(queryInteraction(), None)

        newInteraction()
        self.assert_(queryInteraction() is not None)
        
        restoreInteraction() # restore to no interaction
        self.assert_(queryInteraction() is None)

    def test_checkPermission(self):
        from zope.security import checkPermission
        from zope.security.management import setSecurityPolicy
        from zope.security.management import queryInteraction
        from zope.security.management import newInteraction, endInteraction
        from zope.security.interfaces import NoInteraction

        permission = 'zope.Test'
        obj = object()

        class PolicyStub(object):

            def checkPermission(s, p, o,):
                self.assert_(p is permission)
                self.assert_(o is obj)
                self.assert_(s is queryInteraction() or s is interaction)
                return s is interaction

        setSecurityPolicy(PolicyStub)
        newInteraction()
        interaction = queryInteraction()
        self.assertEquals(checkPermission(permission, obj), True)
        
        endInteraction()
        self.assertRaises(NoInteraction, checkPermission, permission, obj)

    def test_checkPublicPermission(self):
        from zope.security import checkPermission
        from zope.security.checker import CheckerPublic
        from zope.security.management import setSecurityPolicy
        from zope.security.management import newInteraction

        obj = object()

        class ForbiddenPolicyStub(object):

            def checkPermission(s, p, o):
                return False

        setSecurityPolicy(ForbiddenPolicyStub)
        newInteraction()
        self.assertEquals(checkPermission('zope.Test', obj), False)
        self.assertEquals(checkPermission(None, obj), True)
        self.assertEquals(checkPermission(CheckerPublic, obj), True)

    def test_system_user(self):
        from zope.security.management import system_user
        self.assertEquals(system_user.id,
                          u'zope.security.management.system_user')

        self.assertEquals(system_user.title, u'System')

        for name in 'id', 'title', 'description':
            self.assert_(isinstance(getattr(system_user, name), unicode))

def test_suite():
    loader = unittest.TestLoader()
    return loader.loadTestsFromTestCase(Test)

if __name__=='__main__':
    unittest.TextTestRunner().run(test_suite())
