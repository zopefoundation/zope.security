#############################################################################
#
# Copyright (c) 2011 Zope Foundation and Contributors.
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

from __future__ import with_statement
import unittest
import zope.security.management
import zope.security.testing


class InteractionHelperTest(unittest.TestCase):

    def tearDown(self):
        zope.security.management.endInteraction()

    def test_create_interaction_should_return_principal(self):
        principal = zope.security.testing.create_interaction(
            'foo', groups=['bar'], description='desc')
        interaction = zope.security.management.getInteraction()
        participation = interaction.participations[0]
        self.assertEqual('foo', participation.principal.id)
        self.assertEqual(principal.groups, participation.principal.groups)
        self.assertEqual('desc', participation.principal.description)

    def test_usable_as_contextmanager(self):
        with zope.security.testing.interaction('foo'):
            interaction = zope.security.management.getInteraction()
            participation = interaction.participations[0]
            self.assertEqual('foo', participation.principal.id)
        self.assertFalse(zope.security.management.queryInteraction())

    def test_contextmanager_ends_interaction_on_exception(self):
        try:
            with zope.security.testing.interaction('foo'):
                raise RuntimeError()
        except RuntimeError:
            pass
        self.assertFalse(zope.security.management.queryInteraction())
