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
"""Testing support code

This module provides some helper/stub objects for setting up interactions.

$Id$
"""

from zope import interface, component
from zope.security import interfaces
from zope.security.permission import Permission

class Principal:

    interface.implements(interfaces.IPrincipal)

    def __init__(self, id, title=None, description='', groups=None):
        self.id = id
        self.title = title or id
        self.description = description
        if groups is not None:
            self.groups = groups
            interface.directlyProvides(self, interfaces.IGroupAwarePrincipal)

class Participation:

    interface.implements(interfaces.IParticipation)

    def __init__(self, principal):
        self.principal = principal
        self.interaction = None


def addCheckerPublic():
    """Add the CheckerPublic permission as 'zope.Public'"""

    perm = Permission('zope.Public', 'Public',
            """Special permission used for resources that are always public

            The public permission is effectively an optimization, sine
            it allows security computation to be bypassed.
            """
            )
    gsm = component.getGlobalSiteManager()
    gsm.registerUtility(perm, interfaces.IPermission, perm.id)
